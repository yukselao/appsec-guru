"""Hidden Path Discovery: wordlists and ffuf runs. ffuf runs in the api
container; hits stream into PostgreSQL."""
import base64
import json
import logging
import os
import re
import shutil
import subprocess
import threading

from sqlalchemy import select

from wtdb.database import session_scope
from wtdb.models import FuzzRun

from . import settings as st

log = logging.getLogger("fuzz")
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/var/lib/was-troubleshooter/wordlists")
NAME_RX = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_active = {}
_lock = threading.Lock()

BUILTIN = {
    "common-paths.txt": ["admin", "administrator", "login", "logout", "dashboard", "api", "api/v1", "api/v2",
        "config", "config.php", "config.json", ".env", ".git/config", ".git/HEAD", "backup", "backup.zip", "backup.sql",
        "db.sql", "dump.sql", "test", "tmp", "temp", "old", "new", "dev", "staging", "debug", "status", "health",
        "healthz", "metrics", "actuator", "actuator/health", "actuator/env", "server-status", "phpinfo.php", "info.php",
        "robots.txt", "sitemap.xml", ".well-known/security.txt", "swagger", "swagger.json", "swagger-ui.html",
        "openapi.json", "graphql", "graphiql", "console", "shell", "upload", "uploads", "files", "download",
        "images", "img", "assets", "static", "js", "css", "vendor", "node_modules", "wp-admin", "wp-login.php",
        "wp-config.php", "xmlrpc.php", "administrator/index.php", "user", "users", "account", "settings", "setup",
        "install", "install.php", "register", "signup", "reset", "forgot", "token", "secret", "private", "internal",
        "manage", "manager", "portal", "cgi-bin", "server-info", ".htaccess", ".htpasswd", "web.config", "crossdomain.xml"],
    "api-endpoints.txt": ["api", "api/v1", "api/v2", "api/v3", "api/users", "api/user", "api/admin", "api/login",
        "api/auth", "api/token", "api/products", "api/orders", "api/health", "api/status", "api/config", "api/debug",
        "api/docs", "api/swagger", "api/openapi.json", "graphql", "rest", "soap", "rpc", "api/internal", "api/private",
        "api/keys", "api/secrets", "api/export", "api/import", "api/upload", "api/download", "v1", "v2", "actuator"],
    "backup-files.txt": ["backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql", "database.sql", "www.zip",
        "site.zip", "web.zip", "app.zip", "source.zip", ".env.bak", "config.php.bak", "index.php.bak", "index.php~",
        ".git", ".git/config", ".svn/entries", ".DS_Store", "wp-config.php.bak", "config.old", "backup.old", "old.zip"],
}


def ensure_builtin():
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    for name, words in BUILTIN.items():
        p = os.path.join(WORDLIST_DIR, name)
        if not os.path.exists(p):
            with open(p, "w") as fh:
                fh.write("\n".join(words) + "\n")


def _count(path):
    try:
        with open(path, "rb") as fh:
            return sum(1 for ln in fh if ln.strip())
    except OSError:
        return 0


def wordlists():
    ensure_builtin()
    out = []
    for f in sorted(os.listdir(WORDLIST_DIR)):
        p = os.path.join(WORDLIST_DIR, f)
        if f.startswith(".") or not os.path.isfile(p):
            continue
        if True:
            out.append({"name": f, "words": _count(p), "size": os.path.getsize(p),
                        "builtin": f in BUILTIN})
    return out


def wordlist_path(name):
    if not NAME_RX.match(name or ""):
        raise ValueError("invalid wordlist name")
    p = os.path.realpath(os.path.join(WORDLIST_DIR, name))
    if not p.startswith(os.path.realpath(WORDLIST_DIR)) or not os.path.isfile(p):
        raise ValueError("wordlist not found")
    return p


def save_wordlist(name, content):
    ensure_builtin()
    if not NAME_RX.match(name or ""):
        raise ValueError("name may use letters, digits, dot, dash, underscore only")
    if name in BUILTIN:
        raise ValueError("that name is reserved for a built-in list")
    lines = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.startswith("#")]
    if not lines:
        raise ValueError("the wordlist is empty")
    with open(os.path.join(WORDLIST_DIR, name), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return {"name": name, "words": len(lines)}


def read_wordlist(name, limit=5000):
    path = wordlist_path(name)
    with open(path, encoding="utf-8", errors="replace") as fh:
        words = [ln.rstrip("\n") for ln in fh]
    return {"name": name, "words": len(words), "truncated": len(words) > limit, "sample": words[:limit]}


def wordlist_bytes(name):
    with open(wordlist_path(name), "rb") as fh:
        return fh.read()


def delete_wordlist(name):
    if name in BUILTIN:
        raise ValueError("a built-in list cannot be deleted")
    os.remove(wordlist_path(name))


def is_active(run_id):
    with _lock:
        return run_id in _active


def cancel(run_id):
    with _lock:
        p = _active.get(run_id)
    if p:
        p.terminate()
        return True
    return False


def mark_orphans():
    with session_scope() as s:
        for r in s.execute(select(FuzzRun).where(FuzzRun.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the run"


def start(params, client_ip=None):
    url = (params.get("target_url") or "").strip()
    if not re.match(r"^https?://[\w.:\[\]-]+", url):
        raise ValueError("target URL must start with http:// or https://")
    wl = params.get("wordlist") or "common-paths.txt"
    wlpath = wordlist_path(wl)
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    with session_scope() as s:
        r = FuzzRun(target_url=url, wordlist=wl, extensions=(params.get("extensions") or "").strip() or None,
                    methods=params.get("methods") or "GET",
                    match_codes=params.get("match_codes") or "200,204,301,302,307,401,403,405,500",
                    filter_codes=(params.get("filter_codes") or "").strip() or None,
                    threads=int(params.get("threads") or 40), rate=int(params.get("rate") or 0),
                    extra_headers=params.get("extra_headers") or [], status="pending", total_words=_count(wlpath))
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("fuzz_run_create", client_ip=client_ip, run_id=run_id, target=url, wordlist=wl)
    threading.Thread(target=_run, args=(run_id, wlpath), name="fuzz-%d" % run_id, daemon=True).start()
    return run_id


def _run(run_id, wlpath):
    with session_scope() as s:
        r = s.get(FuzzRun, run_id)
        cmd = ["ffuf", "-w", wlpath + ":FUZZ", "-u", r.target_url, "-mc", r.match_codes,
               "-t", str(r.threads), "-json", "-s"]
        if r.extensions:
            cmd += ["-e", r.extensions]
        if r.filter_codes:
            cmd += ["-fc", r.filter_codes]
        if r.rate:
            cmd += ["-rate", str(r.rate)]
        for h in r.extra_headers or []:
            if h.get("name"):
                cmd += ["-H", "{}: {}".format(h["name"], h.get("value", ""))]
        if "GET" not in (r.methods or "GET"):
            cmd += ["-X", r.methods.split(",")[0].strip()]
    hits = []
    try:
        with session_scope() as s:
            s.get(FuzzRun, run_id).status = "running"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with _lock:
            _active[run_id] = p
        for line in p.stdout:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            raw = d.get("input", {}).get("FUZZ", "")
            try:
                path = base64.b64decode(raw).decode("utf-8", "replace") if raw else ""
            except Exception:
                path = raw
            hits.append({"path": path, "url": d.get("url"), "status": d.get("status"),
                         "length": d.get("length"), "words": d.get("words"), "lines": d.get("lines"),
                         "redirect": d.get("redirectlocation") or ""})
            if len(hits) % 10 == 0:
                with session_scope() as s:
                    s.get(FuzzRun, run_id).hits = hits
        p.wait()
        err = p.stderr.read()[:2000]
        with session_scope() as s:
            r = s.get(FuzzRun, run_id)
            r.hits = hits
            r.stats = {"found": len(hits), "by_status": _by_status(hits)}
            if p.returncode and p.returncode != 0 and not hits:
                r.status = "failed" if p.returncode > 0 else "cancelled"
                r.error = err or "ffuf exited with {}".format(p.returncode)
            else:
                r.status = "cancelled" if run_id not in _active else "completed"
                r.status = "completed" if p.returncode == 0 else r.status
    except Exception as exc:
        log.exception("fuzz %s", run_id)
        with session_scope() as s:
            r = s.get(FuzzRun, run_id)
            r.status = "failed"
            r.error = str(exc)
            r.hits = hits
    finally:
        with session_scope() as s:
            r = s.get(FuzzRun, run_id)
            from sqlalchemy import func as _f
            r.finished_at = _f.now()
            if r.status in ("pending", "running"):
                r.status = "cancelled" if run_id not in _active else "completed"
        with _lock:
            _active.pop(run_id, None)


def _by_status(hits):
    out = {}
    for h in hits:
        out[str(h["status"])] = out.get(str(h["status"]), 0) + 1
    return out


def row(r):
    return {"id": r.id, "target_url": r.target_url, "wordlist": r.wordlist, "extensions": r.extensions,
            "methods": r.methods, "match_codes": r.match_codes, "filter_codes": r.filter_codes, "threads": r.threads,
            "rate": r.rate, "status": r.status, "error": r.error, "total_words": r.total_words,
            "hits": r.hits, "stats": r.stats, "active": is_active(r.id),
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}
