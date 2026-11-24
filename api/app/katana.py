"""Katana (web crawler / endpoint discovery) in its own container, reached over
TCP (socat). Asynchronous; crawled endpoints stream into PostgreSQL. Lab use
only: crawl only targets you are authorised to test."""
import json
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import select

from wtdb.database import session_scope
from wtdb.models import KatanaRun

from . import settings as st

log = logging.getLogger("katana")
KATANA = os.environ.get("RECON_KATANA", "recon-katana:7006")
URL_RX = re.compile(r"^https?://[\w.\-]+(:\d+)?(/[^\s]*)?$", re.I)
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
FIELD_SCOPE = ("dn", "rdn", "fqdn")
KNOWN_FILES = ("", "all", "robotstxt", "sitemapxml")
DURATION_RX = re.compile(r"^\d{1,4}(s|m|h)?$")
HEADER_RX = re.compile(r"^[A-Za-z0-9\-]+:\s?.+$")
PROXY_RX = re.compile(r"^(https?|socks5)://[\w.\-]+:\d{1,5}$", re.I)
REGEX_MAX = 300


def _ct_seconds(d):
    if not d:
        return 0
    n = int(re.match(r"\d+", d).group())
    unit = d[-1] if d[-1].isalpha() else "s"
    return n * {"s": 1, "m": 60, "h": 3600}.get(unit, 1)
LOG_MAX = 4000
LOG_RUNS = 25
_active = {}
_logs = {}
_lock = threading.Lock()


def _log_append(run_id, line):
    with _lock:
        buf = _logs.get(run_id)
        if buf is None:
            buf = _logs[run_id] = []
            for old in sorted(_logs)[:-LOG_RUNS]:
                if old not in _active:
                    _logs.pop(old, None)
        buf.append(line)
        if len(buf) > LOG_MAX:
            del buf[:len(buf) - LOG_MAX]


def drop_log(run_id):
    with _lock:
        _logs.pop(run_id, None)


def get_log(run_id, offset=0):
    with _lock:
        buf = _logs.get(run_id, [])
        offset = max(0, min(int(offset or 0), len(buf)))
        return {"lines": buf[offset:], "offset": len(buf),
                "active": run_id in _active, "has_log": bool(buf)}


def _hostport(hp):
    host, port = hp.rsplit(":", 1)
    return host, int(port)


def is_active(run_id):
    with _lock:
        return run_id in _active


def cancel(run_id):
    with _lock:
        ev = _active.get(run_id)
    if ev:
        ev.set()
    return bool(ev)


def mark_orphans():
    with session_scope() as s:
        for r in s.execute(select(KatanaRun).where(KatanaRun.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the run"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(KatanaRun, run_id)
        for k, v in f.items():
            setattr(r, k, v)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def _clean_url(raw):
    u = (raw or "").strip()
    if not u:
        raise ValueError("enter a target URL")
    if "://" not in u:
        u = "http://" + u
    if not URL_RX.match(u):
        raise ValueError("enter a valid target URL, e.g. http://192.168.1.140:3000")
    return u


def _argv(url, o):
    """Whole katana argv. Only whitelisted flags; user strings are only ever flag
    VALUES. -jsonl/-silent/-no-color are forced by the container."""
    argv = ["-u", url, "-d", str(o["depth"]), "-fs", o["field_scope"],
            "-c", str(o["concurrency"]), "-p", str(o["parallelism"]),
            "-rl", str(o["rate_limit"]), "-timeout", str(o["timeout"]), "-retry", str(o["retry"])]
    if o.get("known_files"):
        argv += ["-kf", o["known_files"]]
    if o.get("crawl_duration"):
        argv += ["-ct", o["crawl_duration"]]
    if o.get("js_crawl"):
        argv += ["-jc"]
    if o.get("jsluice"):
        argv += ["-jsl"]
    if o.get("form_extraction"):
        argv += ["-fx"]
    if o.get("tech_detect"):
        argv += ["-td"]
    if o.get("ignore_query_params"):
        argv += ["-iqp"]
    if o.get("headless"):
        argv += ["-hl", "-sc", "-nos", "-ho", "--disable-dev-shm-usage", "-ho", "--disable-gpu"]
    if o.get("include_regex"):
        argv += ["-cs", o["include_regex"]]
    if o.get("exclude_regex"):
        argv += ["-cos", o["exclude_regex"]]
    for h in o.get("headers") or []:
        argv += ["-H", h]
    if o.get("proxy"):
        argv += ["-proxy", o["proxy"]]
    return argv


def start(params, client_ip=None):
    url = _clean_url(params.get("target"))
    field_scope = (params.get("field_scope") or "fqdn").lower()
    if field_scope not in FIELD_SCOPE:
        raise ValueError("crawl scope must be dn, rdn or fqdn")
    known = (params.get("known_files") or "").lower()
    if known not in KNOWN_FILES:
        raise ValueError("known files must be all, robotstxt, sitemapxml or empty")
    duration = (params.get("crawl_duration") or "").strip().lower().replace(" ", "")
    if duration and not DURATION_RX.match(duration):
        raise ValueError("crawl duration must look like 10m, 600s or 1h")
    include_rx = (params.get("include_regex") or "").strip()
    exclude_rx = (params.get("exclude_regex") or "").strip()
    for name, rx in (("include", include_rx), ("exclude", exclude_rx)):
        if len(rx) > REGEX_MAX or "\n" in rx:
            raise ValueError("{} regex is too long".format(name))
    headers = []
    for line in (params.get("headers") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if not HEADER_RX.match(line):
            raise ValueError("headers must be 'Name: value', one per line")
        headers.append(line)
    proxy = (params.get("proxy") or "").strip()
    if proxy and not PROXY_RX.match(proxy):
        raise ValueError("proxy must look like http://host:8080 or socks5://host:1080")
    depth = st.get_int("recon.katana_depth", _ov(params, "depth", "recon.katana_depth"))
    if known == "all" and depth < 3:
        depth = 3   # known-files 'all' needs a minimum depth of 3
    opts = {"depth": depth, "field_scope": field_scope, "known_files": known, "crawl_duration": duration,
            "concurrency": st.get_int("recon.katana_concurrency", _ov(params, "concurrency", "recon.katana_concurrency")),
            "parallelism": st.get_int("recon.katana_parallelism", _ov(params, "parallelism", "recon.katana_parallelism")),
            "rate_limit": st.get_int("recon.katana_rate_limit", _ov(params, "rate_limit", "recon.katana_rate_limit")),
            "timeout": st.get_int("recon.katana_timeout", _ov(params, "timeout", "recon.katana_timeout")),
            "retry": st.get_int("recon.katana_retry", _ov(params, "retry", "recon.katana_retry")),
            "stage_timeout": st.get_int("recon.katana_stage_timeout"),
            "js_crawl": bool(params.get("js_crawl")), "jsluice": bool(params.get("jsluice")),
            "headless": bool(params.get("headless")), "form_extraction": bool(params.get("form_extraction")),
            "tech_detect": bool(params.get("tech_detect")), "ignore_query_params": bool(params.get("ignore_query_params")),
            "include_regex": include_rx, "exclude_regex": exclude_rx, "headers": headers, "proxy": proxy,
            "profile": (params.get("profile") or "")[:20]}
    with session_scope() as s:
        r = KatanaRun(target=url, status="pending", options=opts)
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("katana_run_create", client_ip=client_ip, run_id=run_id, target=url)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, url, opts, ev), name="katana-%d" % run_id, daemon=True).start()
    return run_id


def _ov(params, key, setting_key):
    v = params.get(key)
    if v in (None, ""):
        return None
    return {setting_key: v}


def _parse(d):
    """A katana JSONL record -> {url, method, status}."""
    req = d.get("request") or {}
    resp = d.get("response") or {}
    url = req.get("endpoint") or d.get("endpoint") or d.get("url") or ""
    return {"url": url, "method": req.get("method") or d.get("method") or "GET",
            "status": resp.get("status_code") or d.get("status_code") or ""}


def _stats(urls):
    hosts = set()
    for u in urls:
        m = re.match(r"^https?://([^/]+)", u["url"] or "")
        if m:
            hosts.add(m.group(1))
    return {"urls": len(urls), "hosts": len(hosts)}


def _run(run_id, url, opts, cancel_ev):
    argv = _argv(url, opts)
    urls = []
    seen = set()
    saw_error = []
    _log_append(run_id, "$ katana " + " ".join(argv))
    try:
        update(run_id, status="running")
        host, port = _hostport(KATANA)
        s = socket.create_connection((host, port), timeout=15)
        s.sendall(("\n".join(argv) + "\n__END__\n").encode("utf-8"))
        total = min(7200, max(opts["stage_timeout"], _ct_seconds(opts.get("crawl_duration")) + 120))
        deadline = time.time() + total
        rbuf, last_push = b"", 0.0

        def handle(line):
            line = ANSI_RX.sub("", line).rstrip()
            if not line:
                return
            _log_append(run_id, line)
            if line.startswith("{"):
                try:
                    d = json.loads(line)
                except ValueError:
                    return
                rec = _parse(d)
                if rec["url"] and rec["url"] not in seen:
                    seen.add(rec["url"])
                    urls.append(rec)
            elif re.search(r"\b(FTL|FATAL|could not|failed to)\b", line, re.I):
                saw_error.append(line)

        while not cancel_ev.is_set():
            left = deadline - time.time()
            if left <= 0:
                _log_append(run_id, "[api] reached the stage limit of {}s, stopping".format(opts["stage_timeout"]))
                break
            s.settimeout(min(120, left))
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            rbuf += chunk
            while b"\n" in rbuf:
                raw, rbuf = rbuf.split(b"\n", 1)
                handle(raw.decode("utf-8", "replace"))
            now = time.time()
            if now - last_push > 1.5:
                last_push = now
                update(run_id, results=list(urls), stats=_stats(urls))
        try:
            s.close()
        except OSError:
            pass
        if rbuf.strip():
            handle(rbuf.decode("utf-8", "replace"))
        status = "cancelled" if cancel_ev.is_set() else ("failed" if (saw_error and not urls) else "completed")
        err = saw_error[0] if status == "failed" else None
        _log_append(run_id, "[api] {} - {} url(s)".format(status, len(urls)))
        update(run_id, status=status, error=err, results=list(urls), stats=_stats(urls), finished_at=_now())
        if status == "completed":
            st.audit("katana_run_done", run_id=run_id, target=url, urls=len(urls))
    except (OSError, socket.error) as exc:
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error="Katana unreachable ({}). Is the recon-katana container running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("katana %s", run_id)
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def row(r):
    with _lock:
        has_log = bool(_logs.get(r.id))
    return {"id": r.id, "target": r.target, "status": r.status, "error": r.error, "options": r.options,
            "results": r.results, "stats": r.stats, "active": is_active(r.id), "has_log": has_log,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}


def summary(r):
    out = row(r)
    out["urls"] = len(out.pop("results") or [])
    return out
