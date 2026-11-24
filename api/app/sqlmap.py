"""SQLMap (SQL-injection detection) in its own container, reached over TCP
(socat). Asynchronous; the verbose log streams into an in-memory buffer and
parsed findings into PostgreSQL. Detection/enumeration only - the api never
passes exploitation, file or shell flags. Lab use only."""
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import select

from wtdb.database import session_scope
from wtdb.models import SqlmapRun

from . import settings as st

log = logging.getLogger("sqlmap")
SQLMAP = os.environ.get("RECON_SQLMAP", "recon-sqlmap:7007")
URL_RX = re.compile(r"^https?://[\w.\-]+(:\d+)?(/[^\s]*)?$", re.I)
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TECH_RX = re.compile(r"^[BEUSTQ]{1,6}$")
LOG_MAX = 6000
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
        for r in s.execute(select(SqlmapRun).where(SqlmapRun.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the run"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(SqlmapRun, run_id)
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
        raise ValueError("enter a valid target URL, e.g. http://192.168.1.140:3000/rest/products/search?q=1")
    return u


def _argv(url, opts):
    """Whole sqlmap argv. Detection/enumeration only - NEVER emits --os-*,
    --file-*, --sql-shell, --eval or other exploitation flags. --batch and
    --disable-coloring are forced by the container."""
    argv = ["-u", url,
            "--level", str(opts["level"]),
            "--risk", str(opts["risk"]),
            "--threads", str(opts["threads"])]
    if opts.get("data"):
        argv += ["--data", opts["data"]]
    if opts.get("cookie"):
        argv += ["--cookie", opts["cookie"]]
    if opts.get("technique"):
        argv += ["--technique", opts["technique"]]
    if opts.get("dbs"):
        argv += ["--dbs"]
    return argv


def start(params, client_ip=None):
    url = _clean_url(params.get("target"))
    tech = (params.get("technique") or "").strip().upper()
    if tech and not TECH_RX.match(tech):
        raise ValueError("technique must be letters from BEUSTQ (e.g. BEU)")
    data = (params.get("data") or "").strip()
    cookie = (params.get("cookie") or "").strip()
    for name, val in (("data", data), ("cookie", cookie)):
        if "\n" in val or "\r" in val:
            raise ValueError("{} must be a single line".format(name))
    opts = {"level": st.get_int("recon.sqlmap_level", _ov(params, "level", "recon.sqlmap_level")),
            "risk": st.get_int("recon.sqlmap_risk", _ov(params, "risk", "recon.sqlmap_risk")),
            "threads": st.get_int("recon.sqlmap_threads", _ov(params, "threads", "recon.sqlmap_threads")),
            "stage_timeout": st.get_int("recon.sqlmap_stage_timeout"),
            "data": data, "cookie": cookie, "technique": tech, "dbs": bool(params.get("dbs"))}
    with session_scope() as s:
        r = SqlmapRun(target=url, status="pending", options=opts)
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("sqlmap_run_create", client_ip=client_ip, run_id=run_id, target=url)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, url, opts, ev), name="sqlmap-%d" % run_id, daemon=True).start()
    return run_id


def _ov(params, key, setting_key):
    v = params.get(key)
    if v in (None, ""):
        return None
    return {setting_key: v}


def _run(run_id, url, opts, cancel_ev):
    argv = _argv(url, opts)
    shown = [a if not (i and argv[i - 1] in ("--cookie", "--data")) else "***" for i, a in enumerate(argv)]
    st_ = {"vulnerable": False, "dbms": "", "injections": [], "databases": []}
    collecting = {"dbs": False}
    saw_error = []
    _log_append(run_id, "$ sqlmap " + " ".join(shown))
    try:
        update(run_id, status="running")
        host, port = _hostport(SQLMAP)
        s = socket.create_connection((host, port), timeout=15)
        s.sendall(("\n".join(argv) + "\n__END__\n").encode("utf-8"))
        deadline = time.time() + opts["stage_timeout"]
        rbuf, last_push = b"", 0.0

        def handle(line):
            line = ANSI_RX.sub("", line.rstrip("\r\n"))
            if not line.strip():
                return
            _log_append(run_id, line)
            m = re.match(r"\s*Parameter:\s*(.+?)\s*\(([^)]+)\)", line)
            if m:
                st_["vulnerable"] = True
                st_["injections"].append({"parameter": m.group(1), "place": m.group(2), "types": []})
                return
            m = re.match(r"\s*Type:\s*(.+)", line)
            if m and st_["injections"]:
                st_["injections"][-1]["types"].append({"type": m.group(1).strip(), "title": "", "payload": ""})
                return
            m = re.match(r"\s*Title:\s*(.+)", line)
            if m and st_["injections"] and st_["injections"][-1]["types"]:
                st_["injections"][-1]["types"][-1]["title"] = m.group(1).strip()
                return
            m = re.match(r"\s*Payload:\s*(.+)", line)
            if m and st_["injections"] and st_["injections"][-1]["types"]:
                st_["injections"][-1]["types"][-1]["payload"] = m.group(1).strip()[:400]
                return
            m = re.search(r"back-end DBMS:\s*(.+)", line) or re.search(r"the back-end DBMS is\s*['\"]?([A-Za-z0-9 .>=_-]+)", line)
            if m:
                st_["dbms"] = m.group(1).strip().strip("'\"").split(". ")[0]
                return
            if re.search(r"available databases\s*\[\d+\]", line):
                collecting["dbs"] = True
                return
            if collecting["dbs"]:
                md = re.match(r"\s*\[\*\]\s*(.+)", line)
                if md:
                    st_["databases"].append(md.group(1).strip())
                    return
                collecting["dbs"] = False
            if re.search(r"is vulnerable|injection point\(s\)", line, re.I):
                st_["vulnerable"] = True
            if re.search(r"unable to connect|connection (?:refused|reset|timed out)|could not connect|"
                         r"name or service not known|no route to host|getaddrinfo", line, re.I):
                saw_error.append(line)

        def stats():
            return {"vulnerable": st_["vulnerable"], "injections": len(st_["injections"]),
                    "dbms": st_["dbms"], "databases": len(st_["databases"])}

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
                update(run_id, results=dict(st_), stats=stats())
        try:
            s.close()
        except OSError:
            pass
        if rbuf.strip():
            handle(rbuf.decode("utf-8", "replace"))
        status = "cancelled" if cancel_ev.is_set() else (
            "failed" if (saw_error and not st_["vulnerable"] and not st_["injections"]) else "completed")
        err = saw_error[-1] if status == "failed" else None
        _log_append(run_id, "[api] {} - {}".format(
            status, "vulnerable" if st_["vulnerable"] else "no injection found"))
        update(run_id, status=status, error=err, results=dict(st_), stats=stats(), finished_at=_now())
        if status == "completed":
            st.audit("sqlmap_run_done", run_id=run_id, target=url, vulnerable=st_["vulnerable"])
    except (OSError, socket.error) as exc:
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error="SQLMap unreachable ({}). Is the recon-sqlmap container running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("sqlmap %s", run_id)
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def row(r):
    with _lock:
        has_log = bool(_logs.get(r.id))
    return {"id": r.id, "target": r.target, "status": r.status, "error": r.error, "options": _safe_opts(r.options),
            "results": r.results, "stats": r.stats, "active": is_active(r.id), "has_log": has_log,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}


def _safe_opts(opts):
    """Hide cookie/data values in API responses."""
    o = dict(opts or {})
    for k in ("cookie", "data"):
        if o.get(k):
            o[k] = "***"
    return o


def summary(r):
    out = row(r)
    out.pop("results", None)
    return out
