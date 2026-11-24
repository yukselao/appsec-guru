"""Port scanning with RustScan, running in its own container, reached over TCP
(socat). Asynchronous; results stream into PostgreSQL. Lab use only."""
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import select

from wtdb.database import session_scope
from wtdb.models import PortScanRun

from . import settings as st

log = logging.getLogger("portscan")
RUSTSCAN = os.environ.get("RECON_RUSTSCAN", "recon-rustscan:7004")
TARGET_RX = re.compile(r"^[A-Za-z0-9.\-]{1,255}$")
PORTS_RX = re.compile(r"^[0-9,\-]{0,200}$")
# RustScan greppable line: "<ip> -> [22,80,443]"
GREP_RX = re.compile(r"^(\S+)\s*->\s*\[([0-9,]*)\]")
# live (non-greppable) RustScan prints one such line per open port as it finds it
OPEN_RX = re.compile(r"Open\s+([0-9.]+):(\d+)")
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LOG_MAX = 2000      # lines kept per run
LOG_RUNS = 25       # runs kept in memory
_active = {}
_logs = {}          # run_id -> [line, ...]; live, in memory only
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
    """New log lines past `offset` (a line count). Lines live in memory only, so
    a finished run keeps its log until the api restarts or it is evicted."""
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
        for r in s.execute(select(PortScanRun).where(PortScanRun.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the run"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(PortScanRun, run_id)
        for k, v in f.items():
            setattr(r, k, v)


def start(params, client_ip=None):
    target = (params.get("target") or "").strip()
    target = re.sub(r"^\w+://", "", target).split("/")[0].split(":")[0]
    if not TARGET_RX.match(target):
        raise ValueError("enter a host or IP (no scheme)")
    ports = (params.get("ports") or "").strip().replace(" ", "")
    if ports and not (re.match(r"^\d{1,5}-\d{1,5}$", ports) or re.match(r"^\d{1,5}(,\d{1,5})*$", ports)):
        raise ValueError("ports must be one range (e.g. 1-1000) or a comma list (e.g. 22,80,443)")
    opts = {"ports": ports, "full": bool(params.get("full")), "timeout": max(1000, min(int(params.get("timeout") or 2500), 10000)),
            "batch": max(100, min(int(params.get("batch") or 4500), 65535))}
    with session_scope() as s:
        r = PortScanRun(target=target, ports=ports or None, status="pending", options=opts)
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("port_scan_create", client_ip=client_ip, run_id=run_id, target=target, ports=ports)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, target, opts, ev), name="portscan-%d" % run_id, daemon=True).start()
    return run_id


def _results(found):
    rows = [{"host": h, "ports": sorted(found[h])} for h in sorted(found)]
    return rows, sum(len(r["ports"]) for r in rows)


def _run(run_id, target, opts, cancel_ev):
    ports = opts["ports"] or ("1-65535" if opts["full"] else "")
    payload = "{} {}".format(target, ports).strip()
    found = {}            # ip -> set(open ports), filled live from "Open ip:port"
    saw_error = []
    _log_append(run_id, "$ rustscan -a {}{}".format(target, " " + ports if ports else " (default ports)"))
    try:
        update(run_id, status="running")
        host, port = _hostport(RUSTSCAN)
        s = socket.create_connection((host, port), timeout=15)
        s.sendall((payload + "\n__END__\n").encode("utf-8"))
        s.settimeout(120)
        rbuf, last_push = b"", 0.0

        def handle(line):
            line = ANSI_RX.sub("", line).rstrip()
            if not line:
                return
            _log_append(run_id, line)
            if "error" in line.lower() and "0 error" not in line.lower():
                saw_error.append(line)
            m = OPEN_RX.search(line)
            if m:
                found.setdefault(m.group(1), set()).add(int(m.group(2)))
            else:  # greppable fallback, in case the tool ever runs with -g
                g = GREP_RX.match(line)
                if g:
                    found.setdefault(g.group(1), set()).update(int(p) for p in g.group(2).split(",") if p)

        while not cancel_ev.is_set():
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                _log_append(run_id, "[api] no output for 120s, stopping")
                break
            if not chunk:
                break
            rbuf += chunk
            while b"\n" in rbuf:
                raw, rbuf = rbuf.split(b"\n", 1)
                handle(raw.decode("utf-8", "replace"))
            now = time.time()
            if now - last_push > 1.2:          # keep the results panel fresh too
                last_push = now
                rows, total = _results(found)
                update(run_id, results=rows, stats={"open_ports": total, "hosts": len(rows)})
        try:
            s.close()
        except OSError:
            pass
        if rbuf.strip():
            handle(rbuf.decode("utf-8", "replace"))
        rows, total = _results(found)
        status = "cancelled" if cancel_ev.is_set() else ("failed" if (saw_error and not rows) else "completed")
        err = saw_error[0] if status == "failed" else None
        _log_append(run_id, "[api] {} - {} open port(s)".format(status, total))
        update(run_id, status=status, error=err, results=rows,
               stats={"open_ports": total, "hosts": len(rows)}, finished_at=_now())
        if status == "completed":
            st.audit("port_scan_done", run_id=run_id, target=target, open_ports=total)
    except (OSError, socket.error) as exc:
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error="RustScan unreachable ({}). Is the recon-rustscan container running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("portscan %s", run_id)
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def row(r):
    with _lock:
        has_log = bool(_logs.get(r.id))
    return {"id": r.id, "target": r.target, "ports": r.ports, "status": r.status, "error": r.error, "options": r.options,
            "results": r.results, "stats": r.stats, "active": is_active(r.id), "has_log": has_log,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}
