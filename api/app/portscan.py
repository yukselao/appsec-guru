"""Port scanning with RustScan, running in its own container, reached over TCP
(socat). Asynchronous; results stream into PostgreSQL. Lab use only."""
import logging
import os
import re
import socket
import threading

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
_active = {}
_lock = threading.Lock()


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
    if ports and not PORTS_RX.match(ports):
        raise ValueError("ports: digits, commas and dashes only (e.g. 1-1000 or 22,80,443)")
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


def _run(run_id, target, opts, cancel_ev):
    ports = opts["ports"] or ("1-65535" if opts["full"] else "")
    payload = "{} {}".format(target, ports).strip()
    try:
        update(run_id, status="running")
        host, port = _hostport(RUSTSCAN)
        s = socket.create_connection((host, port), timeout=15)
        s.sendall((payload + "\n__END__\n").encode("utf-8"))
        s.settimeout(opts["timeout"] / 1000.0 * 70 + 60)
        buf = b""
        while not cancel_ev.is_set():
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        s.close()
        out = buf.decode("utf-8", "replace")
        results = []
        for line in out.splitlines():
            m = GREP_RX.match(line.strip())
            if m:
                ports = [int(p) for p in m.group(2).split(",") if p]
                results.append({"host": m.group(1), "ports": ports})
        total = sum(len(r["ports"]) for r in results)
        if cancel_ev.is_set():
            update(run_id, status="cancelled", results=results, stats={"open_ports": total, "hosts": len(results)}, finished_at=_now())
        else:
            update(run_id, status="completed", results=results, stats={"open_ports": total, "hosts": len(results)}, finished_at=_now())
            st.audit("port_scan_done", run_id=run_id, target=target, open_ports=total)
    except (OSError, socket.error) as exc:
        update(run_id, status="failed", error="RustScan unreachable ({}). Is the recon-rustscan container running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("portscan %s", run_id)
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def row(r):
    return {"id": r.id, "target": r.target, "ports": r.ports, "status": r.status, "error": r.error, "options": r.options,
            "results": r.results, "stats": r.stats, "active": is_active(r.id),
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}
