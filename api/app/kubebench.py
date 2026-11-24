"""kube-bench (CIS Kubernetes benchmark) in its own container, reached over TCP
(socat). kube-bench inspects the node it runs on; a meaningful assessment
requires running on / targeting a real Kubernetes control-plane or worker node
(via an in-cluster sensor/Job). The API sends validated argv (one token per
line) + __END__; the container runs kube-bench and returns native JSON after a
sentinel, parsed deterministically (no AI). No Docker socket is used."""
import json
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import desc, select

from wtdb.database import session_scope
from wtdb.models import KubeBenchScan

from . import settings as st

log = logging.getLogger("kubebench")
KUBEBENCH = os.environ.get("RECON_KUBEBENCH", "recon-kubebench:7011")
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
BENCHMARKS = ("cis-1.9", "cis-1.8", "cis-1.7", "cis-1.10", "aks-1.7", "eks-1.5", "gke-1.6")
TARGETS = ("master", "node", "etcd", "controlplane", "policies")
SENTINEL = "__KUBEBENCH_JSON__"
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
        for r in s.execute(select(KubeBenchScan).where(KubeBenchScan.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the scan"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(KubeBenchScan, run_id)
        for k, v in f.items():
            setattr(r, k, v)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def start(params, client_ip=None):
    benchmark = params.get("benchmark") or "cis-1.9"
    if benchmark not in BENCHMARKS:
        raise ValueError("unknown benchmark; choose one of: {}".format(", ".join(BENCHMARKS)))
    targets = [t for t in (params.get("targets") or ["master", "node"]) if t in TARGETS] or ["master", "node"]
    opts = {"benchmark": benchmark, "targets": targets, "stage_timeout": st.get_int("recon.kubebench_stage_timeout")}
    with session_scope() as s:
        r = KubeBenchScan(benchmark=benchmark, targets=",".join(targets), status="pending", stats={})
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("kubebench_scan_create", client_ip=client_ip, run_id=run_id, benchmark=benchmark, targets=targets)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, opts, ev), name="kubebench-%d" % run_id, daemon=True).start()
    return run_id


def _parse(doc):
    checks, sections = [], []
    totals = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
    for ctrl in doc.get("Controls") or []:
        node = ctrl.get("node_type")
        for t in ctrl.get("tests") or []:
            sec = {"section": t.get("section"), "desc": t.get("desc"), "node": node,
                   "pass": 0, "fail": 0, "warn": 0, "info": 0}
            for r in t.get("results") or []:
                status = (r.get("status") or "").upper()
                totals[status] = totals.get(status, 0) + 1
                key = status.lower()
                sec[key] = sec.get(key, 0) + 1
                checks.append({"id": r.get("test_number"), "node": node, "section": t.get("section"),
                               "status": status, "desc": r.get("test_desc"),
                               "remediation": (r.get("remediation") or "").strip(),
                               "scored": r.get("scored")})
            sections.append(sec)
    return {"checks": checks, "sections": sections}, totals


def _stats(totals):
    p, f = totals.get("PASS", 0), totals.get("FAIL", 0)
    scored = p + f
    return {"pass": p, "fail": f, "warn": totals.get("WARN", 0), "info": totals.get("INFO", 0),
            "total": sum(totals.values()),
            "pass_rate": round(100.0 * p / scored, 1) if scored else None}


def _run(run_id, opts, cancel_ev):
    argv = ["run", "--targets", ",".join(opts["targets"]), "--benchmark", opts["benchmark"]]
    _log_append(run_id, "$ kube-bench " + " ".join(argv) + " --json")
    _log_append(run_id, "[api] note: meaningful results require running on a real Kubernetes node.")
    jbuf, in_json, saw_error = [], False, []
    try:
        update(run_id, status="running")
        host, port = _hostport(KUBEBENCH)
        s = socket.create_connection((host, port), timeout=15)
        s.sendall(("\n".join(argv) + "\n__END__\n").encode("utf-8"))
        deadline = time.time() + opts["stage_timeout"]
        rbuf = b""

        def handle(line):
            nonlocal in_json
            if in_json:
                jbuf.append(line)
                return
            line = ANSI_RX.sub("", line).rstrip()
            if line == SENTINEL:
                in_json = True
                return
            if not line:
                return
            _log_append(run_id, line)
            if re.search(r"\bFATAL\b|panic:|unable to|could not", line, re.I):
                saw_error.append(line)

        while not cancel_ev.is_set():
            left = deadline - time.time()
            if left <= 0:
                _log_append(run_id, "[api] reached the stage limit of {}s, stopping".format(opts["stage_timeout"]))
                break
            s.settimeout(min(60, left))
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
        try:
            s.close()
        except OSError:
            pass
        if rbuf.strip():
            handle(rbuf.decode("utf-8", "replace"))

        if cancel_ev.is_set():
            _log_append(run_id, "[api] cancelled")
            update(run_id, status="cancelled", finished_at=_now())
            return
        doc = None
        if jbuf:
            try:
                doc = json.loads("\n".join(jbuf))
            except ValueError as exc:
                saw_error.append("could not parse kube-bench JSON: {}".format(exc))
        if doc is None:
            msg = saw_error[-1] if saw_error else "kube-bench produced no report"
            _log_append(run_id, "[api] failed - {}".format(msg))
            update(run_id, status="failed", error=msg, finished_at=_now())
            return
        res, totals = _parse(doc)
        stats = _stats(totals)
        _log_append(run_id, "[api] completed - {} pass, {} fail, {} warn".format(stats["pass"], stats["fail"], stats["warn"]))
        update(run_id, status="completed", results=res, stats=stats, finished_at=_now())
        st.audit("kubebench_scan_done", run_id=run_id, **{k: stats[k] for k in ("pass", "fail", "warn")})
    except (OSError, socket.error) as exc:
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error="kube-bench unreachable ({}). Is recon-kubebench running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("kubebench %s", run_id)
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def row(r):
    with _lock:
        has_log = bool(_logs.get(r.id))
    return {"id": r.id, "benchmark": r.benchmark, "targets": r.targets, "status": r.status, "error": r.error,
            "results": r.results, "stats": r.stats, "active": is_active(r.id), "has_log": has_log,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}


def summary(r):
    out = row(r)
    out.pop("results", None)
    return out
