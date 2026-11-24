"""Kubescape manifest / Helm / IaC scanning in its own container, reached over
TCP (socat). The control artifacts are baked into the image, so manifest scans
run fully offline and deterministically with NO Kubernetes cluster access. The
API sends validated argv (one token per line) + __END__ then the manifest YAML;
the container scans it and returns native JSON after a sentinel, parsed
deterministically (no AI)."""
import json
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import desc, select

from wtdb.database import session_scope
from wtdb.models import KubescapeScan

from . import settings as st

log = logging.getLogger("kubescape")
KUBESCAPE = os.environ.get("RECON_KUBESCAPE", "recon-kubescape:7010")
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Baked frameworks (see /artifacts in the image). allcontrols runs everything.
FRAMEWORKS = ("nsa", "mitre", "cis-v1.10.0", "allcontrols")
NAME_RX = re.compile(r"^[\w .:/\-]{1,120}$")
SENTINEL = "__KUBESCAPE_JSON__"
MANIFEST_MAX = 512 * 1024
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
        for r in s.execute(select(KubescapeScan).where(KubescapeScan.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the scan"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(KubescapeScan, run_id)
        for k, v in f.items():
            setattr(r, k, v)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def start(params, client_ip=None):
    name = (params.get("name") or "manifest").strip()
    if not NAME_RX.match(name):
        name = "manifest"
    manifest = params.get("manifest") or ""
    if not manifest.strip():
        raise ValueError("paste a Kubernetes manifest (YAML) to scan")
    if len(manifest.encode("utf-8")) > MANIFEST_MAX:
        raise ValueError("manifest is too large (limit 512 KB)")
    if not re.search(r"(^|\n)\s*(apiVersion|kind)\s*:", manifest):
        raise ValueError("this does not look like a Kubernetes manifest (no apiVersion/kind)")
    frameworks = [x for x in (params.get("frameworks") or ["nsa"]) if x in FRAMEWORKS] or ["nsa"]
    opts = {"frameworks": frameworks, "stage_timeout": st.get_int("recon.kubescape_stage_timeout")}
    with session_scope() as s:
        r = KubescapeScan(name=name, status="pending", options=opts)
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("kubescape_scan_create", client_ip=client_ip, run_id=run_id, name=name, frameworks=frameworks)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, manifest, opts, ev), name="kubescape-%d" % run_id, daemon=True).start()
    return run_id


def _sev(sf):
    """Kubescape maps a control's scoreFactor to a severity band."""
    if sf is None:
        return "Unknown"
    if sf >= 9:
        return "Critical"
    if sf >= 7:
        return "High"
    if sf >= 4:
        return "Medium"
    return "Low"


def _parse(doc):
    sd = doc.get("summaryDetails") or {}
    controls = sd.get("controls") or {}
    out_controls, by_sev = [], {}
    failed_resources = passed = failed = skipped = 0
    for cid, c in controls.items():
        status = c.get("status")
        if status == "passed":
            passed += 1
        elif status == "skipped":
            skipped += 1
        elif status == "failed":
            failed += 1
        rc = c.get("ResourceCounters") or {}
        if status == "failed":
            sev = _sev(c.get("scoreFactor"))
            by_sev[sev] = by_sev.get(sev, 0) + 1
            failed_resources += rc.get("failedResources", 0)
            cat = c.get("category")
            out_controls.append({
                "id": cid, "name": c.get("name"), "severity": sev,
                "score_factor": c.get("scoreFactor"),
                "category": (cat.get("name") if isinstance(cat, dict) else cat) or "",
                "failed_resources": rc.get("failedResources", 0),
                "compliance_score": round(c.get("complianceScore") or 0, 1),
                "url": "https://hub.armosec.io/docs/{}".format(cid.lower())})
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    out_controls.sort(key=lambda x: (-rank.get(x["severity"], 0), -x["failed_resources"]))
    # per-resource rollup (manifest objects and how many controls each failed)
    resources = []
    for r in (doc.get("results") or []):
        obj = r.get("resourceID") or ""
        rc = [c for c in (r.get("controls") or []) if (c.get("status") or {}).get("status") == "failed"]
        if rc:
            resources.append({"id": obj, "failed_controls": len(rc)})
    frameworks = [{"name": f.get("name"), "score": round(f.get("complianceScore") or 0, 1)}
                  for f in (sd.get("frameworks") or [])]
    stats = {"score": round(sd.get("complianceScore") or sd.get("score") or 0, 1),
             "failed_controls": failed, "passed_controls": passed, "skipped_controls": skipped,
             "total_controls": len(controls), "failed_resources": failed_resources, "by_severity": by_sev}
    res = {"frameworks": frameworks, "controls": out_controls, "resources": resources}
    return res, stats


def _run(run_id, manifest, opts, cancel_ev):
    argv = ["scan", "framework", ",".join(opts["frameworks"])]
    _log_append(run_id, "$ kubescape " + " ".join(argv) + " <manifest> --format json")
    jbuf, in_json, saw_error = [], False, []
    try:
        update(run_id, status="running")
        host, port = _hostport(KUBESCAPE)
        s = socket.create_connection((host, port), timeout=15)
        s.sendall(("\n".join(argv) + "\n__END__\n").encode("utf-8") + manifest.encode("utf-8"))
        s.shutdown(socket.SHUT_WR)   # EOF so the container's `cat > manifest` completes
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
            if not line or line.startswith("{\"level\""):   # skip kubescape info log json
                return
            _log_append(run_id, line)
            if re.search(r"\bFATAL\b|\[error\]|could not|failed to", line, re.I):
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
                saw_error.append("could not parse Kubescape JSON: {}".format(exc))
        if doc is None:
            msg = saw_error[-1] if saw_error else "Kubescape produced no report"
            _log_append(run_id, "[api] failed - {}".format(msg))
            update(run_id, status="failed", error=msg, finished_at=_now())
            return
        res, stats = _parse(doc)
        _log_append(run_id, "[api] completed - compliance score {}, {} failed controls ({} resources)".format(
            stats["score"], stats["failed_controls"], stats["failed_resources"]))
        update(run_id, status="completed", results=res, stats=stats, score=stats["score"], finished_at=_now())
        st.audit("kubescape_scan_done", run_id=run_id, score=stats["score"], failed=stats["failed_controls"])
    except (OSError, socket.error) as exc:
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error="Kubescape unreachable ({}). Is recon-kubescape running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("kubescape %s", run_id)
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def row(r):
    with _lock:
        has_log = bool(_logs.get(r.id))
    return {"id": r.id, "name": r.name, "status": r.status, "error": r.error, "score": r.score,
            "options": r.options, "results": r.results, "stats": r.stats, "active": is_active(r.id),
            "has_log": has_log, "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}


def summary(r):
    out = row(r)
    out.pop("results", None)
    return out


def overview():
    with session_scope() as s:
        scans = list(s.execute(select(KubescapeScan).where(KubescapeScan.status == "completed")
                               .order_by(desc(KubescapeScan.id))).scalars())
        recent = [summary(r) for r in s.execute(select(KubescapeScan).order_by(desc(KubescapeScan.id)).limit(10)).scalars()]
    agg = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    failed = resources = 0
    ctrl_count = {}
    for sc in scans:
        stt = sc.stats or {}
        for k, v in (stt.get("by_severity") or {}).items():
            agg[k] = agg.get(k, 0) + v
        failed += stt.get("failed_controls", 0)
        resources += stt.get("failed_resources", 0)
        for c in (sc.results or {}).get("controls", []):
            ctrl_count[c["name"]] = ctrl_count.get(c["name"], 0) + 1
    avg = round(sum(sc.score or 0 for sc in scans) / len(scans), 1) if scans else None
    top = sorted(ctrl_count.items(), key=lambda x: -x[1])[:10]
    return {"scans": len(scans), "avg_score": avg, "by_severity": agg,
            "failed_controls": failed, "failed_resources": resources,
            "top_controls": [{"name": n, "count": c} for n, c in top], "recent": recent}
