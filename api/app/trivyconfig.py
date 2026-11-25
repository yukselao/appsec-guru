"""Trivy misconfiguration / IaC scanning (Dockerfile, Kubernetes manifests,
Docker Compose, Terraform) in the shared Trivy container, reached over TCP
(socat) on port 7012. The check bundle is baked into the image for deterministic
offline scans. The api streams the file content to the container, which runs
`trivy config` and returns native JSON after a sentinel, parsed deterministically
(no AI). No Docker socket is used - Trivy only reads the submitted text."""
import json
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import desc, select

from wtdb.database import session_scope
from wtdb.models import TrivyConfigScan

from . import settings as st

log = logging.getLogger("trivyconfig")
TRIVYCONFIG = os.environ.get("RECON_TRIVYCONFIG", "recon-trivy:7012")
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SENTINEL = "__TRIVYCONFIG_JSON__"
MANIFEST_MAX = 512 * 1024
# kind -> canonical filename Trivy uses to detect the config type.
KINDS = {
    "dockerfile": "Dockerfile",
    "kubernetes": "manifest.yaml",
    "compose": "docker-compose.yml",
    "terraform": "main.tf",
}
_SEV_MAP = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
            "LOW": "Low", "UNKNOWN": "Unknown"}
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
# The baked bundle carries a few cloud (AWS/Azure/GCP account) rego checks that a
# 0.58.1 parser cannot load; Trivy skips them. They are irrelevant to Dockerfile
# / K8s / Compose / Terraform file scanning, so we keep them out of the live log.
_NOISE_RX = re.compile(r"rego_type_error|Failed to find embedded check|Trying to fallback to embedded")
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
        for r in s.execute(select(TrivyConfigScan).where(TrivyConfigScan.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the scan"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(TrivyConfigScan, run_id)
        for k, v in f.items():
            setattr(r, k, v)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def start(params, client_ip=None):
    content = params.get("content") or ""
    if not content.strip():
        raise ValueError("no configuration content to scan")
    if len(content.encode("utf-8")) > MANIFEST_MAX:
        raise ValueError("content exceeds {} KB".format(MANIFEST_MAX // 1024))
    kind = (params.get("kind") or "dockerfile").lower()
    if kind not in KINDS:
        raise ValueError("unknown kind; choose one of: {}".format(", ".join(KINDS)))
    name = (params.get("name") or KINDS[kind]).strip()[:200] or KINDS[kind]
    opts = {"kind": kind, "filename": KINDS[kind],
            "stage_timeout": st.get_int("recon.trivyconfig_stage_timeout")}
    with session_scope() as s:
        r = TrivyConfigScan(name=name, kind=kind, status="pending", options=opts, stats={})
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("trivyconfig_scan_create", client_ip=client_ip, run_id=run_id, kind=kind, name=name)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, content, opts, ev), name="trivyconfig-%d" % run_id, daemon=True).start()
    return run_id


def _parse(doc):
    findings = []
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    detected = None
    for res in doc.get("Results") or []:
        rtype = res.get("Type")
        for m in res.get("Misconfigurations") or []:
            if (m.get("Status") or "").upper() == "PASS":
                continue
            sev = _SEV_MAP.get((m.get("Severity") or "UNKNOWN").upper(), "Unknown")
            counts[sev] = counts.get(sev, 0) + 1
            detected = detected or rtype
            cm = m.get("CauseMetadata") or {}
            findings.append({
                "id": m.get("ID") or m.get("AVDID"),
                "avdid": m.get("AVDID"),
                "title": m.get("Title"),
                "severity": sev,
                "message": (m.get("Message") or "").strip(),
                "resolution": (m.get("Resolution") or "").strip(),
                "description": (m.get("Description") or "").strip(),
                "url": m.get("PrimaryURL"),
                "type": rtype,
                "target": res.get("Target"),
                "start_line": cm.get("StartLine"),
                "end_line": cm.get("EndLine"),
            })
    findings.sort(key=lambda f: (-_SEV_RANK.get(f["severity"], 0), f.get("id") or ""))
    total = sum(counts.values())
    stats = {"total": total, "by_severity": counts, "detected": detected,
             "critical": counts["Critical"], "high": counts["High"],
             "medium": counts["Medium"], "low": counts["Low"]}
    return {"findings": findings, "detected": detected}, stats


def _run(run_id, content, opts, cancel_ev):
    _log_append(run_id, "$ trivy config <{}> --format json  (kind: {})".format(opts["filename"], opts["kind"]))
    jbuf, in_json, saw_error = [], False, []
    try:
        update(run_id, status="running")
        host, port = _hostport(TRIVYCONFIG)
        s = socket.create_connection((host, port), timeout=15)
        s.sendall((opts["filename"] + "\n__END__\n").encode("utf-8") + content.encode("utf-8"))
        s.shutdown(socket.SHUT_WR)   # EOF so the container's `cat > file` completes
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
            if not line or _NOISE_RX.search(line):
                return
            _log_append(run_id, line)
            if re.search(r"\bFATAL\b|panic:|unable to open|no such file", line, re.I):
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
                saw_error.append("could not parse Trivy JSON: {}".format(exc))
        if doc is None:
            msg = saw_error[-1] if saw_error else "Trivy produced no report"
            _log_append(run_id, "[api] failed - {}".format(msg))
            update(run_id, status="failed", error=msg, finished_at=_now())
            return
        res, stats = _parse(doc)
        _log_append(run_id, "[api] completed - {} misconfiguration(s): {} critical, {} high, {} medium, {} low".format(
            stats["total"], stats["critical"], stats["high"], stats["medium"], stats["low"]))
        update(run_id, status="completed", results=res, stats=stats, finished_at=_now())
        st.audit("trivyconfig_scan_done", run_id=run_id, total=stats["total"],
                 critical=stats["critical"], high=stats["high"])
    except (OSError, socket.error) as exc:
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error="Trivy unreachable ({}). Is recon-trivy running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("trivyconfig %s", run_id)
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def row(r):
    with _lock:
        has_log = bool(_logs.get(r.id))
    return {"id": r.id, "name": r.name, "kind": r.kind, "status": r.status, "error": r.error,
            "results": r.results, "stats": r.stats, "active": is_active(r.id), "has_log": has_log,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}


def summary(r):
    out = row(r)
    out.pop("results", None)
    return out
