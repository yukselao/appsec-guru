"""Nuclei (CVE / template vulnerability discovery) in its own container, reached
over TCP (socat). Asynchronous; findings stream into PostgreSQL. Lab use only:
scan only targets you are authorised to test."""
import json
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import select

from wtdb.database import session_scope
from wtdb.models import NucleiRun

from . import settings as st

log = logging.getLogger("nuclei")
NUCLEI = os.environ.get("RECON_NUCLEI", "recon-nuclei:7005")
URL_RX = re.compile(r"^https?://[\w.\-]+(:\d+)?(/[^\s]*)?$", re.I)
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SEVERITIES = ("info", "low", "medium", "high", "critical")
TAGS_RX = re.compile(r"^[A-Za-z0-9 ,_\-]{0,200}$")
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
        for r in s.execute(select(NucleiRun).where(NucleiRun.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the run"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(NucleiRun, run_id)
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


def _argv(url, opts):
    """Build the whole nuclei argv. Only whitelisted flags; user strings are
    only ever flag VALUES. -jsonl/-no-color are forced by the container."""
    argv = ["-u", url,
            "-rate-limit", str(opts["rate_limit"]),
            "-timeout", str(opts["timeout"]),
            "-c", str(opts["concurrency"]),
            "-duc", "-ni"]   # no auto-update, no interactsh (offline/lab)
    sev = [x for x in opts.get("severity") or [] if x in SEVERITIES]
    if sev and len(sev) < len(SEVERITIES):
        argv += ["-severity", ",".join(sev)]
    tags = (opts.get("tags") or "").strip()
    if tags:
        argv += ["-tags", tags]
    return argv


def start(params, client_ip=None):
    url = _clean_url(params.get("target"))
    tags = (params.get("tags") or "").strip()
    if not TAGS_RX.match(tags):
        raise ValueError("tags may use letters, digits, comma, dash and underscore only")
    sev = [x for x in (params.get("severity") or []) if x in SEVERITIES]
    opts = {"rate_limit": st.get_int("recon.nuclei_rate_limit", _ov(params, "rate_limit", "recon.nuclei_rate_limit")),
            "timeout": st.get_int("recon.nuclei_timeout", _ov(params, "timeout", "recon.nuclei_timeout")),
            "concurrency": st.get_int("recon.nuclei_concurrency", _ov(params, "concurrency", "recon.nuclei_concurrency")),
            "stage_timeout": st.get_int("recon.nuclei_stage_timeout"),
            "severity": sev, "tags": tags}
    with session_scope() as s:
        r = NucleiRun(target=url, status="pending", options=opts)
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("nuclei_run_create", client_ip=client_ip, run_id=run_id, target=url)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, url, opts, ev), name="nuclei-%d" % run_id, daemon=True).start()
    return run_id


def _ov(params, key, setting_key):
    """A per-run override dict for st.get_int: UI value if given, else effective."""
    v = params.get(key)
    if v in (None, ""):
        return None
    return {setting_key: v}


def _stats(findings):
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    return {"findings": len(findings), "by_severity": by}


def _run(run_id, url, opts, cancel_ev):
    argv = _argv(url, opts)
    findings = []
    saw_error = []
    _log_append(run_id, "$ nuclei " + " ".join(argv))
    try:
        update(run_id, status="running")
        host, port = _hostport(NUCLEI)
        s = socket.create_connection((host, port), timeout=15)
        s.sendall(("\n".join(argv) + "\n__END__\n").encode("utf-8"))
        deadline = time.time() + opts["stage_timeout"]
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
                info = d.get("info") or {}
                findings.append({
                    "template": d.get("template-id") or d.get("templateID") or "",
                    "name": info.get("name") or "",
                    "severity": (info.get("severity") or "info").capitalize(),
                    "matched_at": d.get("matched-at") or d.get("matched") or d.get("host") or "",
                    "type": d.get("type") or ""})
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
                update(run_id, results=list(findings), stats=_stats(findings))
        try:
            s.close()
        except OSError:
            pass
        if rbuf.strip():
            handle(rbuf.decode("utf-8", "replace"))
        status = "cancelled" if cancel_ev.is_set() else ("failed" if (saw_error and not findings) else "completed")
        err = saw_error[0] if status == "failed" else None
        _log_append(run_id, "[api] {} - {} finding(s)".format(status, len(findings)))
        update(run_id, status=status, error=err, results=list(findings), stats=_stats(findings), finished_at=_now())
        if status == "completed":
            st.audit("nuclei_run_done", run_id=run_id, target=url, findings=len(findings))
    except (OSError, socket.error) as exc:
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error="Nuclei unreachable ({}). Is the recon-nuclei container running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("nuclei %s", run_id)
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
    out["findings"] = len(out.pop("results") or [])
    return out
