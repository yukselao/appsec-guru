"""Scan runs: derive policy, toggle debug, launch on SC, capture the scanner log
of that scan (file + per-minute stats in PostgreSQL), poll SC, fetch findings."""
import datetime
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from wastools.core import (FINAL_STATES, RUN_PREFIX, Fatal, LogStreamer, SCError, set_output_sink)
from wastools.ops import create_was_scan, derive_policy, parse_sets, pick_repo
from wtdb.database import session_scope
from wtdb.models import ScanLogStat, ScanRun, ScanRunEvent

from . import conn
from . import settings as st

log = logging.getLogger("runs")
RUNS_DIR = os.environ.get("RUNS_DIR", "/var/log/was-troubleshooter/runs")
UUID_RX = re.compile(r"\[scanUuid=([0-9a-f-]{36})\]")
PROCESSING_RX = re.compile(r"processing scan ([0-9a-f-]{36})")
LEVEL_RX = re.compile(r"\[(DEBUG|INFO|NOTICE|WARN|ERROR|FATAL|TRACE)\]")
REQS_RX = re.compile(r"current req/s ([0-9.]+)")

_active = {}  # run_id -> threading.Event (cancel)
_alock = threading.Lock()


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def event(run_id, level, msg):
    try:
        with session_scope() as s:
            s.add(ScanRunEvent(run_id=run_id, level=level, message=str(msg)[:4000]))
    except Exception:
        log.exception("could not store the event")


def update(run_id, **fields):
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        for k, v in fields.items():
            setattr(r, k, v)


def is_active(run_id):
    with _alock:
        return run_id in _active


def cancel(run_id):
    with _alock:
        ev = _active.get(run_id)
    if ev:
        ev.set()
    return bool(ev)


def mark_orphans():
    """Runs left 'running' by a previous api process lose their log capture."""
    with session_scope() as s:
        for r in s.execute(select(ScanRun).where(ScanRun.status.in_(
                ["pending", "preparing", "launching", "running", "queued"]))).scalars():
            r.summary = dict(r.summary or {}, interrupted=now().isoformat())
            r.status = "interrupted"
            r.error = "the api restarted during the run"


class LogCapture(object):
    """Picks the scan's UUID from the shared scanner log, keeps its lines in a
    file and aggregates per-minute metrics."""

    def __init__(self, run_id, target_host, path):
        self.run_id = run_id
        self.target_host = target_host
        self.path = path
        self.uuid = None
        self.fh = open(path, "a", buffering=1)
        self.lock = threading.Lock()
        self.stats = defaultdict(lambda: defaultdict(float))
        self.reqs = defaultdict(list)
        self.counts = defaultdict(int)
        self.pending = []  # untagged lines before the uuid is known

    def on_line(self, line):
        m = UUID_RX.search(line)
        if self.uuid is None:
            cand = None
            if m and self.target_host and self.target_host in line:
                cand = m.group(1)
            p = PROCESSING_RX.search(line)
            if p:
                cand = cand or p.group(1)
            if cand:
                self.uuid = cand
                update(self.run_id, scan_uuid=cand)
                event(self.run_id, "info", "scan UUID on the scanner: {}".format(cand))
            else:
                if not m:
                    self.pending.append(line)
                    del self.pending[:-300]
                return
        if self.uuid not in line:
            return
        with self.lock:
            self.fh.write(line + "\n")
            lv = LEVEL_RX.search(line)
            lvl = {"FATAL": "error", "TRACE": "debug"}.get(lv.group(1), lv.group(1).lower()) if lv else "info"
            self.counts[lvl] += 1
            self.counts["total"] += 1
            minute = line[:16]  # 2026-11-11T00:01
            st_ = self.stats[minute]
            st_[lvl] += 1
            if "Auditing page starting" in line:
                st_["pages_audited"] += 1
            elif "plugin started" in line:
                st_["plugins_started"] += 1
            elif "added to the sitemap" in line:
                st_["urls_found"] += 1
            r = REQS_RX.search(line)
            if r:
                self.reqs[minute].append(float(r.group(1)))

    def flush(self):
        with self.lock:
            stats, reqs = dict(self.stats), dict(self.reqs)
            self.stats.clear()
            self.reqs.clear()
        if not stats:
            return
        with session_scope() as s:
            for minute, d in stats.items():
                try:
                    ts = datetime.datetime.strptime(minute, "%Y-%m-%dT%H:%M")
                except ValueError:
                    continue
                ts = ts.replace(tzinfo=datetime.datetime.now().astimezone().tzinfo)
                vals = {k: int(d.get(k, 0)) for k in ("debug", "info", "notice", "warn", "error",
                                                      "pages_audited", "plugins_started", "urls_found")}
                rq = reqs.get(minute)
                stmt = pg_insert(ScanLogStat).values(run_id=self.run_id, minute=ts,
                                                     req_per_sec=(sum(rq) / len(rq)) if rq else None, **vals)
                upd = {k: getattr(ScanLogStat, k) + stmt.excluded[k] for k in vals}
                if rq:
                    upd["req_per_sec"] = stmt.excluded.req_per_sec
                s.execute(stmt.on_conflict_do_update(index_elements=["run_id", "minute"], set_=upd))
        update(self.run_id, log_counts=dict(self.counts))

    def close(self):
        self.flush()
        self.fh.close()


def findings(sc, rid):
    """WAS findings of one scan result (vulnerability summary by plugin)."""
    q = {"type": "vuln", "sourceType": "individual", "scanID": str(rid), "view": "all",
         "query": {"tool": "sumid", "type": "vuln", "startOffset": 0, "endOffset": 1000, "filters": []}}
    res = sc.post("analysis", q)
    out = []
    for x in res.get("results", []):
        fam = x.get("family") or {}
        sev = x.get("severity") or {}
        out.append({"plugin_id": x.get("pluginID"), "name": x.get("name"), "severity": sev.get("name"),
                    "severity_id": int(sev.get("id") or 0), "family": fam.get("name") if isinstance(fam, dict) else fam,
                    "count": int(x.get("total") or x.get("hostTotal") or 0)})
    out.sort(key=lambda f: (-f["severity_id"], f["name"] or ""))
    return out


def start(params, client_ip=None, profile_id=None, trigger="manual"):
    url = (params.get("url") or "").strip()
    if not url or not params.get("policy"):
        raise Fatal("target URL and source policy are required")
    name = (params.get("name") or "").strip() or "{}{}".format(RUN_PREFIX, datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    with session_scope() as s:
        r = ScanRun(name=name, target_url=url, source_policy_id=str(params["policy"]), profile_id=profile_id, trigger=trigger,
                    sensor_id=params.get("sensor_id") or None,
                    families=params.get("families") or [], fast=bool(params.get("fast")),
                    debug_mode=params.get("debug") or "none", keep_objects=bool(params.get("keep", True)),
                    status="pending", summary={"set": params.get("set") or [], "repo": params.get("repo"),
                                                "zone": params.get("zone")})
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("scan_run_create", client_ip=client_ip, run_id=run_id, url=url, policy=params["policy"],
             families=params.get("families"), debug=params.get("debug"))
    ev = threading.Event()
    with _alock:
        _active[run_id] = ev
    t = threading.Thread(target=_run, args=(run_id, params, name, ev), name="run-%d" % run_id, daemon=True)
    t.start()
    return run_id


def _run(run_id, p, name, cancel_ev):
    set_output_sink(lambda lvl, m: event(run_id, lvl, m))
    created = {"policy": None, "scan": None}
    washost = None
    debug_on = False
    capture = None
    streamer = None
    rid = None
    t0 = time.time()
    try:
        update(run_id, status="preparing", started_at=now())
        sc = conn.sc()
        dbg = p.get("debug") or "none"
        # ssh is always needed: the run captures the scan's scanner log.
        washost = conn.was(p.get("sensor_id") or None)
        update(run_id, sensor_id=washost.sensor["id"])
        host = washost.ssh.test()
        event(run_id, "ok", "sensor {}: ssh to {} ({})".format(washost.sensor["name"], host, washost.ssh.method))
        if dbg in ("host", "both"):
            procs, _ = washost.active_scan_processes()
            if procs:
                raise Fatal("a scan is running on the scanner; switching host debug would restart the service and kill it")
        audit_shim = _AuditShim(run_id)
        policy_id = sc.resolve_policy(str(p["policy"]))
        fams = ",".join(p.get("families") or [])
        sets = parse_sets([x for x in (p.get("set") or []) if x])
        if dbg in ("sc", "both"):
            sets["was_debug_mode"] = "yes"
        if fams or p.get("fast") or sets:
            policy_id = derive_policy(sc, policy_id, name + "-policy", fams, bool(p.get("fast")), sets, audit_shim)
            created["policy"] = policy_id
        update(run_id, derived_policy_id=created["policy"])
        if dbg in ("host", "both"):
            washost.set_debug(True, audit=audit_shim)
            debug_on = True
        repo = pick_repo(sc, p.get("repo") or None)
        scan = create_was_scan(sc, name, policy_id, p["url"], repo, p.get("zone") or None,
                               "WAS Cockpit run {}".format(run_id))
        created["scan"] = str(scan.get("id"))
        update(run_id, sc_scan_id=created["scan"], status="launching")
        st.audit("was_scan_create", run_id=run_id, scan_id=created["scan"], policy_id=policy_id)
        target_host = re.sub(r"^\w+://", "", p["url"]).split("/")[0].split("#")[0]
        path = os.path.join(RUNS_DIR, "run-{}.log".format(run_id))
        capture = LogCapture(run_id, target_host, path)
        update(run_id, log_file=path)
        streamer = LogStreamer(washost, echo=False, on_line=capture.on_line)
        streamer.start()
        launch = sc.post("wasScan/{}/launch".format(created["scan"]), {})
        rid = str((launch.get("scanResult") or {}).get("id"))
        update(run_id, sc_result_id=rid, status="queued")
        st.audit("was_scan_launch", run_id=run_id, scan_result_id=rid)
        event(run_id, "ok", "scan launched: scan result {}".format(rid))
        _watch(run_id, sc, rid, capture, cancel_ev)
    except Fatal as exc:
        event(run_id, "error", exc.msg)
        update(run_id, status="failed", error=exc.msg)
    except (SCError, RuntimeError) as exc:
        event(run_id, "error", str(exc))
        update(run_id, status="failed", error=str(exc))
    except Exception as exc:  # pragma: no cover
        log.exception("run %s", run_id)
        event(run_id, "error", "{}: {}".format(type(exc).__name__, exc))
        update(run_id, status="failed", error=str(exc))
    finally:
        if streamer:
            streamer.stop()
        if capture:
            capture.close()
        if debug_on:
            _debug_off(run_id, washost)
        if not p.get("keep", True):
            _cleanup(run_id, created)
        update(run_id, finished_at=now(), summary=_merge_summary(run_id, {"duration_s": int(time.time() - t0)}))
        with _alock:
            _active.pop(run_id, None)
        set_output_sink(None)


def _watch(run_id, sc, rid, capture, cancel_ev):
    """Polls Security Center until the result is final (or the run is
    cancelled), flushing log stats; then stores the findings."""
    last_status = None
    last_flush = time.time()
    while not cancel_ev.is_set():
        try:
            cur = sc.scan_result(rid)
            status = str(cur.get("status") or "")
            if status != last_status:
                event(run_id, "info", "Security Center status: {}".format(status))
                last_status = status
                update(run_id, status=status.lower() or "running")
            if status.lower() in FINAL_STATES:
                update(run_id, summary=_merge_summary(run_id, {"sc_result": {
                    k: cur.get(k) for k in ("status", "errorDetails", "scanDuration", "startTime", "finishTime",
                                            "importStatus", "progress")}}))
                break
        except SCError as exc:
            event(run_id, "warn", "could not read the Security Center status: {}".format(exc))
        if time.time() - last_flush > 20:
            capture.flush()
            last_flush = time.time()
        cancel_ev.wait(15)
    if cancel_ev.is_set():
        event(run_id, "warn", "cancel requested; stopping the scan on Security Center")
        try:
            sc.post("scanResult/{}/stop".format(rid), {})
            st.audit("scan_result_stop", run_id=run_id, scan_result_id=rid)
        except SCError as exc:
            event(run_id, "error", "could not stop the scan: {}".format(exc))
        update(run_id, status="cancelled")
        return
    time.sleep(5)  # let the last scanner lines arrive
    try:
        f = findings(sc, rid)
        update(run_id, findings=f)
        event(run_id, "ok", "{} findings loaded".format(len(f)))
    except SCError as exc:
        event(run_id, "warn", "could not load the findings: {}".format(exc))


def _debug_off(run_id, washost, tries=12):
    """Switch the scanner back to info once no scan is running (the restart
    would kill a running scan)."""
    for i in range(tries):
        try:
            washost.set_debug(False, audit=_AuditShim(run_id))
            return True
        except RuntimeError as exc:
            if i == tries - 1:
                event(run_id, "error", "DEBUG IS STILL ON, switch it off on the Dashboard: {}".format(exc))
                return False
            time.sleep(20)
        except Exception as exc:
            event(run_id, "error", "DEBUG IS STILL ON, switch it off on the Dashboard: {}".format(exc))
            return False


def resume_orphans():
    """Runs left active by a previous api process continue: log capture, SC
    polling, findings, debug off and cleanup."""
    with session_scope() as s:
        ids = [r.id for r in s.execute(select(ScanRun).where(ScanRun.status.in_(
            ["pending", "preparing", "launching", "running", "queued", "interrupted"]),
            ScanRun.finished_at.is_(None))).scalars()]
    for rid in ids:
        ev = threading.Event()
        with _alock:
            _active[rid] = ev
        threading.Thread(target=_resume, args=(rid, ev), name="resume-%d" % rid, daemon=True).start()
    return ids


def _resume(run_id, cancel_ev):
    set_output_sink(lambda lvl, m: event(run_id, lvl, m))
    streamer = capture = washost = None
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        rid, uuid, dbg, keep, sensor_id = r.sc_result_id, r.scan_uuid, r.debug_mode, r.keep_objects, r.sensor_id
        created = {"scan": r.sc_scan_id, "policy": r.derived_policy_id}
        path, url, counts, started = r.log_file, r.target_url, dict(r.log_counts or {}), r.started_at
        if r.status == "interrupted":
            r.status, r.error = "running", None
    try:
        if not rid:
            raise Fatal("the api restarted before the scan was launched")
        event(run_id, "info", "api restarted; resuming log capture and status polling")
        sc = conn.sc()
        washost = conn.was(sensor_id)
        target_host = re.sub(r"^\w+://", "", url).split("/")[0].split("#")[0]
        path = path or os.path.join(RUNS_DIR, "run-{}.log".format(run_id))
        capture = LogCapture(run_id, target_host, path)
        capture.uuid = uuid
        capture.counts.update({k: int(v) for k, v in counts.items()})
        streamer = LogStreamer(washost, echo=False, on_line=capture.on_line)
        streamer.start()
        _watch(run_id, sc, rid, capture, cancel_ev)
    except Fatal as exc:
        event(run_id, "error", exc.msg)
        update(run_id, status="failed", error=exc.msg)
    except Exception as exc:
        log.exception("resume %s", run_id)
        event(run_id, "error", str(exc))
        update(run_id, status="failed", error=str(exc))
    finally:
        if streamer:
            streamer.stop()
        if capture:
            capture.close()
        if washost and dbg in ("host", "both"):
            _debug_off(run_id, washost)
        if not keep:
            _cleanup(run_id, created)
        dur = int((now() - started).total_seconds()) if started else None
        update(run_id, finished_at=now(), summary=_merge_summary(run_id, {"duration_s": dur}))
        with _alock:
            _active.pop(run_id, None)
        set_output_sink(None)


def _cleanup(run_id, created):
    try:
        sc = conn.sc()
    except Fatal:
        return
    for kind, path in (("scan", "wasScan"), ("policy", "policy")):
        if created.get(kind):
            try:
                sc.delete("{}/{}".format(path, created[kind]))
                event(run_id, "info", "removed temporary {} {}".format(kind, created[kind]))
            except SCError as exc:
                event(run_id, "warn", "could not remove {} {}: {}".format(kind, created[kind], exc))


def _merge_summary(run_id, extra):
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        d = dict(r.summary or {})
    d.update(extra)
    return d


class _AuditShim(object):
    """wastools expects an Audit-like object with write(action, **fields)."""

    def __init__(self, run_id):
        self.run_id = run_id

    def write(self, action, **fields):
        st.audit(action, run_id=self.run_id, **json.loads(json.dumps(fields, default=str)))
