"""WAS Troubleshooter API (FastAPI). Served under /api by nginx."""
import datetime
import json
import logging
import os
import queue
import re
import secrets
import shlex
from logging.handlers import RotatingFileHandler

from fastapi import APIRouter, Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import delete, desc, func, select

from app import ai, conn, fuzz, profiles, runs, sensors
from harness import analysis as hanalysis, loader as hloader, sast
from app import settings as st
from wastools.core import (IMPORTANT_PREFS, Fatal, LogStreamer, SCError, prefs_dict, ts_human)
from wastools.monitor import collect
from wastools.ops import current_families
from wtdb.database import session_scope
from wtdb.models import (AuditLog, ChatMessage, FuzzRun, ScanFolder, ScanProfile, SastEvent, SastFinding, SastFunction, SastRun, ScanLogStat, ScanRun,
                         ScanRunEvent)


def _setup_logging():
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    handlers = [logging.StreamHandler()]
    path = os.environ.get("LOG_FILE")
    if path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handlers.append(RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5))
    logging.basicConfig(level=level, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")


_setup_logging()
log = logging.getLogger("api")
app = FastAPI(title="WAS Troubleshooter API", docs_url="/api/docs", openapi_url="/api/openapi.json")
router = APIRouter(prefix="/api")


try:
    sensors.seed_from_env()
    fuzz.ensure_builtin()
    fuzz.mark_orphans()
    runs.resume_orphans()
    sast.mark_orphans()
    profiles.start_scheduler()
except Exception:  # database not reachable yet: the next start retries
    log.exception("orphan runs")


@app.exception_handler(Fatal)
def _fatal(_req, exc):
    return JSONResponse({"detail": exc.msg}, status_code=400)


@app.exception_handler(SCError)
def _scerr(_req, exc):
    return JSONResponse({"detail": "Security Center: {}".format(exc)}, status_code=502)


@app.exception_handler(RuntimeError)
def _rterr(_req, exc):
    return JSONResponse({"detail": str(exc)}, status_code=502)


def ip(req: Request):
    return (req.headers.get("x-forwarded-for") or (req.client.host if req.client else "")).split(",")[0].strip()


def sensor_of(req: Request, explicit=None):
    """Selected sensor: explicit value, ?sensor=, or the X-Sensor header (set by the UI)."""
    v = explicit or req.query_params.get("sensor") or req.headers.get("x-sensor")
    try:
        return int(v) if v not in (None, "", "default") else None
    except ValueError:
        return None


def iso(dt):
    return dt.isoformat() if dt else None


# ------------------------------------------------------------------ health
@router.get("/health")
def health():
    with session_scope() as s:
        s.execute(select(func.now()))
    return {"ok": True, "time": datetime.datetime.now().isoformat()}


# ---------------------------------------------------------------- settings
@router.get("/settings")
def get_settings():
    return {"settings": st.get_all(), "sources": st.sources(), "secret_mask": st.SECRET_MASK,
            "default_prompt": st.AI_DEFAULT_PROMPT,
            "env_names": {k: v[2] for k, v in st.FIELDS.items()}}


@router.post("/settings/reset")
def reset_settings(req: Request, body: dict = Body(...)):
    keys = [k for k in body.get("keys") or [] if k in st.FIELDS]
    st.reset(keys, client_ip=ip(req))
    conn.drop_was()
    return {"reset": keys, "settings": st.get_all(), "sources": st.sources()}


@router.put("/settings")
def put_settings(req: Request, values: dict = Body(...)):
    changed = st.save(values, client_ip=ip(req))
    conn.drop_was()
    return {"saved": changed, "settings": st.get_all(), "sources": st.sources()}


@router.post("/settings/test/{what}")
def test_settings(what: str, values: dict = Body(default={})):
    """Tests the stored settings; unsaved form values can be passed and win."""
    if values and what != "ssh":
        raise HTTPException(400, "save first, then test")
    if what == "sc":
        sc = conn.sc()
        sysinfo = sc.get("system") or {}
        out = {"ok": True, "version": sysinfo.get("version"), "build": sysinfo.get("buildID")}
        pols = sc.policies()
        out["was_policies"] = len(pols)
        scanners = sc.was_scanners()
        out["was_scanners"] = None if scanners is None else [
            {"name": x.get("name"), "status": x.get("status")} for x in scanners]
        return out
    if what == "sc-ssh":
        h = conn.sc_host()
        host = h.test()
        rc, out, _ = h.run("rpm -q SecurityCenter 2>/dev/null || true")
        return {"ok": True, "host": host, "method": h.method, "package": out.strip(),
                "sudo": h.sudo("true", check=False)[0] == 0}
    if what == "ssh":
        conn.drop_was()
        w = conn.was(values.get("sensor") if values else None)
        host = w.ssh.test()
        rc, out, _ = w.ssh.run("test -r {} && echo ok || echo no".format(w.log))
        return {"ok": True, "host": host, "method": w.ssh.method, "debug": w.debug_status(),
                "log_readable": out.strip() == "ok", "sudo": w.ssh.sudo("true", check=False)[0] == 0}
    if what == "ai":
        c = st.get_all()
        return ai.test(c["ai.ollama_url"], c["ai.model"])
    raise HTTPException(404, "bilinmeyen test")


# --------------------------------------------------------------- dashboard
@router.get("/dashboard")
def dashboard(req: Request):
    errors = []
    sc = washost = None
    sid = sensor_of(req)
    try:
        sc = conn.sc()
    except Fatal as exc:
        errors.append(exc.msg)
    try:
        washost = conn.was(sid)
    except Fatal as exc:
        errors.append(exc.msg)
    data = collect(None, sc, washost)
    data["sensor"] = getattr(washost, "sensor", None)
    data["errors"] = errors + data["errors"]
    if washost:
        try:
            data["debug"] = washost.debug_status()
        except Exception as exc:
            data["errors"].append("debug durumu: {}".format(exc))
    for r in data["sc"]:
        r.pop("progress", None)
    with session_scope() as s:
        total = s.scalar(select(func.count(ScanRun.id)))
        by_status = dict(s.execute(select(ScanRun.status, func.count()).group_by(ScanRun.status)).all())
        recent = [_run_row(r) for r in s.execute(select(ScanRun).order_by(desc(ScanRun.id)).limit(8)).scalars()]
        daily = s.execute(select(func.date_trunc("day", ScanRun.created_at).label("d"), func.count())
                          .where(ScanRun.created_at > func.now() - datetime.timedelta(days=14))
                          .group_by("d").order_by("d")).all()
    data["runs"] = {"total": total, "by_status": by_status, "recent": recent,
                    "daily": [{"day": d.date().isoformat(), "count": c} for d, c in daily]}
    return data


# ------------------------------------------------------------- SC reference
@router.get("/sc/policies")
def sc_policies(detail: bool = False):
    sc = conn.sc()
    out = []
    for p in sc.policies():
        row = {"id": p.get("id"), "name": p.get("name"), "description": p.get("description") or "",
               "modified": ts_human(p.get("modifiedTime"))}
        if detail:
            try:
                pol = sc.policy(p["id"], fields="id,families,preferences")
                fams, _ = current_families(sc, p["id"])
                prefs = prefs_dict(pol)
                row["families"] = fams or []
                row["prefs"] = {k: prefs.get(k) for k in IMPORTANT_PREFS if k in prefs}
            except SCError as exc:
                row["error"] = str(exc)
        out.append(row)
    return {"policies": out}


@router.get("/sc/policies/{pid}")
def sc_policy(pid: str):
    sc = conn.sc()
    pid = sc.resolve_policy(pid)
    pol = sc.policy(pid)
    fams, src = current_families(sc, pid)
    prefs = prefs_dict(pol)
    return {"id": pid, "name": pol.get("name"), "families": fams, "families_source": src,
            "prefs": {k: prefs.get(k) for k in IMPORTANT_PREFS if k in prefs},
            "all_families": [{"id": i, "name": n} for i, n, _ in sc.was_families()]}


@router.get("/sc/families")
def sc_families():
    return {"families": [{"id": i, "name": n} for i, n, _ in conn.sc().was_families()]}


@router.get("/sc/repos")
def sc_repos():
    return {"repos": conn.sc().repositories()}


@router.get("/sc/results")
def sc_results(days: int = 14):
    rows = conn.sc().scan_results_recent(since_seconds=days * 86400)
    out = [r for r in rows if str(r.get("resultType", "")).lower() == "was" or "was" in str(r.get("resultType", ""))]
    if not out:
        out = rows
    out.sort(key=lambda r: -int(r.get("id") or 0))
    return {"results": out}


@router.get("/sc/results/{rid}")
def sc_result(rid: str):
    sc = conn.sc()
    return {"result": sc.scan_result(rid), "findings": runs.findings(sc, rid)}


@router.post("/sc/results/{rid}/stop")
def sc_result_stop(rid: str, req: Request):
    conn.sc().post("scanResult/{}/stop".format(rid), {})
    st.audit("scan_result_stop", client_ip=ip(req), scan_result_id=rid)
    return {"stopped": rid}


# --------------------------------------------------------------- scan runs
def _run_row(r):
    sev = {}
    for f in r.findings or []:
        sev[f.get("severity") or "?"] = sev.get(f.get("severity") or "?", 0) + 1
    return {"id": r.id, "name": r.name, "target_url": r.target_url, "status": r.status,
            "profile_id": r.profile_id, "trigger": r.trigger, "sensor_id": r.sensor_id,
            "source_policy_id": r.source_policy_id, "derived_policy_id": r.derived_policy_id,
            "families": r.families, "fast": r.fast, "debug_mode": r.debug_mode, "keep": r.keep_objects,
            "sc_scan_id": r.sc_scan_id, "sc_result_id": r.sc_result_id, "scan_uuid": r.scan_uuid,
            "error": r.error, "log_counts": r.log_counts, "findings_count": len(r.findings or []),
            "severity": sev, "created_at": iso(r.created_at), "started_at": iso(r.started_at),
            "finished_at": iso(r.finished_at), "duration_s": (r.summary or {}).get("duration_s"),
            "active": runs.is_active(r.id)}


@router.post("/scans")
def scan_start(req: Request, params: dict = Body(...)):
    """Ad-hoc run without a profile (DevOps / CLI)."""
    params.setdefault("sensor_id", sensor_of(req))
    return {"run_id": runs.start(params, client_ip=ip(req), trigger=params.get("trigger") or "api")}


# ------------------------------------------------------- folders / profiles
@router.get("/folders")
def folders_list():
    return profiles.folder_tree()


@router.post("/folders")
def folder_create(req: Request, body: dict = Body(...)):
    name = str(body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "folder name is required")
    with session_scope() as s:
        f = ScanFolder(name=name[:200], parent_id=body.get("parent_id") or None)
        s.add(f)
        s.flush()
        fid = f.id
    st.audit("scan_folder_create", client_ip=ip(req), folder_id=fid, name=name)
    return {"id": fid}


@router.put("/folders/{fid}")
def folder_update(fid: int, req: Request, body: dict = Body(...)):
    with session_scope() as s:
        f = s.get(ScanFolder, fid)
        if not f:
            raise HTTPException(404, "folder not found")
        if "name" in body and str(body["name"]).strip():
            f.name = str(body["name"]).strip()[:200]
        if "parent_id" in body:
            pid = body["parent_id"] or None
            node = pid
            while node:  # refuse cycles
                if node == fid:
                    raise HTTPException(400, "a folder cannot be moved into itself")
                parent = s.get(ScanFolder, node)
                node = parent.parent_id if parent else None
            f.parent_id = pid
    st.audit("scan_folder_update", client_ip=ip(req), folder_id=fid)
    return {"updated": fid}


@router.delete("/folders/{fid}")
def folder_delete(fid: int, req: Request):
    """Deletes the folder and its sub folders; their profiles move to 'Unfiled'."""
    with session_scope() as s:
        if not s.get(ScanFolder, fid):
            raise HTTPException(404, "folder not found")
        s.execute(delete(ScanFolder).where(ScanFolder.id == fid))
    st.audit("scan_folder_delete", client_ip=ip(req), folder_id=fid)
    return {"deleted": fid}


def _profile_data(body):
    d = {k: body[k] for k in profiles.PROFILE_FIELDS if k in body}
    d["name"] = str(d.get("name") or "").strip()[:200]
    d["target_url"] = str(d.get("target_url") or "").strip()
    for k in ("repo_id", "zone_id", "folder_id", "sensor_id"):
        if k in d:
            d[k] = int(d[k]) if d[k] not in (None, "") else None
    return d


@router.get("/profiles")
def profiles_list(folder: str = "all"):
    with session_scope() as s:
        q = select(ScanProfile).order_by(ScanProfile.name)
        if folder == "unfiled":
            q = q.where(ScanProfile.folder_id.is_(None))
        elif folder not in ("all", ""):
            q = q.where(ScanProfile.folder_id == int(folder))
        rows = list(s.execute(q).scalars())
        last = profiles.last_runs([p.last_run_id for p in rows if p.last_run_id])
        return {"profiles": [profiles.row(p, last.get(p.last_run_id)) for p in rows]}


@router.get("/profiles/{pid}")
def profile_get(pid: int):
    with session_scope() as s:
        p = s.get(ScanProfile, pid)
        if not p:
            raise HTTPException(404, "profile not found")
        out = profiles.row(p, profiles.last_runs([p.last_run_id]).get(p.last_run_id) if p.last_run_id else None)
        out["runs"] = [_run_row(r) for r in s.execute(select(ScanRun).where(ScanRun.profile_id == pid)
                                                       .order_by(desc(ScanRun.id)).limit(20)).scalars()]
    return out


def _save_profile(pid, body, client_ip):
    d = _profile_data(body)
    try:
        profiles.validate(d)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    with session_scope() as s:
        p = s.get(ScanProfile, pid) if pid else ScanProfile()
        if pid and not p:
            raise HTTPException(404, "profile not found")
        for k, v in d.items():
            setattr(p, k, v)
        p.next_run_at = profiles.next_run(d.get("schedule")) if d.get("enabled", True) else None
        if not pid:
            s.add(p)
        s.flush()
        pid = p.id
    st.audit("scan_profile_save", client_ip=client_ip, profile_id=pid, name=d["name"], schedule=d.get("schedule"))
    run_id = None
    if body.get("run_now"):
        try:
            run_id = profiles.run_now(pid, trigger="manual", client_ip=client_ip)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
    return {"id": pid, "run_id": run_id}


@router.post("/profiles")
def profile_create(req: Request, body: dict = Body(...)):
    return _save_profile(None, body, ip(req))


@router.put("/profiles/{pid}")
def profile_update(pid: int, req: Request, body: dict = Body(...)):
    return _save_profile(pid, body, ip(req))


@router.post("/profiles/{pid}/run")
def profile_run(pid: int, req: Request):
    try:
        return {"run_id": profiles.run_now(pid, trigger="manual", client_ip=ip(req))}
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.post("/profiles/{pid}/toggle")
def profile_toggle(pid: int, req: Request):
    with session_scope() as s:
        p = s.get(ScanProfile, pid)
        if not p:
            raise HTTPException(404, "profile not found")
        p.enabled = not p.enabled
        p.next_run_at = profiles.next_run(p.schedule) if p.enabled else None
        state = p.enabled
    st.audit("scan_profile_toggle", client_ip=ip(req), profile_id=pid, enabled=state)
    return {"enabled": state}


@router.post("/profiles/{pid}/copy")
def profile_copy(pid: int, req: Request):
    with session_scope() as s:
        p = s.get(ScanProfile, pid)
        if not p:
            raise HTTPException(404, "profile not found")
        c = ScanProfile(**{k: getattr(p, k) for k in profiles.PROFILE_FIELDS})
        c.name = (p.name + " (copy)")[:200]
        c.enabled = False
        s.add(c)
        s.flush()
        cid = c.id
    st.audit("scan_profile_copy", client_ip=ip(req), profile_id=pid, copy_id=cid)
    return {"id": cid}


@router.delete("/profiles/{pid}")
def profile_delete(pid: int, req: Request):
    with session_scope() as s:
        s.execute(delete(ScanProfile).where(ScanProfile.id == pid))
    st.audit("scan_profile_delete", client_ip=ip(req), profile_id=pid)
    return {"deleted": pid}


@router.get("/scans")
def scan_list(limit: int = 100):
    with session_scope() as s:
        return {"runs": [_run_row(r) for r in
                         s.execute(select(ScanRun).order_by(desc(ScanRun.id)).limit(limit)).scalars()]}


@router.get("/scans/{run_id}")
def scan_get(run_id: int):
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        if not r:
            raise HTTPException(404, "kayıt yok")
        out = _run_row(r)
        out["findings"] = r.findings
        out["summary"] = r.summary
        out["events"] = [{"ts": iso(e.ts), "level": e.level, "message": e.message} for e in s.execute(
            select(ScanRunEvent).where(ScanRunEvent.run_id == run_id).order_by(ScanRunEvent.id)).scalars()]
        out["stats"] = [{"minute": iso(x.minute), "debug": x.debug, "info": x.info, "notice": x.notice,
                         "warn": x.warn, "error": x.error, "pages_audited": x.pages_audited,
                         "plugins_started": x.plugins_started, "urls_found": x.urls_found,
                         "req_per_sec": float(x.req_per_sec) if x.req_per_sec is not None else None}
                        for x in s.execute(select(ScanLogStat).where(ScanLogStat.run_id == run_id)
                                           .order_by(ScanLogStat.minute)).scalars()]
    return out


@router.post("/scans/{run_id}/cancel")
def scan_cancel(run_id: int, req: Request):
    ok = runs.cancel(run_id)
    st.audit("scan_run_cancel", client_ip=ip(req), run_id=run_id, active=ok)
    return {"cancelled": ok}


@router.post("/scans/{run_id}/analyze")
def scan_analyze(run_id: int, req: Request, body: dict = Body(default={})):
    return hanalysis.start(run_id, client_ip=ip(req), fetch_attachments=body.get("attachments", True))


@router.get("/scans/{run_id}/analysis")
def scan_analysis(run_id: int):
    job = hanalysis.get_job(run_id)
    if job:
        return job
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        summ = (r.summary or {}) if r else {}
    if summ.get("analysis"):
        return {"run_id": run_id, "state": "done", "analysis": summ["analysis"],
                "report_url": "/api/scans/{}/report".format(run_id)}
    return {"run_id": run_id, "state": "none"}


@router.get("/scans/{run_id}/report")
def scan_report(run_id: int):
    path = hanalysis.report_path(run_id)
    if not path or not os.path.isfile(path):
        raise HTTPException(404, "no report yet; run the AI analysis first")
    with open(path, encoding="utf-8") as fh:
        return Response(content=fh.read(), media_type="text/html")


@router.get("/scans/{run_id}/attachment/{att_id}")
def scan_attachment(run_id: int, att_id: str):
    from app import wasfindings
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        rid = r.sc_result_id if r else None
    if not rid:
        raise HTTPException(404, "no Security Center result")
    ctype, data = wasfindings.attachment(conn.sc(), rid, att_id)
    return Response(content=data, media_type=ctype)


@router.post("/scans/{run_id}/refresh-findings")
def scan_refresh_findings(run_id: int):
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        if not r or not r.sc_result_id:
            raise HTTPException(404, "SC sonucu yok")
        rid = r.sc_result_id
    f = runs.findings(conn.sc(), rid)
    runs.update(run_id, findings=f)
    return {"findings": f}


@router.delete("/scans/{run_id}")
def scan_delete(run_id: int, req: Request):
    if runs.is_active(run_id):
        raise HTTPException(409, "çalışan kayıt silinemez; önce iptal et")
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        path = r.log_file if r else None
        s.execute(delete(ScanRun).where(ScanRun.id == run_id))
    if path and os.path.isfile(path):
        os.remove(path)
    st.audit("scan_run_delete", client_ip=ip(req), run_id=run_id)
    return {"deleted": run_id}


@router.get("/scans/{run_id}/log")
def scan_log(run_id: int, tail: int = 2000, grep: str = "", level: str = ""):
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        if not r or not r.log_file:
            raise HTTPException(404, "log yok")
        path = r.log_file
    if not os.path.isfile(path):
        return {"lines": [], "total": 0}
    rx = re.compile(grep) if grep else None
    lv = set(x.strip().upper() for x in level.split(",") if x.strip())
    out, total = [], 0
    with open(path, errors="replace") as fh:
        for line in fh:
            total += 1
            if rx and not rx.search(line):
                continue
            if lv and not any("[{}]".format(x) in line for x in lv):
                continue
            out.append(line.rstrip("\n"))
            if len(out) > tail:
                del out[0]
    return {"lines": out, "total": total}


@router.get("/scans/{run_id}/log/download")
def scan_log_download(run_id: int):
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        path = r.log_file if r else None
    if not path or not os.path.isfile(path):
        raise HTTPException(404, "log yok")

    def gen():
        with open(path, "rb") as fh:
            while True:
                b = fh.read(65536)
                if not b:
                    break
                yield b
    return StreamingResponse(gen(), media_type="text/plain", headers={
        "Content-Disposition": 'attachment; filename="was-run-{}.log"'.format(run_id)})


# --------------------------------------------------------- scanner host ops
@router.post("/scanner/reach")
def scanner_reach(req: Request, body: dict = Body(...)):
    """Can the WAS scanner reach the target? Runs curl on the scanner host."""
    url = str(body.get("url") or "").strip()
    if not re.match(r"^https?://[\w.:\[\]-]+(/\S*)?$", url):
        raise HTTPException(400, "URL must start with http:// or https://")
    w = conn.was(sensor_of(req, body.get("sensor")))
    rc, out, er = w.ssh.run("curl -k -s -o /dev/null -m 10 -w '%{http_code} %{time_total} %{remote_ip}' " + shlex.quote(url),
                            timeout=30)
    parts = out.strip().split()
    code = parts[0] if parts else "000"
    return {"reachable": code not in ("000", ""), "http_code": code,
            "seconds": float(parts[1]) if len(parts) > 1 else None, "ip": parts[2] if len(parts) > 2 else None,
            "from": w.ssh.host, "error": (er or "").strip()[:200] if code == "000" else ""}


@router.post("/scanner/debug")
def scanner_debug(req: Request, body: dict = Body(...)):
    on = bool(body.get("on"))
    w = conn.was(sensor_of(req, body.get("sensor")))
    w.set_debug(on, audit=_Audit(ip(req)))
    return {"debug": w.debug_status()}


class _Audit(object):
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def write(self, action, **fields):
        st.audit(action, client_ip=self.client_ip, **json.loads(json.dumps(fields, default=str)))


@router.get("/logs/stream")
def logs_stream(req: Request, uuid: str = "", grep: str = "", backlog: int = Query(200, ge=0, le=5000)):
    w = conn.was(sensor_of(req))
    try:
        rx = re.compile(grep) if grep else None
    except re.error as exc:
        raise HTTPException(400, "regex: {}".format(exc))
    tok = "scanUuid=" + uuid if uuid else None

    def flt(line):
        if tok and tok not in line:
            return False
        return bool(rx.search(line)) if rx else True

    q = queue.Queue(maxsize=20000)

    def push(line):
        try:
            q.put_nowait(line)
        except queue.Full:
            pass
    streamer = LogStreamer(w, line_filter=flt if (tok or rx) else None, backlog=backlog, echo=False, on_line=push)

    def gen():
        streamer.start()
        try:
            yield ": connected\n\n"
            while True:
                try:
                    line = q.get(timeout=15)
                except queue.Empty:
                    yield ": ping\n\n"
                    continue
                batch = [line]
                while len(batch) < 500:
                    try:
                        batch.append(q.get_nowait())
                    except queue.Empty:
                        break
                yield "".join("data: " + l.replace("\r", "") + "\n\n" for l in batch)
        finally:
            streamer.stop()
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------- AI
@router.get("/ai/models")
def ai_models():
    return {"models": ai.models(st.get_all()["ai.ollama_url"])}


@router.get("/ai/history")
def ai_history(session: str):
    with session_scope() as s:
        rows = s.execute(select(ChatMessage).where(ChatMessage.session == session).order_by(ChatMessage.id)).scalars()
        return {"messages": [{"role": m.role, "content": m.content, "stats": m.stats} for m in rows]}


@router.delete("/ai/history")
def ai_history_clear(session: str):
    with session_scope() as s:
        s.execute(delete(ChatMessage).where(ChatMessage.session == session))
    return {"cleared": session}


@router.post("/ai/chat")
def ai_chat(body: dict = Body(...)):
    c = st.get_all()
    model = c["ai.model"]
    if not c["ai.ollama_url"] or not model:
        raise HTTPException(400, "Ollama adresi ve model tanımlı değil (Settings > AI)")
    session = body.get("session") or secrets.token_hex(8)
    text = (body.get("message") or "").strip()
    if not text:
        raise HTTPException(400, "mesaj boş")
    with session_scope() as s:
        s.add(ChatMessage(session=session, role="user", content=text, model=model))
        hist = [{"role": m.role, "content": m.content} for m in s.execute(
            select(ChatMessage).where(ChatMessage.session == session).order_by(ChatMessage.id)).scalars()]

    def gen():
        answer, stats = [], None
        try:
            for d in ai.chat_stream(c["ai.ollama_url"], model, c["ai.system_prompt"], hist,
                                    temperature=c["ai.temperature"] or 0.2, num_ctx=c["ai.num_ctx"] or 16384):
                if d.get("delta"):
                    answer.append(d["delta"])
                if d.get("done"):
                    stats = d.get("stats")
                yield json.dumps(d) + "\n"
        except Fatal as exc:
            yield json.dumps({"error": exc.msg}) + "\n"
        finally:
            if answer:
                with session_scope() as s:
                    s.add(ChatMessage(session=session, role="assistant", content="".join(answer), model=model,
                                      stats=stats))
    return StreamingResponse(gen(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "X-Session": session})


# -------------------------------------------------------------------- SAST
def _sast_row(r):
    return {"id": r.id, "repo_url": r.repo_url, "ref": r.ref, "commit": r.commit, "status": r.status, "model": r.model,
            "options": r.options, "stats": r.stats, "error": r.error, "created_at": iso(r.created_at),
            "started_at": iso(r.started_at), "finished_at": iso(r.finished_at), "active": sast.is_active(r.id)}


@router.get("/harness")
def harness_catalog():
    return hloader.catalog()


@router.post("/sast")
def sast_start(req: Request, params: dict = Body(...)):
    try:
        return {"run_id": sast.start(params, client_ip=ip(req))}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("/sast")
def sast_list(limit: int = 100):
    with session_scope() as s:
        return {"runs": [_sast_row(r) for r in s.execute(select(SastRun).order_by(desc(SastRun.id)).limit(limit)).scalars()]}


@router.get("/sast/{run_id}")
def sast_get(run_id: int, functions: str = "candidates"):
    with session_scope() as s:
        r = s.get(SastRun, run_id)
        if not r:
            raise HTTPException(404, "run not found")
        out = _sast_row(r)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        out["findings"] = sorted([{
            "id": f.id, "file": f.file, "line": f.line, "function": f.function, "parameter": f.parameter, "cwe": f.cwe,
            "title": f.title, "severity": f.severity, "confidence": f.confidence, "description": f.description,
            "evidence": f.evidence, "recommendation": f.recommendation}
            for f in s.execute(select(SastFinding).where(SastFinding.run_id == run_id)).scalars()],
            key=lambda x: (sev_order.get(x["severity"], 9), x["file"], x["line"] or 0))
        q = select(SastFunction).where(SastFunction.run_id == run_id)
        if functions == "candidates":
            q = q.where(SastFunction.status.in_(["candidate", "analysed", "error"]))
        out["functions"] = [{
            "id": f.id, "file": f.file, "name": f.name, "language": f.language, "start_line": f.start_line,
            "end_line": f.end_line, "params": f.params, "sinks": f.sinks, "route": f.route, "priority": f.priority,
            "status": f.status, "verdict": f.verdict, "summary": f.summary, "agent_stats": f.agent_stats}
            for f in s.execute(q.order_by(desc(SastFunction.priority), SastFunction.id).limit(2000)).scalars()]
        out["events"] = [{"ts": iso(e.ts), "level": e.level, "message": e.message} for e in s.execute(
            select(SastEvent).where(SastEvent.run_id == run_id).order_by(SastEvent.id)).scalars()]
    return out


@router.post("/sast/{run_id}/cancel")
def sast_cancel(run_id: int, req: Request):
    ok = sast.cancel(run_id)
    st.audit("sast_run_cancel", client_ip=ip(req), run_id=run_id, active=ok)
    return {"cancelled": ok}


@router.delete("/sast/{run_id}")
def sast_delete(run_id: int, req: Request):
    if sast.is_active(run_id):
        raise HTTPException(409, "cancel the running run first")
    with session_scope() as s:
        s.execute(delete(SastRun).where(SastRun.id == run_id))
    st.audit("sast_run_delete", client_ip=ip(req), run_id=run_id)
    return {"deleted": run_id}


# ----------------------------------------------------------------- sensors
@router.get("/sensors")
def sensors_list():
    return {"sensors": sensors.all_rows(), "secret_mask": st.SECRET_MASK}


@router.get("/sensors/{sid}")
def sensor_get(sid: int):
    s_ = sensors.get(sid)
    if not s_ or s_["id"] != sid:
        raise HTTPException(404, "sensor not found")
    return s_


@router.post("/sensors")
def sensor_create(req: Request, body: dict = Body(...)):
    try:
        sid = sensors.save(None, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    st.audit("sensor_create", client_ip=ip(req), sensor_id=sid, name=body.get("name"))
    return {"id": sid}


@router.put("/sensors/{sid}")
def sensor_update(sid: int, req: Request, body: dict = Body(...)):
    try:
        sensors.save(sid, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    conn.drop_was(sid)
    st.audit("sensor_update", client_ip=ip(req), sensor_id=sid)
    return {"id": sid}


@router.post("/sensors/{sid}/default")
def sensor_default(sid: int, req: Request):
    sensors.make_default(sid)
    st.audit("sensor_default", client_ip=ip(req), sensor_id=sid)
    return {"default": sid}


@router.delete("/sensors/{sid}")
def sensor_delete(sid: int, req: Request):
    sensors.delete(sid)
    conn.drop_was(sid)
    st.audit("sensor_delete", client_ip=ip(req), sensor_id=sid)
    return {"deleted": sid}


@router.post("/sensors/{sid}/test")
def sensor_test(sid: int):
    conn.drop_was(sid)
    w = conn.was(sid)
    host = w.ssh.test()
    rc, out, _ = w.ssh.run("test -r {} && echo ok || echo no; rpm -q nessus-was-scanner 2>/dev/null || true".format(
        shlex.quote(w.log)))
    lines = out.strip().splitlines()
    return {"ok": True, "host": host, "method": w.ssh.method, "debug": w.debug_status(),
            "log_readable": bool(lines) and lines[0] == "ok", "package": lines[1] if len(lines) > 1 else "",
            "sudo": w.ssh.sudo("true", check=False)[0] == 0}


# ------------------------------------------------ Hidden Path Discovery (ffuf)
@router.get("/fuzz/wordlists")
def fuzz_wordlists():
    return {"wordlists": fuzz.wordlists()}


@router.post("/fuzz/wordlists")
def fuzz_wordlist_add(req: Request, body: dict = Body(...)):
    try:
        out = fuzz.save_wordlist(str(body.get("name") or "").strip(), body.get("content") or "")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    st.audit("fuzz_wordlist_add", client_ip=ip(req), name=out["name"], words=out["words"])
    return out


@router.delete("/fuzz/wordlists/{name}")
def fuzz_wordlist_del(name: str, req: Request):
    try:
        fuzz.delete_wordlist(name)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"deleted": name}


@router.get("/fuzz")
def fuzz_list(limit: int = 50):
    with session_scope() as s:
        return {"runs": [fuzz.row(r) for r in s.execute(select(FuzzRun).order_by(desc(FuzzRun.id)).limit(limit)).scalars()]}


@router.post("/fuzz")
def fuzz_start(req: Request, params: dict = Body(...)):
    try:
        return {"run_id": fuzz.start(params, client_ip=ip(req))}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("/fuzz/{run_id}")
def fuzz_get(run_id: int):
    with session_scope() as s:
        r = s.get(FuzzRun, run_id)
        if not r:
            raise HTTPException(404, "fuzz run not found")
        return fuzz.row(r)


@router.post("/fuzz/{run_id}/cancel")
def fuzz_cancel(run_id: int, req: Request):
    ok = fuzz.cancel(run_id)
    st.audit("fuzz_run_cancel", client_ip=ip(req), run_id=run_id, active=ok)
    return {"cancelled": ok}


@router.delete("/fuzz/{run_id}")
def fuzz_delete(run_id: int, req: Request):
    if fuzz.is_active(run_id):
        raise HTTPException(409, "cancel the running scan first")
    with session_scope() as s:
        s.execute(delete(FuzzRun).where(FuzzRun.id == run_id))
    return {"deleted": run_id}


# ------------------------------------------------------------------- audit
@router.get("/audit")
def audit_list(limit: int = 200):
    with session_scope() as s:
        return {"audit": [{"ts": iso(a.ts), "action": a.action, "details": a.details, "client_ip": a.client_ip}
                          for a in s.execute(select(AuditLog).order_by(desc(AuditLog.id)).limit(limit)).scalars()]}


app.include_router(router)
