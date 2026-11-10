"""Scan profiles (saved DAST scans) in a folder tree, and the scheduler that
starts them. Schedule JSON:
  {"type": "on_demand"}
  {"type": "once",     "at": "2026-11-12T03:00"}
  {"type": "interval", "every_hours": 6}
  {"type": "daily",    "time": "02:30"}
  {"type": "weekly",   "time": "02:30", "days": [0, 3]}   # Monday = 0
Times are local to the api container (TZ)."""
import datetime
import logging
import threading
import time

from sqlalchemy import select

from wtdb.database import session_scope
from wtdb.models import ScanFolder, ScanProfile, ScanRun

from . import runs
from . import settings as st

log = logging.getLogger("scheduler")
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
PROFILE_FIELDS = ("name", "description", "folder_id", "sensor_id", "target_url", "source_policy_id", "families", "debug_mode",
                  "scope", "prefs", "keep_objects", "repo_id", "zone_id", "schedule", "enabled")


def local_now():
    return datetime.datetime.now().astimezone()


def _hm(s):
    h, m = (s or "00:00").split(":")[:2]
    return int(h), int(m)


def next_run(schedule, after=None):
    """Next local datetime for a schedule, or None (on demand / past one-off)."""
    sch = schedule or {}
    t = sch.get("type", "on_demand")
    now = after or local_now()
    tz = now.tzinfo
    if t == "once":
        try:
            at = datetime.datetime.fromisoformat(sch.get("at", "")).replace(tzinfo=tz)
        except ValueError:
            return None
        return at if at > now else None
    if t == "interval":
        hours = max(0.25, float(sch.get("every_hours") or 24))
        return now + datetime.timedelta(hours=hours)
    if t in ("daily", "weekly"):
        h, m = _hm(sch.get("time"))
        days = set(int(d) for d in (sch.get("days") or [])) if t == "weekly" else set(range(7))
        if not days:
            return None
        for add in range(0, 8):
            d = (now + datetime.timedelta(days=add)).replace(hour=h, minute=m, second=0, microsecond=0)
            if d > now and d.weekday() in days:
                return d
    return None


def describe(schedule):
    sch = schedule or {}
    t = sch.get("type", "on_demand")
    if t == "once":
        return "once at " + str(sch.get("at", "")).replace("T", " ")
    if t == "interval":
        return "every {} h".format(sch.get("every_hours"))
    if t == "daily":
        return "daily at " + sch.get("time", "")
    if t == "weekly":
        return "weekly on {} at {}".format(", ".join(DAYS[int(d)] for d in sch.get("days") or []), sch.get("time", ""))
    return "on demand"


def validate(data):
    if not str(data.get("name") or "").strip():
        raise ValueError("profile name is required")
    if not str(data.get("target_url") or "").startswith(("http://", "https://")):
        raise ValueError("target URL must start with http:// or https://")
    if not data.get("source_policy_id"):
        raise ValueError("source policy is required")
    sch = data.get("schedule") or {"type": "on_demand"}
    if sch.get("type") not in ("on_demand", "once", "interval", "daily", "weekly"):
        raise ValueError("unknown schedule type")
    if sch.get("type") == "weekly" and not sch.get("days"):
        raise ValueError("pick at least one weekday")
    if sch.get("type") == "once" and next_run(sch) is None:
        raise ValueError("the one-off time must be in the future")
    if data.get("debug_mode") not in (None, "none", "sc", "host", "both"):
        raise ValueError("unknown debug mode")


def row(p, last=None):
    return {"id": p.id, "name": p.name, "description": p.description, "folder_id": p.folder_id, "sensor_id": p.sensor_id,
            "target_url": p.target_url, "source_policy_id": p.source_policy_id, "families": p.families,
            "debug_mode": p.debug_mode, "scope": p.scope, "prefs": p.prefs, "keep_objects": p.keep_objects,
            "repo_id": p.repo_id, "zone_id": p.zone_id, "schedule": p.schedule, "schedule_text": describe(p.schedule),
            "enabled": p.enabled, "next_run_at": p.next_run_at.isoformat() if p.next_run_at else None,
            "last_run_at": p.last_run_at.isoformat() if p.last_run_at else None, "last_run_id": p.last_run_id,
            "last_run": last, "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None}


def run_params(p):
    """Translate a profile into runs.start() parameters."""
    return {"url": p.target_url, "policy": p.source_policy_id, "sensor_id": p.sensor_id, "families": p.families or [],
            "fast": p.scope == "fast", "debug": p.debug_mode, "keep": p.keep_objects, "repo": p.repo_id,
            "zone": p.zone_id, "set": p.prefs or [], "name": "{}{}-{}".format(
                "tscdbg-", "".join(c if c.isalnum() else "-" for c in p.name.lower())[:40].strip("-"),
                local_now().strftime("%Y%m%d-%H%M"))}


def run_now(profile_id, trigger="manual", client_ip=None):
    with session_scope() as s:
        p = s.get(ScanProfile, profile_id)
        if not p:
            raise ValueError("profile not found")
        if p.last_run_id and runs.is_active(p.last_run_id):
            raise ValueError("the previous run of this profile is still active (run #{})".format(p.last_run_id))
        params = run_params(p)
    run_id = runs.start(params, client_ip=client_ip, profile_id=profile_id, trigger=trigger)
    with session_scope() as s:
        p = s.get(ScanProfile, profile_id)
        p.last_run_id = run_id
        p.last_run_at = local_now()
        if trigger == "schedule":
            p.next_run_at = next_run(p.schedule)
            if p.schedule.get("type") == "once":
                p.enabled = False
    st.audit("scan_profile_run", client_ip=client_ip, profile_id=profile_id, run_id=run_id, trigger=trigger)
    return run_id


# ---------------------------------------------------------------- scheduler
_started = False


def _tick():
    now = local_now()
    with session_scope() as s:
        due = [p.id for p in s.execute(select(ScanProfile).where(
            ScanProfile.enabled.is_(True), ScanProfile.next_run_at.isnot(None),
            ScanProfile.next_run_at <= now)).scalars()]
    for pid in due:
        try:
            rid = run_now(pid, trigger="schedule")
            log.info("profile %s started run %s", pid, rid)
        except ValueError as exc:
            log.warning("profile %s skipped: %s", pid, exc)
            with session_scope() as s:
                p = s.get(ScanProfile, pid)
                p.next_run_at = next_run(p.schedule)  # skip this slot, try the next one
        except Exception:
            log.exception("profile %s failed to start", pid)


def start_scheduler(interval=30):
    global _started
    if _started:
        return
    _started = True

    def loop():
        while True:
            try:
                _tick()
            except Exception:
                log.exception("scheduler tick")
            time.sleep(interval)
    threading.Thread(target=loop, name="scheduler", daemon=True).start()
    log.info("scheduler started (every %ss)", interval)


def folder_tree():
    with session_scope() as s:
        folders = [{"id": f.id, "name": f.name, "parent_id": f.parent_id}
                   for f in s.execute(select(ScanFolder).order_by(ScanFolder.name)).scalars()]
        counts = {}
        for p in s.execute(select(ScanProfile.folder_id)).all():
            counts[p[0]] = counts.get(p[0], 0) + 1
    for f in folders:
        f["profiles"] = counts.get(f["id"], 0)
    return {"folders": folders, "unfiled": counts.get(None, 0)}


def last_runs(ids):
    if not ids:
        return {}
    with session_scope() as s:
        return {r.id: {"id": r.id, "status": r.status, "active": runs.is_active(r.id),
                       "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                       "findings": len(r.findings or [])}
                for r in s.execute(select(ScanRun).where(ScanRun.id.in_(ids))).scalars()}
