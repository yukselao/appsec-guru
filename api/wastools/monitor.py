from .core import *  # noqa: F401,F403
# ---------------------------------------------------------------------------
# monitor: running scans on SC + scanner host, SC<->scanUuid linking
# ---------------------------------------------------------------------------
RUNNING_STATES = {"running", "queued", "pending", "preparing", "initializing", "paused", "resuming", "stopping"}


def sc_running(sc):
    """Running/queued scan results from SC (last 7 days) with progress detail."""
    rows = sc.scan_results_recent(since_seconds=7 * 86400)
    out = []
    for r in rows:
        st = str(r.get("status", "")).lower()
        if st in RUNNING_STATES or str(r.get("running")).lower() == "true":
            try:
                r.update(sc.scan_result(r.get("id")))
            except SCError:
                pass
            r["_is_was"] = str(r.get("resultType", "")).lower() == "was"
            targets, scanners = [], []
            prog = r.get("progress") or {}
            if isinstance(prog, dict):
                for s_ in prog.get("scanners") or []:
                    scanners.append(s_.get("name"))
                    for t in s_.get("targets") or []:
                        targets.append({"url": t.get("targetUrl"), "status": t.get("status"),
                                        "error": t.get("errorNotes")})
            r["_targets"] = targets
            r["_scanners"] = scanners
            out.append(r)
    return out


def host_of(url):
    m = re.match(r"^\w+://([^/#?]+)", url or "")
    return m.group(1).lower() if m else (url or "").lower()


def link(data):
    """Match SC scan results to scanner-side scan UUIDs by target host:port."""
    for r in data["sc"]:
        hosts = set(host_of(t["url"]) for t in r.get("_targets") or [])
        r["_uuids"] = [s["uuid"] for s in data["scans"] if s.get("has_dir") and host_of(s.get("target")) in hosts]
    for s in data["scans"]:
        s["sc_ids"] = [str(r.get("id")) for r in data["sc"] if s["uuid"] in r.get("_uuids", [])]


def collect(args, sc=None, washost=None):
    data = {"sc": [], "was": [], "scans": [], "chrome": 0, "drivers": 0, "load": None, "errors": []}
    if sc:
        try:
            data["sc"] = sc_running(sc)
        except SCError as exc:
            data["errors"].append("SC: {}".format(exc))
    if washost:
        try:
            data["was"], data["chrome"] = washost.active_scan_processes()
            data["scans"] = washost.last_scans
            data["drivers"] = washost.last_drivers
            data["load"] = washost.load()
        except Exception as exc:
            data["errors"].append("was: {}".format(exc))
    link(data)
    return data


def fmt_elapsed(sec):
    sec = int(sec or 0)
    return "{:d}:{:02d}:{:02d}".format(sec // 3600, (sec % 3600) // 60, sec % 60)


def resolve_uuid(data, ref):
    """ref: SC scanResult id/name, full or prefix scanUuid. Returns (uuid list, sc row)."""
    act = [s for s in data["scans"] if s.get("has_dir")]
    if ref:
        for s in data["scans"]:
            if s["uuid"].startswith(ref):
                row = next((r for r in data["sc"] if s["uuid"] in r.get("_uuids", [])), None)
                return [s["uuid"]], row
        for r in data["sc"]:
            if str(r.get("id")) == str(ref) or r.get("name") == ref:
                return r.get("_uuids") or [], r
        return [], None
    if len(act) == 1:
        row = next((r for r in data["sc"] if act[0]["uuid"] in r.get("_uuids", [])), None)
        return [act[0]["uuid"]], row
    return None, None


