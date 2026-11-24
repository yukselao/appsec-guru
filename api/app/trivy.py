"""Trivy (container image vulnerability / secret / misconfiguration scanning) in
its own container, reached over TCP (socat). The vuln DB is baked into the image
for deterministic, offline scans. Native JSON is parsed deterministically - no AI.
The backend never touches the Docker socket; Trivy pulls images by reference."""
import json
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import desc, select

from wtdb.database import session_scope
from wtdb.models import TrivyScan

from . import settings as st

log = logging.getLogger("trivy")
TRIVY = os.environ.get("RECON_TRIVY", "recon-trivy:7009")
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
IMAGE_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,250}$")
SCANNERS = ("vuln", "secret", "misconfig", "license")
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SENTINEL = "__TRIVY_JSON__"
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
        for r in s.execute(select(TrivyScan).where(TrivyScan.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the scan"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(TrivyScan, run_id)
        for k, v in f.items():
            setattr(r, k, v)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def _argv(image, o):
    """Whole trivy argv. Only whitelisted flags; the image reference is the only
    user string and is validated. --format json / offline DB are forced by the
    container. Never uses the Docker socket (Trivy pulls the image by reference)."""
    scanners = [x for x in o.get("scanners") or [] if x in SCANNERS] or ["vuln"]
    argv = ["image", image, "--scanners", ",".join(scanners), "--timeout", "{}m".format(o["timeout"])]
    sev = [x for x in o.get("severity") or [] if x in SEVERITIES]
    if sev and len(sev) < len(SEVERITIES):
        argv += ["--severity", ",".join(sev)]
    if o.get("ignore_unfixed"):
        argv += ["--ignore-unfixed"]
    if o.get("list_all_pkgs"):
        argv += ["--list-all-pkgs"]
    return argv


def start(params, client_ip=None):
    image = (params.get("target") or params.get("image") or "").strip()
    if not image or not IMAGE_RX.match(image):
        raise ValueError("enter a valid image reference, e.g. alpine:3.19 or registry/repo:tag")
    scanners = [x for x in (params.get("scanners") or ["vuln"]) if x in SCANNERS] or ["vuln"]
    severity = [x.upper() for x in (params.get("severity") or []) if x.upper() in SEVERITIES]
    opts = {"scanners": scanners, "severity": severity,
            "ignore_unfixed": bool(params.get("ignore_unfixed")),
            "list_all_pkgs": bool(params.get("list_all_pkgs")),
            "timeout": st.get_int("recon.trivy_timeout", _ov(params, "timeout", "recon.trivy_timeout")),
            "stage_timeout": st.get_int("recon.trivy_stage_timeout"),
            "profile": (params.get("profile") or "")[:30]}
    with session_scope() as s:
        r = TrivyScan(target=image, status="pending", options=opts)
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("trivy_scan_create", client_ip=client_ip, run_id=run_id, target=image, scanners=scanners)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, image, opts, ev), name="trivy-%d" % run_id, daemon=True).start()
    return run_id


def _ov(params, key, setting_key):
    v = params.get(key)
    if v in (None, ""):
        return None
    return {setting_key: v}


def _cvss(c):
    if not isinstance(c, dict):
        return ""
    for v in c.values():
        if isinstance(v, dict) and v.get("V3Score"):
            return v["V3Score"]
    return ""


def _parse(doc):
    """Deterministically normalise a Trivy JSON report. No AI, no guessing."""
    res = {"vulnerabilities": [], "secrets": [], "misconfigurations": [], "packages": []}
    md = doc.get("Metadata") or {}
    rd = md.get("RepoDigests") or []
    digest = (rd[0].split("@", 1)[-1] if rd and "@" in rd[0] else "")
    meta = {"os": (md.get("OS") or {}).get("Name"), "os_family": (md.get("OS") or {}).get("Family"),
            "image_id": md.get("ImageID"), "digest": digest, "artifact": doc.get("ArtifactName")}
    for r in doc.get("Results") or []:
        tgt = r.get("Target")
        typ = r.get("Type")
        for v in r.get("Vulnerabilities") or []:
            res["vulnerabilities"].append({
                "cve": v.get("VulnerabilityID"), "pkg": v.get("PkgName"),
                "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion") or "",
                "severity": (v.get("Severity") or "UNKNOWN").title(), "cvss": _cvss(v.get("CVSS")),
                "title": v.get("Title") or "", "url": v.get("PrimaryURL") or "",
                "status": v.get("Status") or "", "cwe": v.get("CweIDs") or [], "target": tgt})
        for sec in r.get("Secrets") or []:
            res["secrets"].append({
                "rule": sec.get("RuleID"), "category": sec.get("Category"), "title": sec.get("Title"),
                "severity": (sec.get("Severity") or "").title(), "file": tgt,
                "line": sec.get("StartLine"), "match": "***"})   # never expose the secret value
        for m in r.get("Misconfigurations") or []:
            res["misconfigurations"].append({
                "id": m.get("ID") or m.get("AVDID"), "title": m.get("Title"),
                "severity": (m.get("Severity") or "").title(), "message": m.get("Message") or "",
                "resolution": m.get("Resolution") or "", "status": m.get("Status") or "",
                "url": m.get("PrimaryURL") or "", "target": tgt})
        for p in r.get("Packages") or []:
            res["packages"].append({"name": p.get("Name"), "version": p.get("Version"),
                                    "licenses": p.get("Licenses") or [], "type": typ})
    return res, meta


def _stats(res):
    by = {}
    fixable = 0
    for v in res["vulnerabilities"]:
        by[v["severity"]] = by.get(v["severity"], 0) + 1
        if v["fixed"]:
            fixable += 1
    return {"vulnerabilities": len(res["vulnerabilities"]), "by_severity": by, "fixable": fixable,
            "secrets": len(res["secrets"]), "misconfigurations": len(res["misconfigurations"]),
            "packages": len(res["packages"])}


def _run(run_id, image, opts, cancel_ev):
    argv = _argv(image, opts)
    _log_append(run_id, "$ trivy " + " ".join(argv))
    jbuf, in_json, saw_error = [], False, []
    try:
        update(run_id, status="running")
        host, port = _hostport(TRIVY)
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
            if re.search(r"\bFATAL\b|\bfailed\b|could not|unable to", line, re.I):
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
        res, meta = _parse(doc)
        res["metadata"] = meta
        stats = _stats(res)
        _log_append(run_id, "[api] completed - {} vulnerabilities, {} secrets, {} misconfigurations".format(
            stats["vulnerabilities"], stats["secrets"], stats["misconfigurations"]))
        update(run_id, status="completed", results=res, stats=stats, digest=meta.get("digest") or None, finished_at=_now())
        st.audit("trivy_scan_done", run_id=run_id, target=image, vulnerabilities=stats["vulnerabilities"])
    except (OSError, socket.error) as exc:
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error="Trivy unreachable ({}). Is the recon-trivy container running?".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("trivy %s", run_id)
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def row(r):
    with _lock:
        has_log = bool(_logs.get(r.id))
    return {"id": r.id, "target": r.target, "digest": r.digest, "status": r.status, "error": r.error,
            "options": r.options, "results": r.results, "stats": r.stats, "active": is_active(r.id),
            "has_log": has_log, "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}


def summary(r):
    out = row(r)
    out.pop("results", None)
    return out


_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def images():
    """Image inventory: the latest scan per image reference, with its summary.
    Every value is from stored scans - no Docker socket, no live enumeration."""
    with session_scope() as s:
        scans = list(s.execute(select(TrivyScan).order_by(desc(TrivyScan.id))).scalars())
    latest, seen = {}, {}
    for sc in scans:
        latest.setdefault(sc.target, sc)
        seen.setdefault(sc.target, []).append(sc)
    out = []
    for tgt, sc in latest.items():
        meta = (sc.results or {}).get("metadata") or {}
        stt = sc.stats or {}
        same = seen[tgt]
        out.append({"image": tgt, "digest": sc.digest or meta.get("digest"),
                    "os": meta.get("os"), "os_family": meta.get("os_family"),
                    "last_scan_id": sc.id, "last_scanned": sc.created_at.isoformat() if sc.created_at else None,
                    "first_seen": (same[-1].created_at.isoformat() if same[-1].created_at else None),
                    "scans": len(same), "status": sc.status,
                    "vulnerabilities": stt.get("vulnerabilities", 0), "by_severity": stt.get("by_severity", {}),
                    "fixable": stt.get("fixable", 0), "secrets": stt.get("secrets", 0),
                    "misconfigurations": stt.get("misconfigurations", 0), "packages": stt.get("packages", 0)})
    out.sort(key=lambda x: -x["vulnerabilities"])
    return {"images": out}


def vulnerabilities():
    """Every unique CVE across the latest scan of each image, with the affected
    images and packages (drill-down from a CVE to every affected image)."""
    with session_scope() as s:
        scans = list(s.execute(select(TrivyScan).where(TrivyScan.status == "completed")
                               .order_by(desc(TrivyScan.id))).scalars())
    latest = {}
    for sc in scans:
        latest.setdefault(sc.target, sc)
    by_cve = {}
    for tgt, sc in latest.items():
        for v in (sc.results or {}).get("vulnerabilities", []):
            c = by_cve.get(v["cve"])
            if c is None:
                c = by_cve[v["cve"]] = {"cve": v["cve"], "severity": v["severity"], "title": v.get("title") or "",
                                        "url": v.get("url") or "", "cvss": v.get("cvss") or "",
                                        "images": {}, "packages": set(), "fixed": ""}
            c["images"][tgt] = sc.id
            c["packages"].add("{} {}".format(v.get("pkg"), v.get("installed")))
            if v.get("fixed") and not c["fixed"]:
                c["fixed"] = v["fixed"]
    cves = [{"cve": c["cve"], "severity": c["severity"], "title": c["title"], "url": c["url"], "cvss": c["cvss"],
             "fixed": c["fixed"], "packages": sorted(c["packages"]),
             "images": [{"image": k, "scan_id": vid} for k, vid in sorted(c["images"].items())],
             "image_count": len(c["images"])} for c in by_cve.values()]
    cves.sort(key=lambda x: (-_SEV_RANK.get(x["severity"], 0), -x["image_count"], x["cve"] or ""))
    return {"cves": cves, "count": len(cves)}


def overview():
    """DB-backed aggregate metrics for the Container Security overview. Every
    number comes from stored scans; nothing is hardcoded."""
    with session_scope() as s:
        scans = list(s.execute(select(TrivyScan).where(TrivyScan.status == "completed")
                               .order_by(desc(TrivyScan.id))).scalars())
        recent = [summary(r) for r in s.execute(select(TrivyScan).order_by(desc(TrivyScan.id)).limit(10)).scalars()]
    latest = {}
    for sc in scans:                       # newest scan per image reference
        latest.setdefault(sc.target, sc)
    agg = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    total_vuln = fixable = secrets = misconfig = vuln_images = secret_images = misconfig_images = 0
    cve_count = {}
    for sc in latest.values():
        stt = sc.stats or {}
        for k, v in (stt.get("by_severity") or {}).items():
            agg[k] = agg.get(k, 0) + v
        total_vuln += stt.get("vulnerabilities", 0)
        fixable += stt.get("fixable", 0)
        secrets += stt.get("secrets", 0)
        misconfig += stt.get("misconfigurations", 0)
        vuln_images += 1 if stt.get("vulnerabilities", 0) else 0
        secret_images += 1 if stt.get("secrets", 0) else 0
        misconfig_images += 1 if stt.get("misconfigurations", 0) else 0
        for v in (sc.results or {}).get("vulnerabilities", []):
            cve_count[v["cve"]] = cve_count.get(v["cve"], 0) + 1
    top = sorted(cve_count.items(), key=lambda x: -x[1])[:10]
    mvi = sorted(latest.values(), key=lambda sc: -(sc.stats or {}).get("vulnerabilities", 0))[:10]
    return {"images": len(latest), "scans": len(scans), "by_severity": agg, "total_vulnerabilities": total_vuln,
            "fixable": fixable, "secrets": secrets, "misconfigurations": misconfig,
            "vulnerable_images": vuln_images, "secret_images": secret_images, "misconfig_images": misconfig_images,
            "top_cves": [{"cve": c, "count": n} for c, n in top],
            "most_vulnerable": [{"target": sc.target, "vulnerabilities": (sc.stats or {}).get("vulnerabilities", 0),
                                 "by_severity": (sc.stats or {}).get("by_severity", {})} for sc in mvi if (sc.stats or {}).get("vulnerabilities", 0)],
            "recent": recent}
