"""Historical trends and run-over-run comparison across the container/K8s
security scanners. A pure read-model over the existing scan tables (Trivy image,
Trivy config/IaC, Kubescape, kube-bench) - no new table, no AI. It turns stored
scan results into time series and set-diffs (new / fixed / unchanged findings)."""
import datetime

from sqlalchemy import asc, select

from wtdb.database import session_scope
from wtdb.models import TrivyScan, TrivyConfigScan, KubescapeScan, KubeBenchScan

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def _trivy_findings(results):
    out = []
    for v in (results or {}).get("vulnerabilities") or []:
        cve, pkg = v.get("cve") or "", v.get("pkg") or ""
        out.append({"fp": cve + "@" + pkg, "id": cve,
                    "severity": v.get("severity") or "Unknown",
                    "title": "{} in {}".format(cve, pkg),
                    "extra": ("fix: " + v["fixed"]) if v.get("fixed") else "no fix"})
    return out


def _trivyconfig_findings(results):
    out = []
    for f in (results or {}).get("findings") or []:
        out.append({"fp": "{}:{}".format(f.get("id"), f.get("start_line") or ""),
                    "id": f.get("id"), "severity": f.get("severity") or "Unknown",
                    "title": f.get("title") or f.get("id"),
                    "extra": ("line " + str(f["start_line"])) if f.get("start_line") else ""})
    return out


def _kubescape_findings(results):
    out = []
    for c in (results or {}).get("controls") or []:
        out.append({"fp": c.get("id"), "id": c.get("id"),
                    "severity": c.get("severity") or "Unknown",
                    "title": c.get("name") or c.get("id"),
                    "extra": "{} resource(s)".format(c.get("failed_resources") or 0)})
    return out


def _kubebench_findings(results):
    # kube-bench has no severity; map FAIL -> High, WARN -> Medium for display.
    smap = {"FAIL": "High", "WARN": "Medium"}
    out = []
    for c in (results or {}).get("checks") or []:
        status = (c.get("status") or "").upper()
        if status not in ("FAIL", "WARN"):
            continue
        out.append({"fp": c.get("id"), "id": c.get("id"),
                    "severity": smap.get(status, "Unknown"),
                    "title": c.get("desc") or c.get("id"), "extra": status})
    return out


# source -> model, display label, which column names the scanned target, and the
# function that turns a scan's `results` into a list of findings.
SOURCES = {
    "trivy": {"model": TrivyScan, "label": "Image vulnerabilities", "target": "target",
              "metric": "vulnerabilities", "extract": _trivy_findings},
    "trivyconfig": {"model": TrivyConfigScan, "label": "IaC misconfigurations", "target": "name",
                    "metric": "misconfigurations", "extract": _trivyconfig_findings},
    "kubescape": {"model": KubescapeScan, "label": "Failed controls", "target": "name",
                  "metric": "failed controls", "extract": _kubescape_findings},
    "kubebench": {"model": KubeBenchScan, "label": "CIS failures", "target": "benchmark",
                  "metric": "failures/warnings", "extract": _kubebench_findings},
}


def _counts(findings):
    c = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return {"total": len(findings), "critical": c["Critical"], "high": c["High"],
            "medium": c["Medium"], "low": c["Low"], "by_severity": c}


def _target_of(src, r):
    return getattr(r, SOURCES[src]["target"]) or ""


def timeline(source, days=90):
    """Per-scan finding counts over time for one source (completed scans)."""
    if source not in SOURCES:
        return {"error": "unknown source"}
    cfg = SOURCES[source]
    Model = cfg["model"]
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=max(1, min(days, 3650)))
    points = []
    with session_scope() as s:
        q = (select(Model).where(Model.status == "completed")
             .where(Model.created_at >= since).order_by(asc(Model.created_at)))
        for r in s.execute(q).scalars():
            c = _counts(cfg["extract"](r.results))
            points.append({"id": r.id, "target": _target_of(source, r),
                           "at": (r.finished_at or r.created_at).isoformat(),
                           **c})
    return {"source": source, "label": cfg["label"], "metric": cfg["metric"], "points": points}


def targets(source):
    """Targets with >=2 completed scans - comparison candidates."""
    if source not in SOURCES:
        return {"error": "unknown source"}
    cfg = SOURCES[source]
    Model = cfg["model"]
    groups = {}
    with session_scope() as s:
        q = select(Model).where(Model.status == "completed").order_by(asc(Model.created_at))
        for r in s.execute(q).scalars():
            t = _target_of(source, r)
            groups.setdefault(t, []).append(
                {"id": r.id, "at": (r.finished_at or r.created_at).isoformat()})
    out = [{"target": t, "scans": v} for t, v in groups.items() if len(v) >= 2]
    out.sort(key=lambda g: g["target"])
    return {"source": source, "targets": out}


def _load(s, Model, scan_id):
    r = s.get(Model, scan_id)
    if not r or r.status != "completed":
        return None
    return r


def compare(source, a, b):
    """Set-diff two completed scans: added / removed / unchanged findings."""
    if source not in SOURCES:
        return {"error": "unknown source"}
    cfg = SOURCES[source]
    Model = cfg["model"]
    with session_scope() as s:
        ra, rb = _load(s, Model, a), _load(s, Model, b)
        if not ra or not rb:
            return {"error": "both scans must exist and be completed"}
        fa = {f["fp"]: f for f in cfg["extract"](ra.results)}
        fb = {f["fp"]: f for f in cfg["extract"](rb.results)}
        meta_a = {"id": ra.id, "target": _target_of(source, ra),
                  "at": (ra.finished_at or ra.created_at).isoformat(), **_counts(list(fa.values()))}
        meta_b = {"id": rb.id, "target": _target_of(source, rb),
                  "at": (rb.finished_at or rb.created_at).isoformat(), **_counts(list(fb.values()))}

    def srt(items):
        return sorted(items, key=lambda f: (-_SEV_RANK.get(f["severity"], 0), f.get("id") or ""))

    added = srt([fb[k] for k in fb if k not in fa])     # new in b
    removed = srt([fa[k] for k in fa if k not in fb])   # fixed/gone in b
    unchanged = srt([fb[k] for k in fb if k in fa])
    return {"source": source, "label": cfg["label"], "a": meta_a, "b": meta_b,
            "added": added, "removed": removed, "unchanged": unchanged,
            "summary": {"added": len(added), "removed": len(removed), "unchanged": len(unchanged),
                        "delta": meta_b["total"] - meta_a["total"]}}


def overview():
    """One summary row per source for the trends landing cards."""
    out = []
    with session_scope() as s:
        for src, cfg in SOURCES.items():
            Model = cfg["model"]
            rows = list(s.execute(select(Model).where(Model.status == "completed")
                                  .order_by(asc(Model.created_at))).scalars())
            latest = _counts(cfg["extract"](rows[-1].results)) if rows else _counts([])
            prev = _counts(cfg["extract"](rows[-2].results)) if len(rows) >= 2 else None
            out.append({"source": src, "label": cfg["label"], "scans": len(rows),
                        "latest_total": latest["total"],
                        "delta": (latest["total"] - prev["total"]) if prev else None})
    return {"sources": out}
