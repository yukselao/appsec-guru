"""Unified security findings read-model. It normalises findings from every
container/Kubernetes engine (Trivy image scans, Kubescape manifest scans) into
one shape so they can be searched, filtered and exported together. This is a
read model over the existing scan tables - there is no separate findings table
to keep in sync, so every number traces back to a stored scan."""
from sqlalchemy import desc, select

from wtdb.database import session_scope
from wtdb.models import KubescapeScan, TrivyScan

RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def _fp(source, ftype, ident, target):
    return "{}:{}:{}:{}".format(source, ftype, ident, target)


def _collect():
    with session_scope() as s:
        trivy = list(s.execute(select(TrivyScan).where(TrivyScan.status == "completed")
                               .order_by(desc(TrivyScan.id))).scalars())
        kube = list(s.execute(select(KubescapeScan).where(KubescapeScan.status == "completed")
                              .order_by(desc(KubescapeScan.id))).scalars())
    out = []
    # Trivy: latest scan per image
    t_latest = {}
    for sc in trivy:
        t_latest.setdefault(sc.target, sc)
    for tgt, sc in t_latest.items():
        r = sc.results or {}
        for v in r.get("vulnerabilities", []):
            out.append({"source": "trivy", "type": "vulnerability", "severity": v.get("severity", "Unknown"),
                        "title": v.get("title") or v.get("cve"), "identifier": v.get("cve"), "target": tgt,
                        "scan_id": sc.id, "scan_page": "/trivy-scan/{}".format(sc.id),
                        "fingerprint": _fp("trivy", "vulnerability", v.get("cve"), tgt),
                        "detail": {"package": v.get("pkg"), "installed": v.get("installed"),
                                   "fixed": v.get("fixed"), "cvss": v.get("cvss"), "url": v.get("url")}})
        for sec in r.get("secrets", []):
            out.append({"source": "trivy", "type": "secret", "severity": sec.get("severity") or "High",
                        "title": sec.get("title") or sec.get("rule"), "identifier": sec.get("rule"), "target": tgt,
                        "scan_id": sc.id, "scan_page": "/trivy-scan/{}".format(sc.id),
                        "fingerprint": _fp("trivy", "secret", sec.get("rule"), tgt + ":" + str(sec.get("file"))),
                        "detail": {"category": sec.get("category"), "file": sec.get("file"), "line": sec.get("line")}})
        for m in r.get("misconfigurations", []):
            out.append({"source": "trivy", "type": "misconfiguration", "severity": m.get("severity", "Unknown"),
                        "title": m.get("title"), "identifier": m.get("id"), "target": tgt,
                        "scan_id": sc.id, "scan_page": "/trivy-scan/{}".format(sc.id),
                        "fingerprint": _fp("trivy", "misconfiguration", m.get("id"), tgt),
                        "detail": {"message": m.get("message"), "resolution": m.get("resolution"), "url": m.get("url")}})
    # Kubescape: latest scan per manifest label
    k_latest = {}
    for sc in kube:
        k_latest.setdefault(sc.name, sc)
    for name, sc in k_latest.items():
        for c in (sc.results or {}).get("controls", []):
            out.append({"source": "kubescape", "type": "k8s-control", "severity": c.get("severity", "Unknown"),
                        "title": c.get("name"), "identifier": c.get("id"), "target": name,
                        "scan_id": sc.id, "scan_page": "/kubescape/{}".format(sc.id),
                        "fingerprint": _fp("kubescape", "k8s-control", c.get("id"), name),
                        "detail": {"category": c.get("category"), "failed_resources": c.get("failed_resources"),
                                   "url": c.get("url")}})
    return out


def aggregate(source=None, ftype=None, severity=None, q=None, limit=2000):
    items = _collect()
    if source:
        items = [f for f in items if f["source"] == source]
    if ftype:
        items = [f for f in items if f["type"] == ftype]
    if severity:
        items = [f for f in items if f["severity"] == severity]
    if q:
        ql = q.lower()
        items = [f for f in items if ql in (str(f["title"]) + " " + str(f["identifier"]) + " " + str(f["target"])).lower()]
    items.sort(key=lambda f: (-RANK.get(f["severity"], 0), f["source"], str(f["identifier"])))
    return {"findings": items[:limit], "total": len(items)}


def summary():
    items = _collect()
    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    by_source, by_type = {}, {}
    for f in items:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_source[f["source"]] = by_source.get(f["source"], 0) + 1
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    return {"total": len(items), "by_severity": by_sev, "by_source": by_source, "by_type": by_type}
