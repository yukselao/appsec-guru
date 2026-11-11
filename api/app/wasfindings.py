"""Rich WAS finding details from Security Center: per-plugin output, URLs,
CVE/CVSS and attachment references, for the offensive-security analysis."""
import re

from wastools.core import SCError

PLUGIN_OUT_RX = re.compile(r"<plugin_output>(.*?)</plugin_output>", re.S)
URL_RX = re.compile(r"https?://[^\s\"'<>]+")


def _text(x, *keys):
    for k in keys:
        v = x.get(k)
        if v:
            return v
    return ""


def details(sc, rid, max_plugins=400):
    """Each finding with severity, family, affected URLs, plugin output text,
    CVE/CVSS and attachment ids."""
    q = {"type": "vuln", "sourceType": "individual", "scanID": str(rid), "view": "all",
         "query": {"tool": "vulndetails", "type": "vuln", "startOffset": 0, "endOffset": max_plugins, "filters": []}}
    res = sc.post("analysis", q)
    by_plugin = {}
    for x in res.get("results", []):
        pid = str(x.get("pluginID"))
        sev = x.get("severity") or {}
        fam = x.get("family") or {}
        text = _text(x, "pluginText", "description")
        out = "\n".join(PLUGIN_OUT_RX.findall(text)) or ""
        urls = sorted(set(URL_RX.findall(out + " " + _text(x, "uri", "request"))))[:25]
        att = x.get("attachment") or x.get("attachments") or []
        if isinstance(att, dict):
            att = [att]
        atts = [{"id": str(a.get("id") or a.get("attachmentID") or a.get("value")), "name": a.get("name") or a.get("type")}
                for a in att if isinstance(a, dict) and (a.get("id") or a.get("attachmentID") or a.get("value"))]
        f = by_plugin.setdefault(pid, {
            "plugin_id": pid, "name": x.get("name"), "severity": sev.get("name"), "severity_id": int(sev.get("id") or 0),
            "family": fam.get("name") if isinstance(fam, dict) else fam,
            "cve": [c for c in (x.get("cve") or "").split(",") if c][:10],
            "cvss": x.get("cvssV3BaseScore") or x.get("baseScore") or "", "urls": [], "output": [], "attachments": []})
        for u in urls:
            if u not in f["urls"]:
                f["urls"].append(u)
        if out and out not in f["output"]:
            f["output"].append(out[:4000])
        for a in atts:
            if a not in f["attachments"]:
                f["attachments"].append(a)
    out = list(by_plugin.values())
    for f in out:
        f["count"] = len(f["urls"]) or 1
        f["output"] = "\n---\n".join(f["output"])[:8000]
    out.sort(key=lambda f: (-f["severity_id"], f["name"] or ""))
    return out


def attachment(sc, rid, att_id):
    """Download one attachment; returns (content_type, bytes). Images stay bytes."""
    r = sc.call("POST", "scanResult/{}/attachment/{}".format(rid, att_id), body={}, raw=True)
    ctype = r.headers.get("Content-Type", "application/octet-stream")
    return ctype, r.read()


def attachment_summary(sc, rid, findings, limit=6):
    """Short text note per attachment (type, size); never inlines binaries."""
    notes = []
    for f in findings:
        for a in f.get("attachments", [])[:2]:
            if len(notes) >= limit:
                return notes
            try:
                ctype, data = attachment(sc, rid, a["id"])
                notes.append({"plugin_id": f["plugin_id"], "attachment_id": a["id"], "name": a.get("name"),
                              "content_type": ctype, "size": len(data),
                              "text": data.decode("utf-8", "replace")[:2000] if "text" in ctype or "json" in ctype else ""})
            except SCError:
                continue
    return notes


def _ts(v):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


def plugin_details(sc, rid, plugin_id, limit=500):
    """Everything Security Center returns for one plugin in one scan result:
    the plugin's reference data once, plus one entry per instance."""
    q = {"type": "vuln", "sourceType": "individual", "scanID": str(rid), "view": "all",
         "query": {"tool": "vulndetails", "type": "vuln", "startOffset": 0, "endOffset": limit,
                   "filters": [{"filterName": "pluginID", "operator": "=", "value": str(plugin_id)}]}}
    rows = sc.post("analysis", q).get("results", [])
    if not rows:
        return None
    x = rows[0]
    sev, fam = x.get("severity") or {}, x.get("family") or {}
    plugin = {
        "plugin_id": str(x.get("pluginID")), "name": x.get("pluginName") or x.get("name"),
        "severity": sev.get("name"), "family": fam.get("name") if isinstance(fam, dict) else fam,
        "synopsis": x.get("synopsis") or "", "description": x.get("description") or "",
        "solution": x.get("solution") or "",
        "see_also": [u for u in re.split(r"\s+", x.get("seeAlso") or "") if u],
        "risk_factor": x.get("riskFactor") or "", "cve": [c for c in (x.get("cve") or "").split(",") if c],
        "xref": [c.strip() for c in (x.get("xref") or "").split(",") if c.strip()],
        "cvss": {k: x.get(k) for k in ("baseScore", "cvssVector", "cvssV3BaseScore", "cvssV3Vector",
                                        "cvssV4BaseScore", "cvssV4Vector", "vprScore", "epssScore") if x.get(k)},
        "exploit_available": x.get("exploitAvailable") or "", "check_type": x.get("checkType") or "",
        "plugin_published": _ts(x.get("pluginPubDate")), "plugin_modified": _ts(x.get("pluginModDate")),
    }
    instances = []
    for i, r in enumerate(rows, 1):
        text = r.get("pluginText") or ""
        out = "\n".join(PLUGIN_OUT_RX.findall(text)) or text
        att = r.get("attachment") or r.get("attachments") or []
        if isinstance(att, dict):
            att = [att]
        atts = [{"id": str(a.get("id") or a.get("attachmentID") or a.get("value")), "name": a.get("name") or a.get("type") or "attachment"}
                for a in att if isinstance(a, dict) and (a.get("id") or a.get("attachmentID") or a.get("value"))] if isinstance(att, list) else []
        instances.append({
            "n": i, "vuln_uuid": r.get("vulnUUID") or "", "host": r.get("dnsName") or r.get("ip") or "",
            "ip": r.get("ip") or "", "port": r.get("port") or "", "protocol": r.get("protocol") or "",
            "urls": sorted(set(URL_RX.findall(out)))[:50], "output": out,
            "first_seen": _ts(r.get("firstSeen")), "last_seen": _ts(r.get("lastSeen")), "attachments": atts})
    return {"plugin": plugin, "instances": instances, "count": len(instances)}
