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
