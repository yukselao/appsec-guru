"""Findings analysis: the offensive-security agent turns a scan's findings into
a structured attacker's read; report.py renders it as HTML."""
import datetime
import json
import logging
import os
import threading

from sqlalchemy import select

from app import conn
from app import settings as st
from app import wasfindings
from wastools.core import Fatal, SCError
from wtdb.database import session_scope
from wtdb.models import ScanRun

from . import loader, report

log = logging.getLogger("analysis")
REPORT_DIR = os.environ.get("REPORT_DIR", "/var/log/was-troubleshooter/reports")
_jobs = {}
_lock = threading.Lock()


def _task(run, findings, attachments):
    slim = [{k: f.get(k) for k in ("plugin_id", "name", "severity", "family", "cve", "cvss", "urls", "output",
                                   "attachments")} for f in findings]
    return ("Analyse this Tenable WAS scan result and return the findings-analysis JSON.\n\n"
            "Scan: {name}\nTarget: {url}\nSource policy: {pol}\nFindings ({n}):\n{findings}\n\n"
            "Fetched attachments:\n{att}\n").format(
        name=run.get("name"), url=run.get("target_url"), pol=run.get("source_policy_id"), n=len(slim),
        findings=json.dumps(slim, ensure_ascii=False)[:60000],
        att=json.dumps(attachments, ensure_ascii=False)[:8000] or "- none")


def job_view(j):
    return {"id": j["id"], "run_id": j["run_id"], "state": j["state"], "error": j.get("error"),
            "report_url": j.get("report_url"), "analysis": j.get("analysis"),
            "findings": j.get("findings_count"), "started": j["started"]}


def get_job(run_id):
    with _lock:
        return job_view(_jobs[run_id]) if run_id in _jobs else None


def start(run_id, client_ip=None, fetch_attachments=True):
    with _lock:
        if run_id in _jobs and _jobs[run_id]["state"] == "running":
            return job_view(_jobs[run_id])
        j = {"id": run_id, "run_id": run_id, "state": "running", "started": datetime.datetime.now().isoformat()}
        _jobs[run_id] = j
    threading.Thread(target=_run, args=(run_id, fetch_attachments), name="analysis-%d" % run_id, daemon=True).start()
    st.audit("findings_analysis_start", client_ip=client_ip, run_id=run_id)
    return job_view(j)


def _run(run_id, fetch_attachments):
    j = _jobs[run_id]
    try:
        with session_scope() as s:
            r = s.get(ScanRun, run_id)
            if not r or not r.sc_result_id:
                raise Fatal("the run has no Security Center result to analyse")
            meta = {"name": r.name, "target_url": r.target_url, "source_policy_id": r.source_policy_id,
                    "sc_result_id": r.sc_result_id}
        c = st.get_all(include_secrets=True)
        if not c["ai.ollama_url"] or not c["ai.model"]:
            raise Fatal("Ollama URL and model are not set (Settings > AI)")
        sc = conn.sc()
        findings = wasfindings.details(sc, meta["sc_result_id"])
        j["findings_count"] = len(findings)
        attachments = wasfindings.attachment_summary(sc, meta["sc_result_id"], findings) if fetch_attachments else []
        meta["_model"] = c["ai.model"]

        # The offensive-security agent answers with one findings-analysis JSON object.
        system, _ = loader.system_prompt("offensive-security-agent")
        analysis = _structured(c, system, _task(meta, findings, attachments))
        html = report.render(meta, analysis, findings)
        os.makedirs(REPORT_DIR, exist_ok=True)
        path = os.path.join(REPORT_DIR, "run-{}.html".format(run_id))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        with session_scope() as s:
            r = s.get(ScanRun, run_id)
            r.summary = dict(r.summary or {}, analysis=analysis, report=path,
                             analysed_at=datetime.datetime.now().isoformat())
        j.update({"state": "done", "analysis": analysis, "report_url": "/api/scans/{}/report".format(run_id)})
        st.audit("findings_analysis_done", run_id=run_id, risk=analysis.get("risk_rating"))
    except (Fatal, SCError, RuntimeError) as exc:
        j.update({"state": "failed", "error": getattr(exc, "msg", str(exc))})
    except Exception as exc:  # pragma: no cover
        log.exception("analysis %s", run_id)
        j.update({"state": "failed", "error": str(exc)})


def _structured(c, system, task):
    """One JSON object from the model (Ollama format=json)."""
    from app import ai
    body = {"model": c["ai.model"], "stream": False, "format": "json",
            "options": {"temperature": 0.2, "num_ctx": int(c["ai.num_ctx"] or 16384)},
            "messages": [{"role": "system", "content": system + "\nReturn ONLY the findings-analysis JSON object."},
                         {"role": "user", "content": task}]}
    r = ai.request(c["ai.ollama_url"], "/api/chat", body, timeout=900)
    d = json.loads(r.read().decode("utf-8"))
    try:
        return json.loads((d.get("message") or {}).get("content") or "{}")
    except ValueError:
        return {"summary": "The model did not return valid JSON.", "risk_rating": "informational",
                "attack_paths": [], "categories": [], "recon": [], "quick_wins": [], "false_positive_watch": []}


def report_path(run_id):
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        return (r.summary or {}).get("report") if r else None
