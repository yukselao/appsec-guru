"""sast skill: clone -> inventory -> function extraction -> candidate selection ->
argument analysis by the sast-agent -> findings in PostgreSQL."""
import datetime
import logging
import os
import shutil
import threading
from collections import defaultdict

from sqlalchemy import select

from app import settings as st
from wtdb.database import session_scope
from wtdb.models import SastEvent, SastFinding, SastFunction, SastRun

from . import agent, extract as ex, tools
from .sinks import SEVERITY_RANK

log = logging.getLogger("sast")
WORK_DIR = os.environ.get("SAST_DIR", "/var/lib/was-troubleshooter/sast")
CONF_RANK = {"high": 3, "medium": 2, "low": 1}
ENTRY_HINT = ("request", "req", "params", "query", "body", "args", "form", "input", "ctx", "event", "payload")

_active = {}
_lock = threading.Lock()


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def event(run_id, level, msg):
    try:
        with session_scope() as s:
            s.add(SastEvent(run_id=run_id, level=level, message=str(msg)[:4000]))
    except Exception:
        log.exception("event")


def update(run_id, **fields):
    with session_scope() as s:
        r = s.get(SastRun, run_id)
        for k, v in fields.items():
            setattr(r, k, v)


def merge_stats(run_id, **kv):
    with session_scope() as s:
        r = s.get(SastRun, run_id)
        d = dict(r.stats or {})
        d.update(kv)
        r.stats = d


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
        for r in s.execute(select(SastRun).where(SastRun.status.in_(
                ["pending", "cloning", "extracting", "analysing"]))).scalars():
            r.status = "interrupted"
            r.error = "api restarted during the run"


def start(params, client_ip=None):
    url = (params.get("repo_url") or "").strip()
    if not url:
        raise ValueError("repository URL is required")
    c = st.get_all()
    opts = {"ref": (params.get("ref") or "").strip(), "include_tests": bool(params.get("include_tests")),
            "max_functions": max(1, min(int(params.get("max_functions") or 40), 500)),
            "min_severity": params.get("min_severity") or "low",
            "mode": params.get("mode") or "auto", "keep_clone": bool(params.get("keep_clone"))}
    with session_scope() as s:
        r = SastRun(repo_url=url, ref=opts["ref"] or None, status="pending", model=c["ai.model"], options=opts)
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("sast_run_create", client_ip=client_ip, run_id=run_id, repo=url, options=opts)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    token = (params.get("token") or "").strip()  # used for the clone only, never stored
    threading.Thread(target=_run, args=(run_id, url, opts, token, ev), name="sast-%d" % run_id, daemon=True).start()
    return run_id


def _priority(f):
    sev = max([SEVERITY_RANK.get(s["severity"], 0) for s in f["sinks"]] or [0])
    entry = 1 if f.get("route") or any(p.lower().startswith(ENTRY_HINT) for p in f["params"]) else 0
    return sev * 10 + entry * 5 + min(len(f["sinks"]), 4)


def _task(ctx, f, callers):
    code, _ = ex.numbered(ctx.root, f["file"], f["start_line"], min(f["end_line"], f["start_line"] + 220))
    sinks = "\n".join("- line {line}: {sink} ({cwe}, {severity}): {text}".format(**s) for s in f["sinks"]) or "- none detected"
    calls = ", ".join(f["calls"][:40]) or "-"
    who = "\n".join("- " + c for c in callers[:10]) or "- unknown (search_code if needed)"
    return ("Review this function argument by argument (argument-analysis skill).\n\n"
            "File: {file}\nFunction: {name}\nLanguage: {language}\nParameters: {params}\n"
            "Route / decorators: {route}\nSink hits:\n{sinks}\nCalls: {calls}\nKnown callers:\n{who}\n\n"
            "Source:\n```\n{code}\n```\n").format(
        file=f["file"], name=f["name"], language=f["language"], params=", ".join(f["params"]) or "-",
        route=f.get("route") or ", ".join(f.get("decorators") or []) or "-", sinks=sinks, calls=calls, who=who,
        code=code)


def _run(run_id, url, opts, token, cancel_ev):
    workdir = os.path.join(WORK_DIR, "run-{}".format(run_id))
    seen = {}  # (file, line, cwe) -> (finding id, confidence rank)
    sev_counts = defaultdict(int)
    current_fn = {"id": None}

    def report(fd):
        sev = str(fd.get("severity", "medium")).lower()
        conf = str(fd.get("confidence", "medium")).lower()
        if sev not in SEVERITY_RANK:
            sev = "medium"
        if conf not in CONF_RANK:
            conf = "medium"
        if SEVERITY_RANK[sev] < SEVERITY_RANK.get(opts["min_severity"], 1):
            return {"ok": True, "ignored": "below minimum severity"}
        try:
            line = int(fd.get("line") or 0) or None
        except (TypeError, ValueError):
            line = None
        key = (fd.get("file"), line, fd.get("cwe"))
        with session_scope() as s:
            if key in seen:
                fid, rank = seen[key]
                if CONF_RANK[conf] <= rank:
                    return {"ok": True, "duplicate": True}
                row = s.get(SastFinding, fid)
            else:
                row = SastFinding(run_id=run_id)
                s.add(row)
            row.function_id = current_fn["id"]
            row.file = str(fd.get("file") or "?")[:1000]
            row.line = line
            row.function = fd.get("function")
            row.parameter = fd.get("parameter")
            row.cwe = (fd.get("cwe") or "")[:20]
            row.title = str(fd.get("title") or "Untitled finding")[:500]
            row.severity, row.confidence = sev, conf
            row.description = fd.get("description")
            row.evidence = fd.get("evidence")
            row.recommendation = fd.get("recommendation")
            s.flush()
            if key not in seen:
                sev_counts[sev] += 1
            seen[key] = (row.id, CONF_RANK[conf])
        event(run_id, "warn", "finding: [{}] {} at {}:{}".format(sev, row.title, row.file, line or "?"))
        return {"ok": True, "id": seen[key][0]}

    ctx = tools.ToolContext(run_id, workdir, report)
    t0 = now()
    try:
        update(run_id, status="cloning", started_at=t0)
        shutil.rmtree(workdir, ignore_errors=True)
        info = tools.repo_clone(ctx, url, ref=opts["ref"], token=token)
        update(run_id, commit=info["commit"])
        event(run_id, "ok", "cloned {} @ {}".format(info["url"], info["commit"][:12]))

        update(run_id, status="extracting")
        files = tools.list_files(ctx, include_tests=opts["include_tests"])
        langs = defaultdict(int)
        for f in files:
            langs[f["language"]] += 1
        event(run_id, "info", "{} source files: {}".format(len(files), dict(langs)))
        funcs = []
        for f in files:
            if cancel_ev.is_set():
                raise RuntimeError("cancelled")
            funcs.extend(tools.extract_functions(ctx, f["path"]))
        index = defaultdict(list)
        for f in funcs:
            index[f["name"]].append(f)
            index[f["name"].split(".")[-1]].append(f)
        ctx.index = index
        with_args = [f for f in funcs if f["params"]]
        cands = [f for f in with_args if f["sinks"]]
        for f in cands:
            f["priority"] = _priority(f)
        cands.sort(key=lambda f: -f["priority"])
        chosen = cands[:opts["max_functions"]]
        ids = {}
        chosen_ids, cand_ids = {id(f) for f in chosen}, {id(f) for f in cands}
        with session_scope() as s:
            for f in funcs:
                status = "candidate" if id(f) in chosen_ids else ("skipped" if id(f) in cand_ids else "extracted")
                row = SastFunction(run_id=run_id, file=f["file"], name=f["name"], language=f["language"],
                                   start_line=f["start_line"], end_line=f["end_line"], params=f["params"],
                                   sinks=f["sinks"], route=f.get("route"), priority=f.get("priority", 0), status=status)
                s.add(row)
                s.flush()
                ids[id(f)] = row.id
        merge_stats(run_id, files=len(files), languages=dict(langs), functions=len(funcs),
                    functions_with_args=len(with_args), candidates=len(cands), selected=len(chosen))
        event(run_id, "ok", "{} functions extracted, {} take arguments, {} reach a sink; analysing top {}".format(
            len(funcs), len(with_args), len(cands), len(chosen)))

        c = st.get_all(include_secrets=True)
        if not c["ai.ollama_url"] or not c["ai.model"]:
            raise RuntimeError("Ollama URL and model are not set (Settings > AI)")
        update(run_id, status="analysing")
        mode = opts["mode"]
        tokens = {"prompt": 0, "eval": 0}
        for n, f in enumerate(chosen, 1):
            if cancel_ev.is_set():
                raise RuntimeError("cancelled")
            fid = ids[id(f)]
            current_fn["id"] = fid
            ctx.finished = None
            short = f["name"].split(".")[-1]
            callers = [g["file"] + ":" + g["name"] for g in funcs if short in g["calls"] and g is not f]
            event(run_id, "info", "[{}/{}] {} ({}) params: {}".format(n, len(chosen), f["name"], f["file"],
                                                                     ", ".join(f["params"])))

            def step(name, args, res):
                if name in ("get_function", "read_file", "search_code"):
                    event(run_id, "debug", "  tool {}({})".format(name, ", ".join(
                        "{}={}".format(k, str(v)[:60]) for k, v in (args or {}).items())))
            try:
                res = agent.run("sast-agent", _task(ctx, f, callers), ctx, c["ai.ollama_url"], c["ai.model"],
                                num_ctx=int(c["ai.num_ctx"] or 16384), on_step=step, mode=mode)
                if res["mode"] == "json" and mode == "auto":
                    mode = "json"  # model has no tool calling; stay in JSON mode
                    event(run_id, "warn", "model has no tool calling; switched to JSON answer mode")
                tokens["prompt"] += res.get("prompt_tokens", 0)
                tokens["eval"] += res.get("eval_tokens", 0)
                fin = res.get("finished") or {}
                with session_scope() as s:
                    row = s.get(SastFunction, fid)
                    row.status = "analysed"
                    row.verdict = fin.get("verdict")
                    row.summary = fin.get("summary")
                    row.agent_stats = {k: res.get(k) for k in ("mode", "steps", "prompt_tokens", "eval_tokens", "seconds")}
            except Exception as exc:
                event(run_id, "error", "  agent failed on {}: {}".format(f["name"], getattr(exc, "msg", exc)))
                with session_scope() as s:
                    s.get(SastFunction, fid).status = "error"
            merge_stats(run_id, analysed=n, findings=dict(sev_counts), tokens=tokens, mode=mode)
        update(run_id, status="completed")
        event(run_id, "ok", "completed: {} findings {}".format(sum(sev_counts.values()), dict(sev_counts)))
    except Exception as exc:
        msg = getattr(exc, "msg", str(exc))
        update(run_id, status="cancelled" if msg == "cancelled" else "failed", error=None if msg == "cancelled" else msg)
        event(run_id, "error" if msg != "cancelled" else "warn", msg)
    finally:
        merge_stats(run_id, findings=dict(sev_counts), seconds=int((now() - t0).total_seconds()))
        update(run_id, finished_at=now())
        if not opts.get("keep_clone"):
            shutil.rmtree(workdir, ignore_errors=True)
        with _lock:
            _active.pop(run_id, None)
