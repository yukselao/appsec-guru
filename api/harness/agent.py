"""Agent loop against Ollama /api/chat. Tool-calling when the model supports it,
JSON-answer mode otherwise."""
import json
import time

from app import ai
from . import loader, tools

JSON_MODE_HINT = """
Your model runtime has no tool calling. Answer with ONE JSON object and nothing else:
{"findings": [{"file": "...", "line": 0, "function": "...", "parameter": "...", "cwe": "CWE-89",
  "title": "...", "severity": "critical|high|medium|low", "confidence": "high|medium|low",
  "description": "source -> path -> sink", "evidence": "...", "recommendation": "..."}],
 "verdict": "vulnerable|safe|not_reachable|unsure", "summary": "one line"}
Use an empty findings list when nothing is vulnerable."""


class NoToolSupport(Exception):
    pass


def _chat(url, model, messages, tools_spec=None, temperature=0.1, num_ctx=16384, fmt=None, timeout=900):
    body = {"model": model, "stream": False, "messages": messages,
            "options": {"temperature": float(temperature), "num_ctx": int(num_ctx)}}
    if tools_spec:
        body["tools"] = tools_spec
    if fmt:
        body["format"] = fmt
    try:
        r = ai.request(url, "/api/chat", body, timeout=timeout)
    except Exception as exc:
        msg = getattr(exc, "msg", str(exc))
        if "does not support tools" in msg:
            raise NoToolSupport(msg)
        raise
    return json.loads(r.read().decode("utf-8"))


def run(agent_name, task, ctx, url, model, num_ctx=16384, on_step=None, mode="auto"):
    """Runs one agent task. Returns {"mode", "steps", "tokens", "finished", "error"}."""
    system, meta = loader.system_prompt(agent_name)
    names = meta.get("tools") or []
    temp = meta.get("temperature", 0.1)
    max_steps = int(meta.get("max_steps", 12))
    stats = {"mode": "tools", "steps": 0, "prompt_tokens": 0, "eval_tokens": 0, "seconds": 0.0}
    t0 = time.time()
    if mode != "json":
        try:
            msgs = [{"role": "system", "content": system}, {"role": "user", "content": task}]
            spec = loader.ollama_tools(names)
            for _ in range(max_steps):
                d = _chat(url, model, msgs, tools_spec=spec, temperature=temp, num_ctx=num_ctx)
                stats["steps"] += 1
                stats["prompt_tokens"] += d.get("prompt_eval_count") or 0
                stats["eval_tokens"] += d.get("eval_count") or 0
                m = d.get("message") or {}
                calls = m.get("tool_calls") or []
                msgs.append({"role": "assistant", "content": m.get("content", ""), "tool_calls": calls} if calls
                            else {"role": "assistant", "content": m.get("content", "")})
                if not calls:
                    if ctx.finished is None:
                        msgs.append({"role": "user", "content": "Call report_finding for each confirmed issue, then call finish."})
                        continue
                    break
                for c in calls:
                    fn = (c.get("function") or {})
                    name, args = fn.get("name"), fn.get("arguments") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except ValueError:
                            args = {}
                    if name not in names:
                        res = {"error": "tool not allowed for this agent: {}".format(name)}
                    else:
                        res = tools.call(ctx, name, args)
                    if on_step:
                        on_step(name, args, res)
                    msgs.append({"role": "tool", "content": json.dumps(res, default=str)[:12000]})
                if ctx.finished is not None:
                    break
            stats["seconds"] = round(time.time() - t0, 1)
            stats["finished"] = ctx.finished
            return stats
        except NoToolSupport:
            pass
    # JSON mode
    stats["mode"] = "json"
    msgs = [{"role": "system", "content": system + "\n" + JSON_MODE_HINT}, {"role": "user", "content": task}]
    d = _chat(url, model, msgs, temperature=temp, num_ctx=num_ctx, fmt="json")
    stats["steps"] = 1
    stats["prompt_tokens"] = d.get("prompt_eval_count") or 0
    stats["eval_tokens"] = d.get("eval_count") or 0
    try:
        out = json.loads((d.get("message") or {}).get("content") or "{}")
    except ValueError:
        out = {}
    for f in out.get("findings") or []:
        if isinstance(f, dict):
            tools.call(ctx, "report_finding", f)
    ctx.finished = {"verdict": out.get("verdict", "unsure"), "summary": out.get("summary", "")}
    stats["finished"] = ctx.finished
    stats["seconds"] = round(time.time() - t0, 1)
    return stats
