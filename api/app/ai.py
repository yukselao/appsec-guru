"""Ollama: connection test, model list, streaming chat (NDJSON)."""
import json
import ssl
import time
import urllib.error
import urllib.request

from wastools.core import Fatal


def base(url):
    url = (url or "").strip().rstrip("/")
    if not url:
        raise Fatal("Ollama adresi tanımlı değil (Settings > AI)")
    if not url.startswith("http"):
        url = "http://" + url
    if url.endswith("/api"):
        url = url[:-4]
    return url


def request(url, path, body=None, timeout=30):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base(url) + path, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except urllib.error.HTTPError as exc:
        raise Fatal("Ollama HTTP {}: {}".format(exc.code, exc.read().decode("utf-8", "replace")[:300]))
    except (urllib.error.URLError, OSError) as exc:
        raise Fatal("Ollama'ya bağlanılamadı ({}): {}".format(base(url), exc))


def models(url):
    tags = json.loads(request(url, "/api/tags", timeout=15).read().decode("utf-8"))
    return [{"name": m.get("name"), "size": m.get("size"),
             "family": (m.get("details") or {}).get("family"),
             "params": (m.get("details") or {}).get("parameter_size")} for m in tags.get("models") or []]


def test(url, model):
    t0 = time.time()
    ms = models(url)
    names = [m["name"] for m in ms]
    out = {"ok": True, "url": base(url), "models": ms, "tags_ms": int((time.time() - t0) * 1000)}
    try:
        out["version"] = json.loads(request(url, "/api/version", timeout=10).read().decode()).get("version")
    except Fatal:
        pass
    if model:
        out["model_found"] = model in names or (model + ":latest") in names
        if out["model_found"]:
            t1 = time.time()
            r = json.loads(request(url, "/api/chat", {
                "model": model, "stream": False, "options": {"num_predict": 8},
                "messages": [{"role": "user", "content": "Sadece 'hazir' yaz."}]}, timeout=240).read().decode())
            out["reply"] = (r.get("message") or {}).get("content", "")[:200]
            out["chat_ms"] = int((time.time() - t1) * 1000)
    return out


def chat_stream(url, model, system_prompt, messages, temperature=0.2, num_ctx=16384):
    """Yields dicts: {"delta": str} ... {"done": True, "stats": {...}}"""
    payload = {"model": model, "stream": True,
               "messages": [{"role": "system", "content": system_prompt}] + messages[-30:],
               "options": {"temperature": float(temperature), "num_ctx": int(num_ctx)}}
    r = request(url, "/api/chat", payload, timeout=900)
    try:
        for raw in r:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("error"):
                yield {"error": d["error"]}
                return
            out = {"delta": (d.get("message") or {}).get("content", "")}
            if d.get("done"):
                out["done"] = True
                out["stats"] = {k: d.get(k) for k in ("total_duration", "eval_count", "prompt_eval_count")}
            yield out
    finally:
        r.close()
