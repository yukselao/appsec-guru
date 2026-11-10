"""Reads ai/agents, ai/skills and ai/tools Markdown files (front matter + body)."""
import json
import os

AI_DIR = os.environ.get("AI_DIR", "/ai")


def _parse(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    meta, body = {}, text
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end > 0:
            for line in text[3:end].strip().splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                v = v.strip()
                if v[:1] in "[{":
                    try:
                        v = json.loads(v)
                    except ValueError:
                        pass
                elif v.lower() in ("true", "false"):
                    v = v.lower() == "true"
                else:
                    try:
                        v = int(v) if v.isdigit() else float(v) if v.replace(".", "", 1).isdigit() else v
                    except ValueError:
                        pass
                meta[k.strip()] = v
            body = text[end + 4:].lstrip("\n")
    return meta, body


def _load(kind, name):
    path = os.path.join(AI_DIR, kind, name + ".md")
    if not os.path.isfile(path):
        raise FileNotFoundError("{}/{} tanımı yok: {}".format(kind, name, path))
    meta, body = _parse(path)
    meta.setdefault("name", name)
    meta["body"] = body
    return meta


def agent(name):
    return _load("agents", name)


def skill(name):
    return _load("skills", name)


def tool(name):
    return _load("tools", name)


def catalog():
    out = {}
    for kind in ("agents", "skills", "tools"):
        d = os.path.join(AI_DIR, kind)
        items = []
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith(".md"):
                    meta, body = _parse(os.path.join(d, f))
                    items.append({"name": meta.get("name", f[:-3]), "title": meta.get("title"),
                                  "description": meta.get("description"), "file": "ai/{}/{}".format(kind, f),
                                  "meta": {k: v for k, v in meta.items() if k not in ("name", "title", "description")}})
        out[kind] = items
    return out


def ollama_tools(names):
    """Tool specs for Ollama /api/chat from ai/tools/*.md front matter."""
    specs = []
    for n in names:
        t = tool(n)
        specs.append({"type": "function", "function": {
            "name": t["name"], "description": t.get("description", ""),
            "parameters": t.get("parameters") or {"type": "object", "properties": {}}}})
    return specs


def system_prompt(agent_name):
    a = agent(agent_name)
    parts = [a["body"]]
    for s in a.get("skills") or []:
        try:
            parts.append("\n\n# Skill reference: {}\n{}".format(s, skill(s)["body"]))
        except FileNotFoundError:
            pass
    return "\n".join(parts), a
