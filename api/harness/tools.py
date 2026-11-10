"""Tool implementations. Contracts (description, JSON schema) are in ai/tools/*.md."""
import fnmatch
import os
import re
import subprocess
import urllib.parse

from . import extract as ex

MAX_SEARCH = 60


class ToolContext(object):
    """Per-run state handed to every tool."""

    def __init__(self, run_id, workdir, report_cb, index=None):
        self.run_id = run_id
        self.workdir = workdir
        self.root = os.path.join(workdir, "repo")
        self.report_cb = report_cb
        self.index = index or {}  # function name -> [function dict]
        self.finished = None

    def safe(self, rel):
        p = os.path.realpath(os.path.join(self.root, rel or ""))
        if not p.startswith(os.path.realpath(self.root)):
            raise ValueError("path outside repository: {}".format(rel))
        return p


def repo_clone(ctx, url, ref="", token=""):
    url = url.strip()
    if not re.match(r"^https://[\w.-]+/[\w./-]+$", url):
        raise ValueError("https GitHub/GitLab URL bekleniyor")
    url = re.sub(r"/(tree|-/tree)/.*$", "", url).rstrip("/")
    if not url.endswith(".git"):
        url += ".git"
    clone_url = url
    if token:
        p = urllib.parse.urlsplit(url)
        clone_url = urllib.parse.urlunsplit((p.scheme, "oauth2:{}@{}".format(token, p.netloc), p.path, "", ""))
    os.makedirs(ctx.workdir, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [clone_url, ctx.root]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).replace(token, "***") if token else (r.stderr or r.stdout)
        raise RuntimeError("git clone başarısız: " + msg.strip()[-400:])
    commit = subprocess.run(["git", "-C", ctx.root, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    return {"url": url, "commit": commit}


def list_files(ctx, include_tests=False):
    return ex.list_files(ctx.root, include_tests=include_tests)


def extract_functions(ctx, path):
    ctx.safe(path)
    return ex.extract(ctx.root, path)


def get_function(ctx, name, path=""):
    short = name.split(".")[-1]
    cands = ctx.index.get(name) or ctx.index.get(short) or []
    if path:
        cands = [c for c in cands if c["file"] == path] or cands
    if not cands:
        return {"found": False, "hint": "not in the function index; try search_code"}
    out = []
    for c in cands[:3]:
        code, _ = ex.numbered(ctx.root, c["file"], c["start_line"], min(c["end_line"], c["start_line"] + 160))
        out.append({"file": c["file"], "name": c["name"], "params": c["params"], "start_line": c["start_line"],
                    "end_line": c["end_line"], "route": c.get("route"), "code": code})
    return {"found": True, "matches": out}


def read_file(ctx, path, start=1, end=None):
    ctx.safe(path)
    start = int(start or 1)
    end = int(end or start + 120)
    end = min(end, start + 200)
    code, total = ex.numbered(ctx.root, path, start, end)
    return {"path": path, "start": start, "end": min(end, total), "total_lines": total, "code": code}


def search_code(ctx, pattern, glob=""):
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return {"error": "invalid regex: {}".format(exc)}
    hits = []
    for d, dirs, files in os.walk(ctx.root):
        dirs[:] = [x for x in dirs if x not in ex.SKIP_DIRS and not x.startswith(".")]
        for f in files:
            if glob and not fnmatch.fnmatch(f, glob):
                continue
            if not ex.language_of(f) and not f.endswith((".html", ".twig", ".jinja", ".ejs", ".yml", ".yaml", ".json", ".xml")):
                continue
            p = os.path.join(d, f)
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if rx.search(line):
                            hits.append("{}:{}:{}".format(os.path.relpath(p, ctx.root), i, line.strip()[:200]))
                            if len(hits) >= MAX_SEARCH:
                                return {"matches": hits, "truncated": True}
            except OSError:
                continue
    return {"matches": hits, "truncated": False}


def report_finding(ctx, **f):
    return ctx.report_cb(f)


def finish(ctx, verdict="unsure", summary=""):
    ctx.finished = {"verdict": verdict, "summary": summary}
    return {"ok": True}


REGISTRY = {
    "repo_clone": repo_clone, "list_files": list_files, "extract_functions": extract_functions,
    "get_function": get_function, "read_file": read_file, "search_code": search_code,
    "report_finding": report_finding, "finish": finish,
}


def call(ctx, name, args):
    fn = REGISTRY.get(name)
    if not fn:
        return {"error": "unknown tool {}".format(name)}
    try:
        return fn(ctx, **(args or {}))
    except TypeError as exc:
        return {"error": "bad arguments: {}".format(exc)}
    except (ValueError, OSError, RuntimeError) as exc:
        return {"error": str(exc)}
