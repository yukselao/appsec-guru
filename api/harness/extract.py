"""function-extraction skill: functions, parameters, line ranges, calls, sinks."""
import ast
import os
import re

from .sinks import scan_lines

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".php": "php", ".java": "java", ".go": "go", ".rb": "ruby",
    ".cs": "csharp", ".kt": "java",
}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv",
             "site-packages", "bower_components", ".next", "coverage", "out", "third_party"}
TEST_RX = re.compile(r"(^|/)(tests?|spec|__tests__|e2e|cypress)(/|$)|(_test|\.test|\.spec|Test)\.\w+$")
CALL_RX = re.compile(r"\b([A-Za-z_][\w.]*)\s*\(")
KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "elif", "and", "or", "not", "print",
            "new", "typeof", "await", "sizeof", "def", "class", "with", "lambda", "isset", "empty", "array", "list"}
MAX_FILE_BYTES = 600_000


def language_of(path):
    return LANG_BY_EXT.get(os.path.splitext(path)[1].lower())


def list_files(root, include_tests=False):
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".")]
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root)
            lang = language_of(f)
            if not lang or f.endswith((".min.js", ".bundle.js", ".d.ts")):
                continue
            if not include_tests and TEST_RX.search(rel):
                continue
            try:
                if os.path.getsize(p) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            out.append({"path": rel, "language": lang})
    return sorted(out, key=lambda x: x["path"])


def _calls(lines):
    names = set()
    for l in lines:
        for m in CALL_RX.finditer(l):
            n = m.group(1)
            if n.split(".")[-1] not in KEYWORDS:
                names.add(n)
    return sorted(names)[:80]


def _python(rel, src, lines):
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    out = []

    def visit(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, ast.ClassDef):
                visit(ch, prefix + ch.name + ".")
            elif isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = ch.args
                params = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
                if a.vararg:
                    params.append("*" + a.vararg.arg)
                if a.kwarg:
                    params.append("**" + a.kwarg.arg)
                params = [p for p in params if p not in ("self", "cls")]
                start = min([d.lineno for d in ch.decorator_list] + [ch.lineno])
                end = getattr(ch, "end_lineno", ch.lineno)
                decos = [lines[d.lineno - 1].strip() for d in ch.decorator_list]
                route = next((d for d in decos if re.search(r"\.(route|get|post|put|delete|patch|api_route)\(", d)), None)
                out.append({"name": prefix + ch.name, "params": params, "start_line": start, "end_line": end,
                            "decorators": decos, "route": route})
                visit(ch, prefix + ch.name + ".")
    visit(tree, "")
    return out


SIG = {
    "javascript": [
        re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*)?\(([^)]*)\)\s*(?:=>)?"),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>"),
        re.compile(r"^\s*(?:public|private|protected|static|async|\s)*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::\s*[\w<>\[\]|, ]+)?\s*\{"),
        re.compile(r"""^\s*(?:app|router|server|api)\.(get|post|put|delete|patch|all|use)\s*\(\s*['"`]([^'"`]+)['"`]\s*,.*?(?:async\s*)?(?:function\s*\w*)?\s*\(([^)]*)\)"""),
    ],
    "php": [re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?\s*([A-Za-z_]\w*)\s*\(([^)]*)\)")],
    "java": [re.compile(r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)+[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")],
    "csharp": [re.compile(r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|async|virtual|override)\s+)+[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")],
    "go": [re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)")],
    "ruby": [re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_]\w*[?!]?)\s*(?:\(([^)]*)\)|\s+([^#\n]+))?")],
}
CTRL = {"if", "for", "while", "switch", "catch", "function", "return", "else", "do", "try", "with"}


def _params(raw, lang):
    out = []
    for p in (raw or "").split(","):
        p = re.sub(r"=.*$", "", p).strip()
        if not p:
            continue
        if lang in ("java", "csharp", "go"):
            toks = p.replace("...", " ").split()
            name = toks[-1] if lang != "go" else toks[0]
        elif lang == "php":
            m = re.search(r"\$(\w+)", p)
            name = m.group(1) if m else p
        else:
            name = re.sub(r"[:?].*$", "", p).strip(" {}[].*&")
        name = name.strip("*&")
        if name and name not in ("self", "this", "cls"):
            out.append(name)
    return out


def _block_end(lines, i, lang):
    if lang == "ruby":
        depth = 0
        for j in range(i, len(lines)):
            s = lines[j].strip()
            if re.match(r"^(def|class|module|if|unless|case|while|until|begin|for)\b", s) or re.search(r"\bdo(\s*\|[^|]*\|)?\s*$", s):
                depth += 1
            if re.match(r"^end\b", s):
                depth -= 1
                if depth <= 0:
                    return j + 1
        return len(lines)
    depth, started = 0, False
    for j in range(i, min(len(lines), i + 1500)):
        line = re.sub(r"(\"(\\.|[^\"\\])*\"|'(\\.|[^'\\])*'|`[^`]*`)", "", lines[j])
        line = re.sub(r"//.*$", "", line)
        for ch in line:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth <= 0:
                    return j + 1
        if not started and j > i + 3:
            return i + 1  # declaration without body (interface, arrow expression)
    return min(len(lines), i + 200)


def _generic(rel, lang, lines):
    out = []
    for i, line in enumerate(lines):
        for rx in SIG.get(lang, []):
            m = rx.match(line)
            if not m:
                continue
            g = m.groups()
            if lang == "javascript" and len(g) == 3:  # route registration
                name = "{} {}".format(g[0].upper(), g[1])
                params = _params(g[2], lang)
                route = line.strip()
            else:
                name = g[0]
                if name in CTRL:
                    continue
                raw = g[1] if len(g) > 1 else ""
                if lang == "ruby" and len(g) > 2 and g[2]:
                    raw = g[2]
                params = _params(raw, lang)
                route = line.strip() if re.search(r"@(Get|Post|Put|Delete|Request)Mapping|\[Http(Get|Post)|Route::", "".join(lines[max(0, i - 3):i + 1])) else None
            end = _block_end(lines, i, lang)
            out.append({"name": name, "params": params, "start_line": i + 1, "end_line": max(end, i + 1),
                        "decorators": [], "route": route})
            break
    return out


def extract(root, rel):
    path = os.path.join(root, rel)
    lang = language_of(rel)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return []
    lines = src.splitlines()
    funcs = _python(rel, src, lines) if lang == "python" else _generic(rel, lang, lines)
    for f in funcs:
        body = lines[f["start_line"] - 1:f["end_line"]]
        f["file"] = rel
        f["language"] = lang
        f["sinks"] = scan_lines(lang, body, offset=f["start_line"])
        f["calls"] = _calls(body)
    return funcs


def numbered(root, rel, start, end):
    with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    start = max(1, int(start or 1))
    end = min(len(lines), int(end or start + 120))
    return "\n".join("{:5d}  {}".format(i, lines[i - 1]) for i in range(start, end + 1)), len(lines)
