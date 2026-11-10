"""Sink catalog (machine-readable form of ai/skills/sink-catalog.md)."""
import re

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# id -> (cwe, severity, {language: [regex, ...]}); "*" applies to every language
SINKS = {
    "cmd": ("CWE-78", "critical", {
        "python": [r"\bos\.(system|popen|exec\w*|spawn\w*)\s*\(", r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True", r"\bcommands\.getoutput\("],
        "javascript": [r"\bchild_process\b", r"\b(exec|execSync|spawn|spawnSync|execFile)\s*\("],
        "php": [r"\b(exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(", r"`[^`]*\$"],
        "java": [r"Runtime\.getRuntime\(\)\.exec\(", r"new\s+ProcessBuilder\("],
        "go": [r"exec\.Command\("],
        "ruby": [r"\b(system|exec|spawn|%x)\b", r"`[^`]*#\{"],
        "csharp": [r"Process\.Start\("],
    }),
    "code": ("CWE-94", "critical", {
        "python": [r"(?<![\w.])(eval|exec|compile)\s*\("],
        "javascript": [r"(?<![\w.])eval\s*\(", r"new\s+Function\s*\(", r"\bvm\.runIn\w+\(", r"setTimeout\s*\(\s*['\"`]"],
        "php": [r"\b(eval|assert|create_function)\s*\(", r"preg_replace\s*\([^)]*/e['\"]"],
        "java": [r"ScriptEngine\w*\.eval\("],
        "ruby": [r"\b(eval|instance_eval|class_eval)\b"],
    }),
    "sql": ("CWE-89", "high", {
        "python": [r"\.execute(many)?\s*\(\s*(f['\"]|['\"][^'\"]*['\"]\s*(%|\+|\.format))", r"\.execute\s*\(\s*\w+\s*\)", r"\.raw\s*\(", r"text\s*\(\s*f['\"]"],
        "javascript": [r"\.(query|raw|execute)\s*\(\s*(`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)", r"sequelize\.query\(", r"knex\.raw\("],
        "php": [r"\b(mysqli?_query|pg_query|sqlite_query)\s*\(", r"->(query|exec)\s*\(\s*['\"][^'\"]*\$", r"->(query|exec)\s*\([^)]*\.\s*\$"],
        "java": [r"\.(executeQuery|executeUpdate|execute)\s*\(\s*\"[^\"]*\"\s*\+", r"createStatement\(\)", r"createQuery\s*\(\s*\"[^\"]*\"\s*\+"],
        "go": [r"\.(Query|Exec|QueryRow)\s*\(\s*(fmt\.Sprintf|\"[^\"]*\"\s*\+)"],
        "ruby": [r"\.(where|find_by_sql|execute)\s*\(\s*\"[^\"]*#\{"],
        "csharp": [r"new\s+SqlCommand\s*\(\s*\"[^\"]*\"\s*\+", r"\.(ExecuteSqlRaw|FromSqlRaw)\("],
    }),
    "nosql": ("CWE-943", "high", {
        "javascript": [r"\$where", r"\.find(One)?\s*\(\s*req\.(body|query|params)", r"\.find(One)?\s*\(\s*JSON\.parse"],
        "python": [r"\$where", r"\.find(_one)?\s*\(\s*(request|json\.loads)"],
    }),
    "deser": ("CWE-502", "critical", {
        "python": [r"\bpickle\.loads?\(", r"\bcPickle\.loads?\(", r"\byaml\.load\s*\((?![^)]*SafeLoader)", r"\bmarshal\.loads?\(", r"\bjsonpickle\.decode\("],
        "javascript": [r"node-serialize|\.unserialize\s*\(", r"\bserialize-javascript\b"],
        "php": [r"\bunserialize\s*\("],
        "java": [r"\.readObject\s*\(", r"XMLDecoder", r"ObjectInputStream"],
        "ruby": [r"Marshal\.load", r"YAML\.load\b"],
        "csharp": [r"BinaryFormatter", r"\.Deserialize\("],
    }),
    "path": ("CWE-22", "high", {
        "python": [r"(?<![\w.])open\s*\(\s*(?!['\"])", r"\bsend_(file|from_directory)\s*\(", r"os\.path\.join\([^)]*(request|param|arg)"],
        "javascript": [r"\bfs\.(readFile|readFileSync|createReadStream|writeFile|unlink)\w*\s*\(\s*(?!['\"])", r"res\.(sendFile|download)\s*\("],
        "php": [r"\b(include|require)(_once)?\s*\(?\s*\$", r"\b(fopen|file_get_contents|readfile|file|unlink)\s*\(\s*\$"],
        "java": [r"new\s+File(InputStream|OutputStream)?\s*\([^)]*\+", r"Paths\.get\("],
        "go": [r"os\.(Open|ReadFile)\(", r"ioutil\.ReadFile\("],
    }),
    "ssrf": ("CWE-918", "high", {
        "python": [r"\brequests\.(get|post|put|request)\s*\(\s*(?!['\"])", r"\burllib\d?\.\w*urlopen\s*\(\s*(?!['\"])", r"httpx\.\w+\s*\(\s*(?!['\"])"],
        "javascript": [r"\b(fetch|axios(\.\w+)?|got|request|needle)\s*\(\s*(?!['\"`])"],
        "php": [r"\bcurl_setopt\s*\([^)]*CURLOPT_URL", r"\bfile_get_contents\s*\(\s*\$"],
        "java": [r"new\s+URL\s*\(\s*(?!\")", r"RestTemplate\w*\.(get|post)"],
        "go": [r"http\.(Get|Post)\(\s*(?!\")"],
    }),
    "xss": ("CWE-79", "medium", {
        "python": [r"render_template_string\s*\(", r"\bMarkup\s*\(", r"\|\s*safe\b", r"make_response\s*\([^)]*\+"],
        "javascript": [r"\.innerHTML\s*=", r"dangerouslySetInnerHTML", r"res\.send\s*\(\s*[^)]*(req\.|\+)", r"document\.write\s*\("],
        "php": [r"\becho\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)", r"\bprint\s+[^;]*\$_(GET|POST|REQUEST)"],
        "java": [r"getWriter\(\)\.(print|write)\w*\("],
    }),
    "redirect": ("CWE-601", "medium", {
        "python": [r"\bredirect\s*\(\s*(request|[a-z_]+\s*\))"],
        "javascript": [r"res\.redirect\s*\(\s*req\."],
        "php": [r"header\s*\(\s*['\"]Location:\s*['\"]?\s*\.\s*\$"],
        "java": [r"sendRedirect\s*\("],
    }),
    "xxe": ("CWE-611", "high", {
        "python": [r"etree\.(parse|fromstring|XML)\s*\(", r"xml\.dom\.minidom\.parse", r"XMLParser\([^)]*resolve_entities\s*=\s*True"],
        "php": [r"simplexml_load_string|DOMDocument.*loadXML|LIBXML_NOENT"],
        "java": [r"DocumentBuilderFactory\.newInstance\(\)", r"SAXParserFactory\.newInstance\(\)", r"XMLInputFactory"],
        "javascript": [r"libxmljs.*noent\s*:\s*true"],
    }),
    "ldap": ("CWE-90", "high", {
        "*": [r"\.search(_s)?\s*\([^)]*(\+|%|format|\$\{)"],
    }),
    "crypto": ("CWE-327", "low", {
        "*": [r"\b(md5|sha1)\s*\(", r"hashlib\.(md5|sha1)\(", r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", r"\bDES\b|/ECB/", r"Math\.random\(\)"],
    }),
    "secret": ("CWE-798", "medium", {
        "*": [r"(password|passwd|pwd|secret|api_?key|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]", r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"],
    }),
}

_COMPILED = {}


def compiled(lang):
    if lang not in _COMPILED:
        out = []
        for sid, (cwe, sev, by_lang) in SINKS.items():
            for rx in by_lang.get(lang, []) + by_lang.get("*", []):
                out.append((sid, cwe, sev, re.compile(rx, re.I)))
        _COMPILED[lang] = out
    return _COMPILED[lang]


def scan_lines(lang, lines, offset=1):
    """lines: list of str; returns [{sink, cwe, severity, line, text}]"""
    hits = []
    pats = compiled(lang)
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith(("#", "//", "*", "/*")):
            continue
        for sid, cwe, sev, rx in pats:
            if rx.search(line):
                hits.append({"sink": sid, "cwe": cwe, "severity": sev, "line": i + offset, "text": s[:200]})
    return hits
