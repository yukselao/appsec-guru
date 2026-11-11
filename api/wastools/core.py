# ---------------------------------------------------------------------------
# core: SC REST client, SSH runner, WAS host helpers, output helpers.
# Shared with the single-file CLI tools in ../../src (same code, tested on sc4).
# Python 3.6 compatible. Standard library only (no third-party modules).
# ---------------------------------------------------------------------------
import argparse
import atexit
import datetime
import getpass
import json
import os
import pty
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

import ssl
import urllib.error
import urllib.parse
import urllib.request

ENV_PREFIX = "TSC_"
RUN_PREFIX = "tscdbg-"
WAS_SERVICE = "nessus-was-scanner"
DROPIN_DIR = "/etc/systemd/system/nessus-was-scanner.service.d"
DROPIN_FILE = DROPIN_DIR + "/tscdbg-debug.conf"
WAS_TEMPLATE_ID = "40"

# Known WAS families (Tenable.sc 6.9.1 plugins.db). Used when the API does not
# expose WAS families; ids are stable across feeds.
KNOWN_WAS_FAMILIES = [
    ("2000001", "Authentication & Session"),
    ("2000002", "Code Execution"),
    ("2000003", "Component Vulnerability"),
    ("2000004", "Cross Site Scripting"),
    ("2000005", "Cross Site Request Forgery"),
    ("2000006", "Data Exposure"),
    ("2000007", "File Inclusion"),
    ("2000008", "General"),
    ("2000009", "Injection"),
    ("2000010", "SSL/TLS"),
    ("2000011", "HTTP Security Header"),
    ("2000012", "Web Applications"),
    ("2000013", "Web Servers"),
    ("2000014", "Artificial Intelligence"),
]

FAST_PREFS = {
    "was[scope]page_limit": "150",
    "was[scope]directory_depth_limit": "4",
    "was[scope]dom_depth_limit": "3",
    "was_timeout": "00:45:00",
    "was[http]request_concurrency": "10",
    "was[assessment][bruteforce]enable": "no",
}

IMPORTANT_PREFS = [
    "was_timeout", "was_debug_mode", "was[debug_config]",
    "was[scope]option", "was[scope]page_limit", "was[scope]directory_depth_limit",
    "was[scope]dom_depth_limit", "was[scope]exclude_path_patterns",
    "was[assessment]enable", "was[assessment][bruteforce]enable", "was[assessment]dictionary",
    "was[http]request_concurrency", "was[http]request_timeout",
    "was[plugin][rate_limiter]requests_per_second", "was[plugin][rate_limiter]autothrottle",
]
SECRET_PREF_RE = re.compile(r"(password|secret|token|cookie|session|credential|key)", re.I)

FINAL_STATES = {"completed", "error", "stopped", "partial", "aborted", "failed", "canceled", "cancelled"}


# ----------------------------- output helpers ------------------------------
class C(object):
    on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET = "\033[0m" if on else ""
    DIM = "\033[2m" if on else ""
    BOLD = "\033[1m" if on else ""
    RED = "\033[31m" if on else ""
    GREEN = "\033[32m" if on else ""
    YELLOW = "\033[33m" if on else ""
    BLUE = "\033[34m" if on else ""
    CYAN = "\033[36m" if on else ""


_OUT = threading.local()


class Fatal(Exception):
    """Raised by die(); the API turns it into a 400 with the message.
    (The CLI copy in ../../src derives from SystemExit instead.)"""

    def __init__(self, msg, code=1):
        Exception.__init__(self, msg)
        self.msg = msg
        self.code = code


def set_output_sink(fn):
    """Route info/ok/warn/err of the current thread to fn(level, msg)."""
    _OUT.sink = fn


def _emit(level, prefix, color, msg, stream=None):
    sink = getattr(_OUT, "sink", None)
    if sink:
        sink(level, msg)
        return
    stream = stream or sys.stdout
    stream.write("{}{}{} {}\n".format(color, prefix, C.RESET, msg))
    stream.flush()


def info(msg):
    _emit("info", "[*]", C.CYAN, msg)


def ok(msg):
    _emit("ok", "[+]", C.GREEN, msg)


def warn(msg):
    _emit("warn", "[!]", C.YELLOW, msg)


def err(msg):
    _emit("error", "[x]", C.RED, msg, sys.stderr)


def die(msg, code=1):
    if not getattr(_OUT, "sink", None):
        err(msg)
    raise Fatal(msg, code)


def color_log_line(line):
    if not C.on:
        return line
    if "[ERROR]" in line or "[FATAL]" in line:
        return C.RED + line + C.RESET
    if "[WARN]" in line:
        return C.YELLOW + line + C.RESET
    if "[DEBUG]" in line or "[TRACE]" in line:
        return C.DIM + line + C.RESET
    if "[NOTICE]" in line:
        return C.BLUE + line + C.RESET
    return line


def table(rows, headers):
    rows = [[("" if v is None else str(v)) for v in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, v in enumerate(r):
            widths[i] = min(max(widths[i], len(v)), 60)
    fmt = "  ".join("{:<%d}" % w for w in widths)
    print(C.BOLD + fmt.format(*headers) + C.RESET)
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt.format(*[v[:60] for v in r]))
    if not rows:
        print(C.DIM + "(kayit yok)" + C.RESET)


def ts_human(ts):
    try:
        ts = int(ts)
        if ts <= 0:
            return ""
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return ""


def now_stamp():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def confirm(question, assume_yes=False):
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        warn("etkilesimsiz calisma, '{}' sorusu HAYIR kabul edildi (--yes ile gec)".format(question))
        return False
    try:
        ans = input("{} [y/N] ".format(question)).strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes", "e", "evet")


# --------------------------------- audit -----------------------------------
class Audit(object):
    def __init__(self, base_dir):
        self.path = os.path.join(base_dir, "audit.jsonl")
        self.base_dir = base_dir

    def write(self, action, **fields):
        try:
            if not os.path.isdir(self.base_dir):
                os.makedirs(self.base_dir)
            rec = {"time": datetime.datetime.now().isoformat(),
                   "local_user": getpass.getuser(), "action": action}
            rec.update(fields)
            with open(self.path, "a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        except Exception as exc:  # audit must never break the tool
            warn("audit yazilamadi: {}".format(exc))


# ------------------------------ SC REST client ------------------------------
class SCError(Exception):
    pass


class SCPending(SCError):
    pass


class SC(object):
    def __init__(self, url, access_key, secret_key, verify=False, timeout=60):
        if not url:
            die("SC adresi yok: --sc veya dosyadaki SC_URL")
        if not url.startswith("http"):
            url = "https://" + url
        self.base = url.rstrip("/")
        if not self.base.endswith("/rest"):
            self.base += "/rest"
        if not access_key or not secret_key:
            die("SC API anahtari yok. Dosyanin ustundeki SC_ACCESS_KEY / SC_SECRET_KEY'i doldur "
                "ya da TSC_ACCESS_KEY / TSC_SECRET_KEY env veya --access-key/--secret-key ver.")
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-APIKey": "accesskey={}; secretkey={};".format(access_key, secret_key),
        }
        self.timeout = timeout

    def call(self, method, path, params=None, body=None, raw=False):
        url = self.base + "/" + path.lstrip("/")
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.headers, method=method)
        try:
            r = urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)
            status = r.status
        except urllib.error.HTTPError as exc:
            r, status = exc, exc.code
        except (urllib.error.URLError, OSError) as exc:
            raise SCError("{} {} baglanti hatasi: {}".format(method, path, exc))
        if raw:
            if status == 202:
                raise SCPending("{} {} HTTP 202 (SC dosyayi hazirliyor)".format(method, path))
            if status != 200:
                raise SCError("{} {} HTTP {}".format(method, path, status))
            return r
        text = r.read().decode("utf-8", "replace")
        try:
            data = json.loads(text)
        except ValueError:
            raise SCError("{} {} HTTP {} JSON olmayan yanit: {}".format(method, path, status, text[:300]))
        code = data.get("error_code", 0)
        if status >= 400 or code:
            raise SCError("{} {} HTTP {} error_code={} {}".format(
                method, path, status, code, data.get("error_msg", "")).strip())
        for w in data.get("warnings") or []:
            warn("SC uyarisi: {}".format(w))
        return data.get("response")

    def get(self, path, **params):
        return self.call("GET", path, params=params or None)

    def post(self, path, body=None):
        return self.call("POST", path, body=body if body is not None else {})

    def patch(self, path, body):
        return self.call("PATCH", path, body=body)

    def delete(self, path):
        return self.call("DELETE", path)

    # ---- generic list helper (SC returns {usable:[], manageable:[]} or a list)
    @staticmethod
    def as_list(resp):
        if resp is None:
            return []
        if isinstance(resp, list):
            return resp
        if isinstance(resp, dict):
            seen, out = set(), []
            for key in ("usable", "manageable", "results"):
                for item in resp.get(key) or []:
                    k = str(item.get("id")) if isinstance(item, dict) else str(item)
                    if k not in seen:
                        seen.add(k)
                        out.append(item)
            return out
        return []

    # ---- reference data
    def system(self):
        return self.get("system")

    def zones(self):
        return self.as_list(self.get("zone", fields="id,name,description"))

    def repositories(self):
        return self.as_list(self.get("repository", fields="id,name,type,dataFormat"))

    def credentials(self):
        return self.as_list(self.get("credential", filter="usable", fields="id,name,type,authType"))

    def report_definitions(self):
        return self.as_list(self.get("reportDefinition", fields="id,name,type"))

    def was_scanners(self):
        try:
            return self.as_list(self.get(
                "wasScanner", fields="id,name,description,status,statusMessage,version,enabled,"
                                      "pluginSet,lastCheckinTime,linkedOn"))
        except SCError as exc:
            if "error_code=163" in str(exc) or "administrator" in str(exc).lower():
                info("WAS scanner listesi yalniz SC yoneticisine acik; bu API anahtari ile scanner durumu gorulemez")
                return None
            warn("wasScanner uc noktasi: {} -> scanner listesinde wasCapable araniyor".format(exc))
            rows = self.as_list(self.get(
                "scanner", fields="id,name,ip,status,version,wasCapable,enabled"))
            return [r for r in rows if str(r.get("wasCapable")).lower() == "true"]

    def was_families(self):
        try:
            rows = self.as_list(self.get("pluginFamily", fields="id,name,type,count"))
            fam = [(str(r.get("id")), r.get("name"), r.get("count"))
                   for r in rows if str(r.get("type", "")).lower() == "was"
                   or str(r.get("id", "")).startswith("2000")]
            if fam:
                return fam
        except SCError as exc:
            warn("pluginFamily okunamadi ({}), bilinen liste kullaniliyor".format(exc))
        return [(i, n, None) for i, n in KNOWN_WAS_FAMILIES]

    # ---- policies
    def policies(self):
        rows = self.as_list(self.get(
            "policy", fields="id,name,description,policyTemplate,modifiedTime,owner,canUse,canManage"))
        out = []
        for r in rows:
            tpl = r.get("policyTemplate") or {}
            if str(tpl.get("id")) == WAS_TEMPLATE_ID or "web app" in str(tpl.get("name", "")).lower():
                out.append(r)
        return out

    def policy(self, pid, fields=None):
        fields = fields or ("id,name,description,policyTemplate,families,preferences,"
                            "modifiedTime,createdTime,owner,context,isWas")
        return self.get("policy/{}".format(pid), fields=fields)

    def resolve_policy(self, ref):
        if str(ref).isdigit():
            return str(ref)
        matches = [p for p in self.policies() if p.get("name") == ref]
        if not matches:
            die("politika bulunamadi: {}".format(ref))
        if len(matches) > 1:
            die("ayni adla birden fazla politika: {}".format([m.get("id") for m in matches]))
        return str(matches[0]["id"])

    # ---- scans / results
    def was_scans(self):
        return self.as_list(self.get(
            "wasScan", fields="id,uuid,name,description,status,policy,zone,repository,urlList,"
                              "createdTime,modifiedTime"))

    def scan_result(self, rid):
        return self.get("scanResult/{}".format(rid),
                        fields="id,name,status,running,progress,errorDetails,startTime,finishTime,"
                               "completedChecks,totalChecks,resultType,resultSource,jobID,"
                               "importStatus,importErrorDetails,downloadAvailable,"
                               "diagnosticAvailable,scanDuration,createdTime")

    def scan_results_recent(self, since_seconds=86400 * 2):
        start = int(time.time()) - since_seconds
        return self.as_list(self.get(
            "scanResult", startTime=str(start), timeCompareField="createdTime",
            fields="id,name,status,running,startTime,finishTime,completedChecks,totalChecks,"
                   "resultType,resultSource,jobID,createdTime,scanDuration"))


def family_ids_from_policy(pol):
    fams = pol.get("families")
    if fams is None:
        return None
    out = []
    for f in fams:
        if isinstance(f, dict):
            out.append(str(f.get("id")))
        else:
            out.append(str(f))
    return sorted(out)


def prefs_dict(pol):
    prefs = pol.get("preferences")
    if isinstance(prefs, dict):
        return prefs
    if isinstance(prefs, list):
        out = {}
        for p in prefs:
            if isinstance(p, dict) and "name" in p:
                out[p["name"]] = p.get("value")
        return out
    return {}


def resolve_families(sc, spec):
    """'Authentication & Session,Injection' or '2000001,2000009' -> [(id, name)]"""
    known = sc.was_families()
    by_name = dict((n.lower(), i) for i, n, _ in known)
    names = dict((i, n) for i, n, _ in known)
    out = []
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        if part.isdigit():
            out.append((part, names.get(part, "?")))
        elif part.lower() in by_name:
            out.append((by_name[part.lower()], part))
        else:
            die("bilinmeyen aile: '{}'. Gecerli: {}".format(part, ", ".join(n for _, n, _ in known)))
    return out


# ------------------------------ SSH runner ---------------------------------
class SSH(object):
    """Runs commands on a remote host.

    key      : ssh -o BatchMode=yes (default, uses ~/.ssh/config and agent)
    password : one ControlMaster connection is authenticated once, through
               sshpass -e when installed, otherwise by typing the password
               into a pseudo-terminal (stdlib pty; works where /tmp and /home
               are noexec, e.g. Tenable Core). Every later command reuses the
               master socket, so the password is entered only once and never
               written to disk, argv or logs.
    """

    def __init__(self, host, user="osadmin", port=22, password=None, key=None,
                 jump=None, jump_user=None, jump_password=None, connect_timeout=10):
        if not host:
            die("was adresi yok: --was")
        self.host = host
        self.user = user
        self.port = int(port or 22)
        self.password = password
        self.key = key
        self.jump = jump
        self.jump_user = jump_user or user
        self.jump_password = jump_password
        self.connect_timeout = connect_timeout
        self.ctl = None
        if password or jump_password:
            self.method = "sshpass" if (shutil.which("sshpass") and not jump_password) else "pty"
        else:
            self.method = "key"

    @property
    def label(self):
        j = " via {}@{}".format(self.jump_user, self.jump) if self.jump else ""
        return "{}@{}{} ({})".format(self.user, self.host, j, self.method)

    @property
    def target(self):
        return "{}@{}".format(self.user, self.host)

    def _common_opts(self):
        opts = ["-p", str(self.port),
                "-o", "ConnectTimeout={}".format(self.connect_timeout),
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ServerAliveInterval=30", "-o", "LogLevel=ERROR"]
        if self.key:
            opts += ["-i", self.key]
        if self.jump:
            opts += ["-J", "{}@{}".format(self.jump_user, self.jump)]
        return opts

    # ---- password: ControlMaster authenticated once
    def _ensure_master(self):
        if self.method == "key" or self.ctl:
            return
        d = tempfile.mkdtemp(prefix="tscdbg-")
        os.chmod(d, stat.S_IRWXU)
        ctl = os.path.join(d, "c")
        cmd = (["ssh", "-M", "-N", "-f", "-S", ctl, "-o", "ControlPersist=1800",
                "-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1",
                "-o", "PreferredAuthentications=publickey,keyboard-interactive,password"]
               + self._common_opts() + [self.target])
        if self.method == "sshpass":
            env = dict(os.environ)
            env["SSHPASS"] = self.password
            p = subprocess.Popen(["sshpass", "-e"] + cmd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            try:
                _, er = p.communicate(timeout=self.connect_timeout + 40)
            except subprocess.TimeoutExpired:
                p.kill()
                er = "zaman asimi"
            transcript = er or ""
        else:
            transcript = self._pty_auth(cmd)
        chk = subprocess.call(["ssh", "-S", ctl, "-O", "check", self.target],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if chk != 0:
            shutil.rmtree(d, ignore_errors=True)
            last = [l for l in transcript.replace("\r", "").splitlines() if l.strip()][-3:]
            die("ssh sifreli giris basarisiz [{}]: {}".format(self.label, " | ".join(last)[:300]))
        self.ctl = ctl
        atexit.register(self._close_master, d)

    def _pty_auth(self, cmd):
        pid, fd = pty.fork()
        if pid == 0:  # child
            try:
                os.execvp(cmd[0], cmd)
            finally:
                os._exit(127)
        transcript, buf, sent = "", "", 0
        deadline = time.time() + self.connect_timeout + 40
        done = False
        while not done and time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.5)
            if fd in r:
                try:
                    data = os.read(fd, 4096).decode("utf-8", "replace")
                except OSError:
                    data = ""
                if not data:
                    done = True
                else:
                    transcript += data
                    buf += data
                    tail = buf.strip().lower()
                    if "(yes/no" in tail:
                        os.write(fd, b"yes\n")
                        buf = ""
                    elif tail.endswith(":") and ("password" in tail[-120:] or "passcode" in tail[-120:]):
                        line = buf.strip().splitlines()[-1] if buf.strip() else ""
                        pw = self.password
                        if self.jump and self.jump_password and ("@" + self.jump) in line:
                            pw = self.jump_password
                        os.write(fd, ((pw or "") + "\n").encode("utf-8"))
                        buf = ""
                        sent += 1
                        if sent > 4:
                            done = True
            wpid, _ = os.waitpid(pid, os.WNOHANG)
            if wpid:
                done = True
        try:
            os.kill(pid, 0)
            if not done:
                os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        except (OSError, ChildProcessError):
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        return "\n".join(l for l in transcript.splitlines()
                         if not re.search(r"(password|passcode)[^:]*:\s*$", l.strip(), re.I))

    def _close_master(self, d):
        if self.ctl:
            subprocess.call(["ssh", "-S", self.ctl, "-O", "exit", self.target],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(d, ignore_errors=True)

    def _cmd(self, remote_cmd):
        if self.method == "key":
            return (["ssh", "-o", "BatchMode=yes"] + self._common_opts() + [self.target, "--", remote_cmd])
        self._ensure_master()
        return ["ssh", "-S", self.ctl, "-o", "ControlMaster=no", "-o", "BatchMode=yes",
                "-o", "LogLevel=ERROR", self.target, "--", remote_cmd]

    def _popen(self, remote_cmd, stdin=None, stdout=subprocess.PIPE):
        return subprocess.Popen(self._cmd(remote_cmd),
                                stdin=stdin if stdin is not None else subprocess.DEVNULL,
                                stdout=stdout, stderr=subprocess.PIPE, universal_newlines=True)

    def run(self, remote_cmd, input_text=None, timeout=60, check=False):
        p = self._popen(remote_cmd, stdin=subprocess.PIPE if input_text is not None else None)
        try:
            out, er = p.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, er = p.communicate()
            raise RuntimeError("ssh zaman asimi ({}s): {}".format(timeout, remote_cmd[:80]))
        er = "\n".join(l for l in (er or "").splitlines()
                       if not l.startswith("**") and "post-quantum" not in l
                       and "store now, decrypt later" not in l and "openssh.com/pq" not in l)
        if check and p.returncode != 0:
            raise RuntimeError("uzak komut basarisiz (rc={}) [{}]: {}".format(
                p.returncode, self.label, (er or out).strip()[:400]))
        return p.returncode, out, er

    def sudo(self, shell_cmd, timeout=90, check=True):
        """Run as root: sudo -n; with a password fall back to sudo -S (stdin)."""
        q = shlex.quote(shell_cmd)
        if self.password:
            remote = "sudo -n true 2>/dev/null && sudo -n sh -c {q} || sudo -S -p '' sh -c {q}".format(q=q)
            return self.run(remote, input_text=self.password + "\n", timeout=timeout, check=check)
        return self.run("sudo -n sh -c {}".format(q), timeout=timeout, check=check)

    def stream(self, remote_cmd):
        return self._popen(remote_cmd)

    def test(self):
        rc, out, er = self.run("hostname", timeout=self.connect_timeout + 30)
        if rc != 0:
            hint = " Anahtarla girilemiyorsa --was-password ile sifre ver." if self.method == "key" else ""
            die("ssh {} basarisiz: {}{}".format(self.label, (er or "").strip()[:300], hint))
        return out.strip()


# ------------------------------ WAS host ops -------------------------------
class WasHost(object):
    def __init__(self, ssh, log_path):
        self.ssh = ssh
        self.log = log_path

    def debug_status(self):
        rc, out, _ = self.ssh.run(
            "systemctl show {} -p Environment -p ActiveState -p MainPID; "
            "test -f {} && echo DROPIN=yes || echo DROPIN=no".format(WAS_SERVICE, DROPIN_FILE))
        d = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k] = v
        env = d.get("Environment", "")
        m = re.search(r"WAS_LOG_LEVEL=(\S+)", env)
        return {"level": m.group(1) if m else "info (varsayilan)",
                "dropin": d.get("DROPIN") == "yes",
                "active": d.get("ActiveState"),
                "pid": self.scanner_pid() or d.get("MainPID")}

    def scanner_pid(self):
        # systemd MainPID can read 0 after a restart (Type=forking without
        # PIDFile), so look at the process list directly.
        rc, out, _ = self.ssh.run("pgrep -u tiowas -f 'bin/scanner$' | head -1")
        return out.strip()

    def active_scan_processes(self):
        """Scan workers on the scanner host. A scan runs as a child of the
        scanner that renames itself 'scan_instance' and drives several
        chromedriver/chrome pairs. Each scan has a directory
        /opt/nessus-was-scanner/scans/<uuid> and tags its log lines with
        [scanUuid=<uuid>]."""
        sh = ("ps -u tiowas -o pid=,ppid=,etimes=,pcpu=,rss=,args= 2>/dev/null; echo '@@DIRS'; "
              "ls -1 --time-style=+%s -l /opt/nessus-was-scanner/scans 2>/dev/null | awk 'NF>=7{print $6, $7}'; "
              "echo '@@LOG'; tail -n 4000 " + shlex.quote(self.log) + " 2>/dev/null | "
              "grep -o '^[^ ]* \\[scanUuid=[0-9a-f-]*\\] \\[[A-Z]*\\].*' | "
              "awk '{u=$2; t[u]=$1; n[u]++; if (!(u in url) && match($0, /https?:\\/\\/[^\\/ ,)#]+/)) url[u]=substr($0, RSTART, RLENGTH)} "
              "END{for (u in t) print u, t[u], n[u], (u in url ? url[u] : \"-\")}'")
        rc, out, _ = self.ssh.run(sh, timeout=60)
        part = "ps"
        procs, chrome, drivers, dirs, logs = [], 0, 0, {}, {}
        for line in out.splitlines():
            if line == "@@DIRS":
                part = "dirs"
                continue
            if line == "@@LOG":
                part = "log"
                continue
            if part == "ps":
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                pid, ppid, et, cpu, rss, args = parts
                low = args.lower()
                if "chromedriver" in low:
                    drivers += 1
                elif "chrome" in low:
                    chrome += 1
                elif args.startswith("scan_instance") or re.search(r"(^|/|\s)bin/scan(\s|$)", args):
                    procs.append({"pid": pid, "ppid": ppid, "elapsed_s": int(et), "cpu": cpu,
                                  "rss_mb": int(rss) // 1024, "args": args[:60]})
            elif part == "dirs":
                bits = line.split()
                if len(bits) == 2 and re.match(r"^[0-9a-f-]{36}$", bits[1]):
                    dirs[bits[1]] = int(bits[0])
            else:
                bits = line.split()
                if len(bits) >= 4:
                    uuid = bits[0].replace("[scanUuid=", "").rstrip("]")
                    logs[uuid] = {"last_log": bits[1][:19], "lines_recent": int(bits[2]),
                                  "target": bits[3] if bits[3] != "-" else ""}
        scans = []
        for uuid in sorted(set(dirs) | set(logs)):
            d = {"uuid": uuid, "dir_mtime": dirs.get(uuid), "has_dir": uuid in dirs}
            d.update(logs.get(uuid, {"last_log": "", "lines_recent": 0, "target": ""}))
            scans.append(d)
        for p in procs:
            p["scans"] = [s["uuid"] for s in scans if s["has_dir"]]
        self.last_scans = scans
        self.last_drivers = drivers
        return procs, chrome

    def load(self):
        rc, out, _ = self.ssh.run("cat /proc/loadavg; free -m | awk '/Mem:/{print $2, $3}'; nproc")
        lines = out.split("\n")
        try:
            la = lines[0].split()[:3]
            tot, used = lines[1].split()
            return {"load": " ".join(la), "mem": "{}/{} MB".format(used, tot), "cpus": lines[2].strip()}
        except Exception:
            return {"load": "?", "mem": "?", "cpus": "?"}

    def set_debug(self, on, wait=True, audit=None):
        host = self.ssh.test()
        procs, _ = self.active_scan_processes()
        if procs:
            raise RuntimeError("{} uzerinde calisan {} tarama var; servis restart'i onlari keser. "
                               "Once bitmesini bekle.".format(host, len(procs)))
        old_pid = self.scanner_pid()
        if on:
            cmd = ("mkdir -p {d} && printf '[Service]\\nEnvironment=\"WAS_LOG_LEVEL=debug\"\\n' > {f} && "
                   "systemctl daemon-reload && systemctl restart {s}").format(d=DROPIN_DIR, f=DROPIN_FILE, s=WAS_SERVICE)
        else:
            cmd = "rm -f {f} && systemctl daemon-reload && systemctl restart {s}".format(f=DROPIN_FILE, s=WAS_SERVICE)
        info("{}: log seviyesi {} yapiliyor, {} yeniden baslatiliyor".format(
            host, "DEBUG" if on else "info", WAS_SERVICE))
        self.ssh.sudo(cmd, timeout=180)
        if audit:
            audit.write("was_debug_" + ("on" if on else "off"), host=host, target=self.ssh.label)
        if wait:
            self.wait_linked(old_pid)

    def wait_linked(self, old_pid=None, timeout=120):
        t0 = time.time()
        while time.time() - t0 < timeout:
            pid = self.scanner_pid()
            if pid and pid != "0" and pid != old_pid:
                rc, out, _ = self.ssh.run("tail -n 300 {} 2>/dev/null | grep -E 'linked to|polling' | tail -2".format(
                    shlex.quote(self.log)))
                if "linked to" in out or "polling" in out:
                    ok("scanner ayakta (pid {}), SC ile bagli".format(pid))
                    return True
            time.sleep(3)
        warn("scanner {} sn icinde 'linked' satiri yazmadi; log'u kontrol et".format(timeout))
        return False

    def tail_cmd(self, lines=0):
        return "tail -n {} -F {} 2>/dev/null".format(int(lines), shlex.quote(self.log))


class LogStreamer(threading.Thread):
    """Streams the remote scanner log to the terminal and an optional file."""

    def __init__(self, washost, out_path=None, line_filter=None, backlog=0, echo=True, on_line=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.washost = washost
        self.out_path = out_path
        self.filter = line_filter
        self.backlog = backlog
        self.echo = echo
        self.on_line = on_line
        self.proc = None
        self.counts = {"total": 0, "DEBUG": 0, "INFO": 0, "NOTICE": 0, "WARN": 0, "ERROR": 0}
        self._halt = threading.Event()

    def run(self):
        fh = open(self.out_path, "a") if self.out_path else None
        try:
            while not self._halt.is_set():
                self.proc = self.washost.ssh.stream(self.washost.tail_cmd(self.backlog))
                for line in iter(self.proc.stdout.readline, ""):
                    if self._halt.is_set():
                        break
                    line = line.rstrip("\n")
                    if self.filter and not self.filter(line):
                        continue
                    self.counts["total"] += 1
                    m = re.search(r"\[(DEBUG|INFO|NOTICE|WARN|ERROR|FATAL|TRACE)\]", line)
                    if m:
                        lvl = {"FATAL": "ERROR", "TRACE": "DEBUG"}.get(m.group(1), m.group(1))
                        self.counts[lvl] = self.counts.get(lvl, 0) + 1
                    if fh:
                        fh.write(line + "\n")
                        fh.flush()
                    if self.on_line:
                        self.on_line(line)
                    if self.echo:
                        print(color_log_line(line))
                        sys.stdout.flush()
                if self._halt.is_set():
                    break
                self.backlog = 0
                time.sleep(2)  # ssh dropped: reconnect
        finally:
            if fh:
                fh.close()

    def stop(self):
        self._halt.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass


def scan_status_line(res, t0):
    st = res.get("status")
    prog = res.get("progress") or {}
    extra = ""
    if isinstance(prog, dict):
        bits = []
        for sc_ in prog.get("scanners") or []:
            for t in sc_.get("targets") or []:
                bits.append("{} {} @{}".format(t.get("targetUrl"), t.get("status"), sc_.get("name")))
                if t.get("errorNotes"):
                    bits.append("hata={}".format(t.get("errorNotes")))
        for k in ("completedTargets", "scannedSize"):
            if prog.get(k) not in (None, "", "0", -1):
                bits.append("{}={}".format(k, prog.get(k)))
        extra = " | ".join(bits)
    cc, tc = res.get("completedChecks"), res.get("totalChecks")
    checks = " checks={}/{}".format(cc, tc) if str(tc) not in ("None", "", "0", "-1") else ""
    el = int(time.time() - t0)
    return "[{:02d}:{:02d}] scanResult {} status={} running={}{} {}".format(
        el // 60, el % 60, res.get("id"), st, res.get("running"), checks, extra).rstrip()
