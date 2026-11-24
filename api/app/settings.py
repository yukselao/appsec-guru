"""Settings. Base values come from .env (passed to the api container as
environment variables); a value saved in the UI (PostgreSQL) overrides it until
it is reset. Secrets saved in the UI are encrypted with the app secret key
(PyNaCl SecretBox, APP_SECRET_KEY_FILE). Secrets are never returned to the UI."""
import os
import threading

import nacl.secret
import nacl.utils
from sqlalchemy import select

from wtdb.database import session_scope
from wtdb.models import AuditLog, Setting

AI_DEFAULT_PROMPT = (
    "Sen Tenable Web App Scanning (WAS) ve Tenable.sc uzmanı bir destek mühendisisin. "
    "Kullanıcı sana nessus-was-scanner logları (/var/log/nessus-was/scanner.log, [scanUuid=...] etiketli), "
    "Tenable.sc tarama durumları, politika ayarları ve bulgular yapıştıracak. Logları analiz et: taramanın hangi "
    "aşamada olduğunu (crawl/dom_exploration, audit, plugin çalışması, autothrottle), hataları ve uyarıları, kök "
    "nedenleri ve somut sonraki adımları açıkla. Kısa, maddeli ve Türkçe yaz; satırlardan kanıt göster; emin "
    "olmadığın yeri belirt.")

# key -> (default, secret, env var)
FIELDS = {
    "sc.url": ("", False, "SC_URL"),
    "sc.access_key": ("", True, "SC_ACCESS_KEY"),
    "sc.secret_key": ("", True, "SC_SECRET_KEY"),
    "sc.verify_tls": ("false", False, "SC_VERIFY_TLS"),
    "sc.ssh_host": ("", False, "SC_SSH_HOST"),
    "sc.ssh_port": ("22", False, "SC_SSH_PORT"),
    "sc.ssh_user": ("osadmin", False, "SC_SSH_USER"),
    "sc.ssh_password": ("", True, "SC_SSH_PASSWORD"),
    "ssh.host": ("", False, "WAS_SSH_HOST"),
    "ssh.port": ("22", False, "WAS_SSH_PORT"),
    "ssh.user": ("osadmin", False, "WAS_SSH_USER"),
    "ssh.password": ("", True, "WAS_SSH_PASSWORD"),
    "ssh.key_path": ("", False, "WAS_SSH_KEY_PATH"),
    "ssh.jump_host": ("", False, "WAS_JUMP_HOST"),
    "ssh.jump_user": ("", False, "WAS_JUMP_USER"),
    "ssh.jump_password": ("", True, "WAS_JUMP_PASSWORD"),
    "ssh.log_path": ("/var/log/nessus-was/scanner.log", False, "WAS_LOG_PATH"),
    "ai.ollama_url": ("http://192.168.1.140:11434", False, "OLLAMA_URL"),
    "ai.model": ("", False, "OLLAMA_MODEL"),
    "ai.temperature": ("0.2", False, "AI_TEMPERATURE"),
    "ai.ctx_chars": ("24000", False, "AI_CTX_CHARS"),
    "ai.num_ctx": ("16384", False, "AI_NUM_CTX"),
    "ai.system_prompt": (AI_DEFAULT_PROMPT, False, "AI_SYSTEM_PROMPT"),
    "recon.httpx_timeout": ("10", False, "RECON_HTTPX_TIMEOUT"),
    "recon.httpx_threads": ("50", False, "RECON_HTTPX_THREADS"),
    "recon.httpx_rate_limit": ("150", False, "RECON_HTTPX_RATE_LIMIT"),
    "recon.httpx_retries": ("0", False, "RECON_HTTPX_RETRIES"),
    "recon.idle_timeout": ("180", False, "RECON_IDLE_TIMEOUT"),
    "recon.stage_timeout": ("900", False, "RECON_STAGE_TIMEOUT"),
    "recon.rustscan_batch": ("1000", False, "RECON_RUSTSCAN_BATCH"),
    "recon.rustscan_timeout": ("2500", False, "RECON_RUSTSCAN_TIMEOUT"),
    "recon.nuclei_rate_limit": ("150", False, "RECON_NUCLEI_RATE_LIMIT"),
    "recon.nuclei_timeout": ("10", False, "RECON_NUCLEI_TIMEOUT"),
    "recon.nuclei_concurrency": ("25", False, "RECON_NUCLEI_CONCURRENCY"),
    "recon.nuclei_bulk_size": ("25", False, "RECON_NUCLEI_BULK_SIZE"),
    "recon.nuclei_retries": ("1", False, "RECON_NUCLEI_RETRIES"),
    "recon.nuclei_stage_timeout": ("1800", False, "RECON_NUCLEI_STAGE_TIMEOUT"),
    "recon.katana_depth": ("3", False, "RECON_KATANA_DEPTH"),
    "recon.katana_concurrency": ("10", False, "RECON_KATANA_CONCURRENCY"),
    "recon.katana_rate_limit": ("20", False, "RECON_KATANA_RATE_LIMIT"),
    "recon.katana_parallelism": ("5", False, "RECON_KATANA_PARALLELISM"),
    "recon.katana_timeout": ("10", False, "RECON_KATANA_TIMEOUT"),
    "recon.katana_retry": ("1", False, "RECON_KATANA_RETRY"),
    "recon.katana_stage_timeout": ("900", False, "RECON_KATANA_STAGE_TIMEOUT"),
    "recon.sqlmap_level": ("1", False, "RECON_SQLMAP_LEVEL"),
    "recon.sqlmap_risk": ("1", False, "RECON_SQLMAP_RISK"),
    "recon.sqlmap_threads": ("1", False, "RECON_SQLMAP_THREADS"),
    "recon.sqlmap_timeout": ("30", False, "RECON_SQLMAP_TIMEOUT"),
    "recon.sqlmap_retries": ("2", False, "RECON_SQLMAP_RETRIES"),
    "recon.sqlmap_stage_timeout": ("1800", False, "RECON_SQLMAP_STAGE_TIMEOUT"),
    "recon.commix_level": ("1", False, "RECON_COMMIX_LEVEL"),
    "recon.commix_timeout": ("30", False, "RECON_COMMIX_TIMEOUT"),
    "recon.commix_retries": ("3", False, "RECON_COMMIX_RETRIES"),
    "recon.commix_stage_timeout": ("1800", False, "RECON_COMMIX_STAGE_TIMEOUT"),
}
# key -> (min, max) of whole-number settings; checked on save and clamped on use
INT_LIMITS = {
    "recon.httpx_timeout": (1, 120),
    "recon.httpx_threads": (1, 300),
    "recon.httpx_rate_limit": (1, 1000),
    "recon.httpx_retries": (0, 5),
    "recon.idle_timeout": (30, 1800),
    "recon.stage_timeout": (60, 3600),
    "recon.rustscan_batch": (100, 65535),
    "recon.rustscan_timeout": (500, 20000),
    "recon.nuclei_rate_limit": (1, 1000),
    "recon.nuclei_timeout": (1, 60),
    "recon.nuclei_concurrency": (1, 100),
    "recon.nuclei_bulk_size": (1, 100),
    "recon.nuclei_retries": (0, 5),
    "recon.nuclei_stage_timeout": (60, 7200),
    "recon.katana_depth": (1, 10),
    "recon.katana_concurrency": (1, 50),
    "recon.katana_rate_limit": (1, 1000),
    "recon.katana_parallelism": (1, 50),
    "recon.katana_timeout": (1, 60),
    "recon.katana_retry": (0, 5),
    "recon.katana_stage_timeout": (60, 3600),
    "recon.sqlmap_level": (1, 5),
    "recon.sqlmap_risk": (1, 3),
    "recon.sqlmap_threads": (1, 10),
    "recon.sqlmap_timeout": (1, 120),
    "recon.sqlmap_retries": (0, 5),
    "recon.sqlmap_stage_timeout": (60, 7200),
    "recon.commix_level": (1, 3),
    "recon.commix_timeout": (1, 120),
    "recon.commix_retries": (0, 5),
    "recon.commix_stage_timeout": (60, 7200),
}
SECRET_MASK = "__SET__"

_box = None
_lock = threading.Lock()
_version = 0  # bumped on every write; connection caches compare against it


def version():
    return _version


def _secretbox():
    global _box
    if _box is None:
        path = os.environ.get("APP_SECRET_KEY_FILE", "/run/secrets/app_secret_key")
        with open(path) as fh:
            raw = fh.read().strip()
        key = bytes.fromhex(raw)
        if len(key) != nacl.secret.SecretBox.KEY_SIZE:
            raise RuntimeError("app_secret_key 64 hex karakter olmali (openssl rand -hex 32)")
        _box = nacl.secret.SecretBox(key)
    return _box


def _base():
    """default <- .env (environment)"""
    out, src = {}, {}
    for k, (d, _secret, env) in FIELDS.items():
        v = os.environ.get(env)
        if v not in (None, ""):
            out[k], src[k] = v, "env"
        else:
            out[k], src[k] = d, "default"
    return out, src


def sources():
    """{key: "ui" | "env" | "default"}: where the effective value comes from."""
    _, src = _base()
    with session_scope() as s:
        for row in s.execute(select(Setting)).scalars():
            if row.key in FIELDS:
                src[row.key] = "ui"
    return src


def get_all(include_secrets=False):
    """Effective values: UI (database) over .env over defaults. Secrets come
    back decrypted only when asked; otherwise SECRET_MASK (set) or "" (empty)."""
    out, _ = _base()
    if not include_secrets:
        for k, (_d, secret, _e) in FIELDS.items():
            if secret:
                out[k] = SECRET_MASK if out[k] else ""
    with session_scope() as s:
        for row in s.execute(select(Setting)).scalars():
            if row.key not in FIELDS:
                continue
            if row.is_secret:
                if not row.secret_value:
                    out[row.key] = ""
                elif include_secrets:
                    out[row.key] = _secretbox().decrypt(row.secret_value).decode("utf-8")
                else:
                    out[row.key] = SECRET_MASK
            else:
                out[row.key] = row.value if row.value is not None else ""
    return out


def get_int(key, values=None):
    """A whole-number setting inside its limits; the default when it is not a number."""
    lo, hi = INT_LIMITS[key]
    try:
        n = int((values or get_all())[key])
    except (TypeError, ValueError):
        n = int(FIELDS[key][0])
    return max(lo, min(n, hi))


def _check_ints(values):
    for key, (lo, hi) in INT_LIMITS.items():
        if key not in values:
            continue
        try:
            good = lo <= int(str(values[key]).strip()) <= hi
        except ValueError:
            good = False
        if not good:
            raise ValueError("{} must be a whole number from {} to {}".format(key, lo, hi))


def save(values, client_ip=None):
    """Saves known keys. A secret equal to SECRET_MASK keeps the stored value;
    an empty secret clears it. Raises ValueError on an out-of-range number."""
    global _version
    _check_ints(values)
    changed = []
    with _lock, session_scope() as s:
        for key, val in values.items():
            if key not in FIELDS:
                continue
            secret = FIELDS[key][1]
            if secret and val == SECRET_MASK:
                continue
            val = "" if val is None else str(val)
            row = s.get(Setting, key) or Setting(key=key)
            row.is_secret = secret
            if secret:
                row.value = None
                row.secret_value = _secretbox().encrypt(val.encode("utf-8")) if val else None
            else:
                row.value = val
                row.secret_value = None
            s.merge(row)
            changed.append(key)
        if changed:
            s.add(AuditLog(action="settings_save", details={"keys": changed}, client_ip=client_ip))
        _version += 1
    return changed


def reset(keys, client_ip=None):
    """Drops UI overrides so the .env / default value applies again."""
    global _version
    with _lock, session_scope() as s:
        for k in keys:
            row = s.get(Setting, k)
            if row:
                s.delete(row)
        s.add(AuditLog(action="settings_reset", details={"keys": list(keys)}, client_ip=client_ip))
        _version += 1


def audit(action, client_ip=None, **details):
    try:
        with session_scope() as s:
            s.add(AuditLog(action=action, details=details, client_ip=client_ip))
    except Exception:
        pass
