"""Container registry connections: store registry endpoints (token encrypted),
browse repositories and tags over the Docker Registry HTTP API v2, and launch a
Trivy scan of a chosen image. The api talks to the registry directly over HTTP(S)
- it never uses the Docker socket. Credentials are passed to Trivy only to pull
the image and are never persisted in a scan row or returned to the UI."""
import logging
import re

import httpx
from sqlalchemy import desc, select

from wtdb.database import session_scope
from wtdb.models import Registry

from . import settings as st
from . import trivy

log = logging.getLogger("registries")
HOST_RX = re.compile(r"^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$")
REPO_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]{0,250}$")
TAG_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,127}$")
_BEARER_RX = re.compile(r'(\w+)="([^"]*)"')


def _token(reg):
    if not reg.token_enc:
        return ""
    try:
        return st._secretbox().decrypt(reg.token_enc).decode("utf-8")
    except Exception:
        return ""


def _base(reg):
    return ("http://" if reg.insecure else "https://") + reg.host


def row(reg):
    return {"id": reg.id, "name": reg.name, "host": reg.host, "username": reg.username or "",
            "has_token": bool(reg.token_enc), "insecure": reg.insecure,
            "created_at": reg.created_at.isoformat() if reg.created_at else None}


def list_registries():
    with session_scope() as s:
        return {"registries": [row(r) for r in s.execute(select(Registry).order_by(desc(Registry.id))).scalars()]}


def _validate(params):
    name = (params.get("name") or "").strip()[:120]
    host = (params.get("host") or "").strip().lower()[:200]
    if not name:
        raise ValueError("name is required")
    if not HOST_RX.match(host):
        raise ValueError("host must be a registry hostname, e.g. ghcr.io or registry.example.com:5000")
    return name, host


def add(params, client_ip=None):
    name, host = _validate(params)
    username = (params.get("username") or "").strip()[:200] or None
    token = params.get("token") or ""
    insecure = bool(params.get("insecure"))
    with session_scope() as s:
        r = Registry(name=name, host=host, username=username, insecure=insecure,
                     token_enc=st._secretbox().encrypt(token.encode("utf-8")) if token else None)
        s.add(r)
        s.flush()
        rid = r.id
    st.audit("registry_add", client_ip=client_ip, registry_id=rid, host=host)
    return {"id": rid}


def update(reg_id, params, client_ip=None):
    name, host = _validate(params)
    with session_scope() as s:
        r = s.get(Registry, reg_id)
        if not r:
            raise ValueError("registry not found")
        r.name, r.host = name, host
        r.username = (params.get("username") or "").strip()[:200] or None
        r.insecure = bool(params.get("insecure"))
        # token: only overwrite when a new one is supplied; "" leaves it unchanged,
        # an explicit clear flag removes it.
        if params.get("clear_token"):
            r.token_enc = None
        elif params.get("token"):
            r.token_enc = st._secretbox().encrypt(params["token"].encode("utf-8"))
    st.audit("registry_update", client_ip=client_ip, registry_id=reg_id, host=host)
    return {"id": reg_id}


def delete(reg_id, client_ip=None):
    with session_scope() as s:
        r = s.get(Registry, reg_id)
        if not r:
            raise ValueError("registry not found")
        s.delete(r)
    st.audit("registry_delete", client_ip=client_ip, registry_id=reg_id)
    return {"deleted": reg_id}


def _bearer(reg, challenge, client):
    """Resolve a Bearer token from a WWW-Authenticate challenge."""
    parts = dict(_BEARER_RX.findall(challenge))
    realm = parts.get("realm")
    if not realm:
        return None
    params = {k: parts[k] for k in ("service", "scope") if parts.get(k)}
    auth = None
    tok = _token(reg)
    if reg.username and tok:
        auth = (reg.username, tok)
    tr = client.get(realm, params=params, auth=auth, timeout=15)
    if tr.status_code == 200:
        return tr.json().get("token") or tr.json().get("access_token")
    return None


def _get(reg, path, scope=None):
    """GET a registry v2 path, handling Basic auth and Bearer token challenges."""
    url = _base(reg) + path
    tok = _token(reg)
    basic = (reg.username, tok) if (reg.username and tok) else None
    with httpx.Client(follow_redirects=True, timeout=20) as client:
        r = client.get(url, auth=basic)
        if r.status_code == 401 and "www-authenticate" in r.headers:
            wa = r.headers["www-authenticate"]
            if wa.lower().startswith("bearer"):
                bt = _bearer(reg, wa, client)
                if bt:
                    r = client.get(url, headers={"Authorization": "Bearer " + bt})
        return r


def _reg(reg_id):
    with session_scope() as s:
        r = s.get(Registry, reg_id)
        if not r:
            raise ValueError("registry not found")
        # detach a lightweight copy (session closes after)
        return type("R", (), {"id": r.id, "name": r.name, "host": r.host, "username": r.username,
                              "token_enc": r.token_enc, "insecure": r.insecure,
                              "created_at": r.created_at})()


def test(reg_id):
    reg = _reg(reg_id)
    try:
        r = _get(reg, "/v2/")
    except httpx.HTTPError as exc:
        return {"ok": False, "error": "{}: {}".format(type(exc).__name__, exc)}
    ok = r.status_code in (200, 401)   # 401 after auth attempt still means "reachable"
    return {"ok": r.status_code == 200, "reachable": ok, "status": r.status_code,
            "detail": "" if r.status_code == 200 else "reachable but authentication failed or is required" if r.status_code == 401 else r.text[:200]}


def catalog(reg_id, n=200):
    reg = _reg(reg_id)
    try:
        r = _get(reg, "/v2/_catalog?n={}".format(int(n)))
    except httpx.HTTPError as exc:
        return {"error": "{}: {}".format(type(exc).__name__, exc)}
    if r.status_code != 200:
        return {"error": "catalog not available (HTTP {}). Some registries (e.g. Docker Hub, GHCR) do not expose /v2/_catalog; enter a repository directly.".format(r.status_code),
                "repositories": []}
    return {"repositories": (r.json() or {}).get("repositories") or []}


def tags(reg_id, repo):
    repo = (repo or "").strip()
    if not REPO_RX.match(repo):
        return {"error": "invalid repository name"}
    reg = _reg(reg_id)
    try:
        r = _get(reg, "/v2/{}/tags/list".format(repo))
    except httpx.HTTPError as exc:
        return {"error": "{}: {}".format(type(exc).__name__, exc)}
    if r.status_code != 200:
        return {"error": "could not list tags (HTTP {})".format(r.status_code), "tags": []}
    return {"repository": repo, "tags": (r.json() or {}).get("tags") or []}


def scan(reg_id, repo, tag, params=None, client_ip=None):
    repo, tag = str(repo or "").strip(), str(tag or "").strip()
    if not REPO_RX.match(repo) or not TAG_RX.match(tag):
        raise ValueError("invalid repository or tag")
    reg = _reg(reg_id)
    image = "{}/{}:{}".format(reg.host, repo, tag)
    sp = dict(params or {})
    sp.update({"target": image, "registry": reg.host, "insecure": reg.insecure,
               "username": reg.username or "", "password": _token(reg) if reg.username else "",
               "registry_token": "" if reg.username else _token(reg)})
    run_id = trivy.start(sp, client_ip=client_ip)
    return {"run_id": run_id, "image": image}
