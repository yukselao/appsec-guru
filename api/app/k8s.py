"""Minimal Kubernetes REST client over a kubeconfig. Parses a kubeconfig,
authenticates with a client certificate or a bearer token, and makes
authenticated calls to the cluster API with httpx. The API server must be
reachable from the Docker network (for a Docker-Desktop-local cluster, the
kubeconfig server should be host.docker.internal:<port>). No kubectl, no Docker
socket. Exec/auth-provider credential plugins are not supported."""
import base64
import contextlib
import os
import tempfile

import httpx
import yaml


class KubeConfigError(ValueError):
    pass


def _b64(v):
    return base64.b64decode(v) if v else None


def parse(text):
    """Return the connection parameters for the kubeconfig's current context."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise KubeConfigError("not valid YAML: {}".format(exc))
    if not isinstance(doc, dict) or doc.get("kind") != "Config":
        raise KubeConfigError("not a kubeconfig (kind: Config expected)")
    ctx_name = doc.get("current-context")
    contexts = {c["name"]: c["context"] for c in doc.get("contexts") or [] if "name" in c}
    if ctx_name not in contexts:
        if not contexts:
            raise KubeConfigError("kubeconfig has no contexts")
        ctx_name = next(iter(contexts))
    ctx = contexts[ctx_name]
    clusters = {c["name"]: c["cluster"] for c in doc.get("clusters") or [] if "name" in c}
    users = {u["name"]: u["user"] for u in doc.get("users") or [] if "name" in u}
    cl = clusters.get(ctx.get("cluster")) or {}
    us = users.get(ctx.get("user")) or {}
    if us.get("exec") or us.get("auth-provider"):
        raise KubeConfigError("exec / auth-provider credential plugins are not supported; "
                              "use a kubeconfig with a client certificate or a bearer token")
    server = cl.get("server")
    if not server:
        raise KubeConfigError("kubeconfig context has no server URL")
    return {
        "context": ctx_name,
        "server": server.rstrip("/"),
        "insecure": bool(cl.get("insecure-skip-tls-verify")),
        "ca": _b64(cl.get("certificate-authority-data")),
        "client_cert": _b64(us.get("client-certificate-data")),
        "client_key": _b64(us.get("client-key-data")),
        "token": us.get("token"),
        "namespace": ctx.get("namespace") or "default",
    }


@contextlib.contextmanager
def client(cfg, timeout=20):
    """An httpx.Client authenticated for the cluster. Temp cert/key files are
    written for the lifetime of the context and removed afterwards."""
    tmp = []
    cert = None
    verify = False
    headers = {}
    try:
        if cfg.get("client_cert") and cfg.get("client_key"):
            cf = tempfile.NamedTemporaryFile(delete=False, suffix=".crt"); cf.write(cfg["client_cert"]); cf.close(); tmp.append(cf.name)
            kf = tempfile.NamedTemporaryFile(delete=False, suffix=".key"); kf.write(cfg["client_key"]); kf.close(); tmp.append(kf.name)
            cert = (cf.name, kf.name)
        if cfg.get("token"):
            headers["Authorization"] = "Bearer " + cfg["token"]
        if cfg.get("insecure"):
            verify = False
        elif cfg.get("ca"):
            caf = tempfile.NamedTemporaryFile(delete=False, suffix=".ca"); caf.write(cfg["ca"]); caf.close(); tmp.append(caf.name)
            verify = caf.name
        with httpx.Client(base_url=cfg["server"], cert=cert, verify=verify,
                          headers=headers, timeout=timeout, follow_redirects=True) as c:
            yield c
    finally:
        for p in tmp:
            with contextlib.suppress(OSError):
                os.unlink(p)


def version(cfg):
    with client(cfg, timeout=10) as c:
        r = c.get("/version")
        r.raise_for_status()
        return r.json()


def get_json(cfg, path, timeout=20):
    with client(cfg, timeout=timeout) as c:
        r = c.get(path)
        r.raise_for_status()
        return r.json()


def list_pods(cfg):
    return get_json(cfg, "/api/v1/pods", timeout=30)


def post_json(cfg, path, body, timeout=20):
    with client(cfg, timeout=timeout) as c:
        r = c.post(path, json=body)
        r.raise_for_status()
        return r.json()


def delete(cfg, path, timeout=20):
    with client(cfg, timeout=timeout) as c:
        r = c.request("DELETE", path)
        return r.status_code, (r.json() if r.content else {})


def pod_logs(cfg, namespace, pod, container=None, timeout=20):
    path = "/api/v1/namespaces/{}/pods/{}/log".format(namespace, pod)
    if container:
        path += "?container=" + container
    with client(cfg, timeout=timeout) as c:
        r = c.get(path)
        r.raise_for_status()
        return r.text
