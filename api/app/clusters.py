"""Registered Kubernetes clusters and the scans that run against them:
  - posture        : live Kubescape framework scan (reaches the cluster API)
  - image-inventory: list running workloads' images (K8s API) -> feed Trivy
  - node-bench     : CIS kube-bench as a Job on a node, logs parsed deterministically
The kubeconfig is stored encrypted; the API server must be reachable from the
Docker network. No Docker socket. JSON from the tools is parsed deterministically
(no AI), reusing the existing Kubescape / kube-bench parsers."""
import json
import logging
import os
import re
import socket
import threading
import time

import httpx
from sqlalchemy import desc, select

from wtdb.database import session_scope
from wtdb.models import Cluster, ClusterScan

from . import settings as st
from . import k8s, kubescape, kubebench, trivy

log = logging.getLogger("clusters")
KUBESCAPE_CLUSTER = os.environ.get("RECON_KUBESCAPE_CLUSTER", "recon-kubescape:7013")
ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
KINDS = ("posture", "image-inventory", "node-bench")
POSTURE_FRAMEWORKS = ("nsa", "mitre", "cis-v1.10.0", "allcontrols")
NODE_BENCH_IMAGE = "aquasec/kube-bench:v0.10.7"
LOG_MAX = 4000
LOG_RUNS = 25
_active = {}
_logs = {}
_lock = threading.Lock()


# --------------------------------------------------------------------- log buffer
def _log_append(run_id, line):
    with _lock:
        buf = _logs.get(run_id)
        if buf is None:
            buf = _logs[run_id] = []
            for old in sorted(_logs)[:-LOG_RUNS]:
                if old not in _active:
                    _logs.pop(old, None)
        buf.append(line)
        if len(buf) > LOG_MAX:
            del buf[:len(buf) - LOG_MAX]


def drop_log(run_id):
    with _lock:
        _logs.pop(run_id, None)


def get_log(run_id, offset=0):
    with _lock:
        buf = _logs.get(run_id, [])
        offset = max(0, min(int(offset or 0), len(buf)))
        return {"lines": buf[offset:], "offset": len(buf),
                "active": run_id in _active, "has_log": bool(buf)}


def is_active(run_id):
    with _lock:
        return run_id in _active


def cancel(run_id):
    with _lock:
        ev = _active.get(run_id)
    if ev:
        ev.set()
    return bool(ev)


def mark_orphans():
    with session_scope() as s:
        for r in s.execute(select(ClusterScan).where(ClusterScan.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the scan"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(ClusterScan, run_id)
        for k, v in f.items():
            setattr(r, k, v)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def _hostport(hp):
    host, port = hp.rsplit(":", 1)
    return host, int(port)


# --------------------------------------------------------------------- registration
def _kubeconfig_text(cluster_id):
    with session_scope() as s:
        c = s.get(Cluster, cluster_id)
        if not c:
            raise ValueError("cluster not found")
        return st._secretbox().decrypt(c.kubeconfig_enc).decode("utf-8"), c.name


def cluster_row(c):
    return {"id": c.id, "name": c.name, "server": c.server or "", "context": c.context or "",
            "created_at": c.created_at.isoformat() if c.created_at else None}


def list_clusters():
    with session_scope() as s:
        return {"clusters": [cluster_row(c) for c in s.execute(select(Cluster).order_by(desc(Cluster.id))).scalars()]}


def add_cluster(params, client_ip=None):
    name = (params.get("name") or "").strip()[:120]
    kubeconfig = params.get("kubeconfig") or ""
    if not name:
        raise ValueError("name is required")
    if not kubeconfig.strip():
        raise ValueError("paste a kubeconfig")
    cfg = k8s.parse(kubeconfig)   # raises KubeConfigError (ValueError) on bad config
    with session_scope() as s:
        c = Cluster(name=name, server=cfg["server"], context=cfg["context"],
                    kubeconfig_enc=st._secretbox().encrypt(kubeconfig.encode("utf-8")))
        s.add(c)
        s.flush()
        cid = c.id
    st.audit("cluster_add", client_ip=client_ip, cluster_id=cid, server=cfg["server"])
    return {"id": cid, "server": cfg["server"], "context": cfg["context"]}


def delete_cluster(cluster_id, client_ip=None):
    with session_scope() as s:
        c = s.get(Cluster, cluster_id)
        if not c:
            raise ValueError("cluster not found")
        s.delete(c)
    st.audit("cluster_delete", client_ip=client_ip, cluster_id=cluster_id)
    return {"deleted": cluster_id}


def test_cluster(cluster_id):
    text, _ = _kubeconfig_text(cluster_id)
    cfg = k8s.parse(text)
    try:
        v = k8s.version(cfg)
    except httpx.HTTPError as exc:
        return {"ok": False, "error": "{}: {}".format(type(exc).__name__, exc),
                "hint": "the API server must be reachable from the Docker network (e.g. host.docker.internal for a local cluster)"}
    return {"ok": True, "version": v.get("gitVersion"), "platform": v.get("platform")}


# --------------------------------------------------------------------- scan lifecycle
def start(cluster_id, kind, params, client_ip=None):
    if kind not in KINDS:
        raise ValueError("unknown scan kind")
    text, cname = _kubeconfig_text(cluster_id)   # validates existence + decrypts
    cfg = k8s.parse(text)
    opts = {"kind": kind}
    if kind == "posture":
        fws = [f for f in (params.get("frameworks") or ["nsa", "mitre"]) if f in POSTURE_FRAMEWORKS] or ["nsa"]
        opts["frameworks"] = fws
        opts["stage_timeout"] = st.get_int("recon.kubescape_stage_timeout")
    elif kind == "node-bench":
        opts["benchmark"] = (params.get("benchmark") or "cis-1.9")
        opts["stage_timeout"] = st.get_int("recon.kubebench_stage_timeout")
    with session_scope() as s:
        r = ClusterScan(cluster_id=cluster_id, cluster_name=cname, kind=kind, status="pending", options=opts, stats={})
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("cluster_scan_create", client_ip=client_ip, run_id=run_id, cluster_id=cluster_id, kind=kind)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, kind, cfg, text, opts, ev),
                     name="cluster-%s-%d" % (kind, run_id), daemon=True).start()
    return run_id


def _run(run_id, kind, cfg, kubeconfig, opts, ev):
    try:
        update(run_id, status="running")
        if kind == "posture":
            _run_posture(run_id, kubeconfig, opts, ev)
        elif kind == "image-inventory":
            _run_inventory(run_id, cfg, ev)
        elif kind == "node-bench":
            _run_nodebench(run_id, cfg, opts, ev)
    except ValueError as exc:
        _log_append(run_id, "[api] failed - {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    except httpx.HTTPError as exc:
        _log_append(run_id, "[api] cluster API error: {}".format(exc))
        update(run_id, status="failed", error="cluster API error: {}".format(exc), finished_at=_now())
    except Exception as exc:
        log.exception("cluster scan %s", run_id)
        _log_append(run_id, "[api] error: {}".format(exc))
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


# --------------------------------------------------------------------- posture (Kubescape)
def _run_posture(run_id, kubeconfig, opts, cancel_ev):
    fws = opts["frameworks"]
    argv = ["scan", "framework", ",".join(fws)]
    _log_append(run_id, "$ kubescape {} --kubeconfig <cluster> --format json".format(" ".join(argv)))
    jbuf, in_json, saw_error = [], False, []
    host, port = _hostport(KUBESCAPE_CLUSTER)
    s = socket.create_connection((host, port), timeout=15)
    s.sendall(("\n".join(argv) + "\n__END__\n").encode("utf-8") + kubeconfig.encode("utf-8"))
    s.shutdown(socket.SHUT_WR)
    deadline = time.time() + opts["stage_timeout"]
    rbuf = b""

    def handle(line):
        nonlocal in_json
        if in_json:
            jbuf.append(line)
            return
        line = ANSI_RX.sub("", line).rstrip()
        if line == kubescape.SENTINEL:
            in_json = True
            return
        if not line or line.startswith('{"level"'):
            return
        _log_append(run_id, line)
        if re.search(r"\bFATAL\b|\[error\]|could not|failed to|connection refused|unauthorized", line, re.I):
            saw_error.append(line)

    while not cancel_ev.is_set():
        left = deadline - time.time()
        if left <= 0:
            _log_append(run_id, "[api] reached the stage limit of {}s, stopping".format(opts["stage_timeout"]))
            break
        s.settimeout(min(60, left))
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        rbuf += chunk
        while b"\n" in rbuf:
            raw, rbuf = rbuf.split(b"\n", 1)
            handle(raw.decode("utf-8", "replace"))
    try:
        s.close()
    except OSError:
        pass
    if rbuf.strip():
        handle(rbuf.decode("utf-8", "replace"))
    if cancel_ev.is_set():
        _log_append(run_id, "[api] cancelled")
        update(run_id, status="cancelled", finished_at=_now())
        return
    doc = None
    if jbuf:
        try:
            doc = json.loads("\n".join(jbuf))
        except ValueError as exc:
            saw_error.append("could not parse Kubescape JSON: {}".format(exc))
    if doc is None:
        raise ValueError(saw_error[-1] if saw_error else "Kubescape produced no report")
    res, stats = kubescape._parse(doc)
    api_info = doc.get("clusterAPIServerInfo") or {}
    res["cluster_version"] = api_info.get("gitVersion")
    res["frameworks_requested"] = fws
    _log_append(run_id, "[api] completed - score {}, {} failed controls across {} resources".format(
        stats["score"], stats["failed_controls"], stats["failed_resources"]))
    update(run_id, status="completed", results=res, stats=stats, finished_at=_now())
    st.audit("cluster_posture_done", run_id=run_id, score=stats["score"], failed=stats["failed_controls"])


# --------------------------------------------------------------------- image inventory
def _run_inventory(run_id, cfg, cancel_ev):
    _log_append(run_id, "$ GET /api/v1/pods  (collecting running workload images)")
    data = k8s.list_pods(cfg)
    items = data.get("items") or []
    images = {}   # image -> {namespaces:set, pods:set, running:int}
    for pod in items:
        meta, spec, pstatus = pod.get("metadata") or {}, pod.get("spec") or {}, pod.get("status") or {}
        ns, name = meta.get("namespace"), meta.get("name")
        phase = pstatus.get("phase")
        # prefer the resolved imageID/image from status, fall back to spec
        resolved = {}
        for cs in (pstatus.get("containerStatuses") or []):
            resolved[cs.get("name")] = cs.get("image")
        containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
        for c in containers:
            img = resolved.get(c.get("name")) or c.get("image")
            if not img:
                continue
            e = images.setdefault(img, {"namespaces": set(), "pods": set(), "running": 0})
            e["namespaces"].add(ns)
            e["pods"].add("{}/{}".format(ns, name))
            if phase == "Running":
                e["running"] += 1
    rows = [{"image": img, "namespaces": sorted(v["namespaces"]), "pods": sorted(v["pods"]),
             "pod_count": len(v["pods"]), "running": v["running"]}
            for img, v in images.items()]
    rows.sort(key=lambda r: (-r["pod_count"], r["image"]))
    stats = {"images": len(rows), "pods": len(items),
             "namespaces": len({r for v in images.values() for r in v["namespaces"]})}
    _log_append(run_id, "[api] completed - {} unique image(s) across {} pod(s)".format(stats["images"], stats["pods"]))
    update(run_id, status="completed", results={"images": rows}, stats=stats, finished_at=_now())
    st.audit("cluster_inventory_done", run_id=run_id, images=stats["images"])


def scan_image(run_id, image, client_ip=None):
    """Launch a Trivy scan of one image found in a cluster's inventory."""
    with session_scope() as s:
        r = s.get(ClusterScan, run_id)
        if not r or r.kind != "image-inventory":
            raise ValueError("inventory scan not found")
        imgs = {i["image"] for i in (r.results or {}).get("images") or []}
    if image not in imgs:
        raise ValueError("image is not part of this inventory")
    tid = trivy.start({"target": image, "scanners": ["vuln", "secret"]}, client_ip=client_ip)
    return {"run_id": tid, "image": image}


# --------------------------------------------------------------------- node CIS (kube-bench Job)
_JOB_NS = "default"


def _nodebench_job(name, benchmark):
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "labels": {"app": "appsecguru-kubebench"}},
        "spec": {
            "backoffLimit": 0, "ttlSecondsAfterFinished": 300,
            "template": {"metadata": {"labels": {"app": "appsecguru-kubebench"}}, "spec": {
                "hostPID": True, "restartPolicy": "Never",
                "tolerations": [{"operator": "Exists"}],
                "containers": [{
                    "name": "kube-bench", "image": NODE_BENCH_IMAGE,
                    "command": ["kube-bench", "run", "--benchmark", benchmark, "--json"],
                    "volumeMounts": [
                        {"name": "var-lib-etcd", "mountPath": "/var/lib/etcd", "readOnly": True},
                        {"name": "var-lib-kubelet", "mountPath": "/var/lib/kubelet", "readOnly": True},
                        {"name": "etc-systemd", "mountPath": "/etc/systemd", "readOnly": True},
                        {"name": "etc-kubernetes", "mountPath": "/etc/kubernetes", "readOnly": True},
                        {"name": "usr-bin", "mountPath": "/usr/local/mount-from-host/bin", "readOnly": True},
                    ]}],
                "volumes": [
                    {"name": "var-lib-etcd", "hostPath": {"path": "/var/lib/etcd"}},
                    {"name": "var-lib-kubelet", "hostPath": {"path": "/var/lib/kubelet"}},
                    {"name": "etc-systemd", "hostPath": {"path": "/etc/systemd"}},
                    {"name": "etc-kubernetes", "hostPath": {"path": "/etc/kubernetes"}},
                    {"name": "usr-bin", "hostPath": {"path": "/usr/bin"}},
                ]}}}}


def _run_nodebench(run_id, cfg, opts, cancel_ev):
    benchmark = opts["benchmark"]
    name = "appsecguru-kubebench-{}".format(run_id)
    _log_append(run_id, "$ kubectl apply job/{} (kube-bench {} on a node)".format(name, benchmark))
    body = _nodebench_job(name, benchmark)
    try:
        k8s.post_json(cfg, "/apis/batch/v1/namespaces/{}/jobs".format(_JOB_NS), body, timeout=20)
    except httpx.HTTPStatusError as exc:
        raise ValueError("could not create kube-bench Job (HTTP {}): {}".format(exc.response.status_code, exc.response.text[:200]))
    _log_append(run_id, "[api] Job created, waiting for the node benchmark pod to complete…")
    deadline = time.time() + opts["stage_timeout"]
    logs = None
    try:
        while not cancel_ev.is_set() and time.time() < deadline:
            time.sleep(4)
            pods = k8s.get_json(cfg, "/api/v1/namespaces/{}/pods?labelSelector=job-name={}".format(_JOB_NS, name), timeout=15)
            its = pods.get("items") or []
            if not its:
                continue
            pod = its[0]
            phase = (pod.get("status") or {}).get("phase")
            podname = (pod.get("metadata") or {}).get("name")
            if phase in ("Succeeded", "Failed"):
                _log_append(run_id, "[api] pod {} {} - collecting report".format(podname, phase))
                logs = k8s.pod_logs(cfg, _JOB_NS, podname, timeout=20)
                break
            _log_append(run_id, "[api] pod {} is {}…".format(podname, phase))
        if cancel_ev.is_set():
            _log_append(run_id, "[api] cancelled")
            update(run_id, status="cancelled", finished_at=_now())
            return
        if logs is None:
            raise ValueError("kube-bench Job did not complete within the time limit")
        # kube-bench prints JSON to stdout; extract the JSON object from the logs
        m = re.search(r"\{.*\}", logs, re.S)
        if not m:
            raise ValueError("kube-bench produced no JSON report")
        doc = json.loads(m.group(0))
        res, totals = kubebench._parse(doc)
        stats = kubebench._stats(totals)
        _log_append(run_id, "[api] completed - {} pass, {} fail, {} warn".format(stats["pass"], stats["fail"], stats["warn"]))
        update(run_id, status="completed", results=res, stats=stats, finished_at=_now())
        st.audit("cluster_nodebench_done", run_id=run_id, **{k: stats[k] for k in ("pass", "fail", "warn")})
    finally:
        # best-effort cleanup of the Job + pods
        try:
            k8s.delete(cfg, "/apis/batch/v1/namespaces/{}/jobs/{}?propagationPolicy=Background".format(_JOB_NS, name))
        except httpx.HTTPError:
            pass


# --------------------------------------------------------------------- serialization
def row(r):
    with _lock:
        has_log = bool(_logs.get(r.id))
    return {"id": r.id, "cluster_id": r.cluster_id, "cluster_name": r.cluster_name, "kind": r.kind,
            "status": r.status, "error": r.error, "options": r.options, "results": r.results, "stats": r.stats,
            "active": is_active(r.id), "has_log": has_log,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}


def summary(r):
    out = row(r)
    out.pop("results", None)
    return out
