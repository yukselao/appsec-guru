"""Subdomain discovery: subfinder -> dnsx -> httpx, each in its own container,
reached over TCP (socat). Runs asynchronously; results stream into PostgreSQL."""
import json
import logging
import os
import re
import socket
import threading
import time

from sqlalchemy import select

from wtdb.database import session_scope
from wtdb.models import SubdomainRun

from . import settings as st

log = logging.getLogger("recon")
SUBFINDER = os.environ.get("RECON_SUBFINDER", "recon-subfinder:7001")
DNSX = os.environ.get("RECON_DNSX", "recon-dnsx:7002")
HTTPX = os.environ.get("RECON_HTTPX", "recon-httpx:7003")
DOMAIN_RX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
_active = {}
_lock = threading.Lock()


def _hostport(hp):
    host, port = hp.rsplit(":", 1)
    return host, int(port)


# Deterministic OSS-tool contract: send the request lines then the "__END__"
# sentinel; the tool runs and streams its output back; read until EOF.
SENTINEL = "__END__"


# Optional first request line with "key=value" pairs; only httpx reads it.
OPTS = "__OPTS__"
HTTPX_OPTS = ("timeout", "threads", "rate_limit", "retries")


def stream_tool(hp, lines, idle=180, total=900):
    """Returns (output, reason). reason is None when the tool finished, else why
    reading stopped early: the output is then incomplete."""
    host, port = _hostport(hp)
    reason = None
    deadline = time.monotonic() + total
    s = socket.create_connection((host, port), timeout=15)
    try:
        s.sendall(("\n".join(lines) + "\n" + SENTINEL + "\n").encode("utf-8"))
        buf = b""
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                reason = "reached the stage limit of {} s".format(total)
                break
            s.settimeout(min(idle, left))
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                if time.monotonic() >= deadline:
                    continue
                reason = "sent nothing for {} s".format(idle)
                break
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", "replace"), reason
    finally:
        s.close()


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
        for r in s.execute(select(SubdomainRun).where(SubdomainRun.status.in_(["pending", "running"]))).scalars():
            r.status = "interrupted"
            r.error = "the api restarted during the run"


def update(run_id, **f):
    with session_scope() as s:
        r = s.get(SubdomainRun, run_id)
        for k, v in f.items():
            setattr(r, k, v)


def start(params, client_ip=None):
    domain = (params.get("domain") or "").strip().lower().lstrip(".")
    domain = re.sub(r"^\w+://", "", domain).split("/")[0]
    if not DOMAIN_RX.match(domain):
        raise ValueError("enter a valid domain, e.g. example.com")
    cfg = st.get_all()
    if params.get("timeout"):
        cfg["recon.stage_timeout"] = params["timeout"]  # per-run override from the form
    opts = {"resolve": params.get("resolve", True), "probe_http": params.get("probe_http", True),
            "timeout": st.get_int("recon.stage_timeout", cfg), "idle": st.get_int("recon.idle_timeout", cfg),
            "httpx": {k: st.get_int("recon.httpx_" + k, cfg) for k in HTTPX_OPTS}}
    with session_scope() as s:
        r = SubdomainRun(domain=domain, status="pending", options=opts)
        s.add(r)
        s.flush()
        run_id = r.id
    st.audit("subdomain_run_create", client_ip=client_ip, run_id=run_id, domain=domain)
    ev = threading.Event()
    with _lock:
        _active[run_id] = ev
    threading.Thread(target=_run, args=(run_id, domain, opts, ev), name="recon-%d" % run_id, daemon=True).start()
    return run_id


def _run(run_id, domain, opts, cancel_ev):
    limits = {"idle": opts["idle"], "total": opts["timeout"]}
    cut = []  # stages that stopped before the tool finished

    def tool(stage, hp, lines):
        out, reason = stream_tool(hp, lines, **limits)
        if reason:
            cut.append("{} {}".format(stage, reason))
            log.warning("recon %s: %s %s", run_id, stage, reason)
        return out

    try:
        update(run_id, status="running", stage="subfinder")
        sub = tool("subfinder", SUBFINDER, [domain])
        subs = sorted(set(l.strip() for l in sub.splitlines() if l.strip() and "." in l))
        update(run_id, subdomains=subs, stats={"subdomains": len(subs)})
        if cancel_ev.is_set():
            update(run_id, status="cancelled", finished_at=_now())
            return
        by_host = {h: {"host": h} for h in subs}
        if opts["resolve"] and subs:
            update(run_id, stage="dnsx")
            dns = tool("dnsx", DNSX, subs)
            for line in dns.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                h = d.get("host")
                if h in by_host:
                    by_host[h].update({"a": d.get("a") or [], "aaaa": d.get("aaaa") or [], "cname": d.get("cname") or [],
                                       "mx": d.get("mx") or [], "ns": d.get("ns") or [], "txt": d.get("txt") or [],
                                       "resolved": True})
            update(run_id, results=sorted(by_host.values(), key=lambda r: r["host"]),
                   stats={"subdomains": len(subs), "resolved": sum(1 for r in by_host.values() if r.get("resolved"))})
        if cancel_ev.is_set():
            _finalize(run_id, by_host, "cancelled")
            return
        if opts["probe_http"] and subs:
            update(run_id, stage="httpx")
            # the tool also stops itself, shortly after the api stops reading
            head = " ".join([OPTS] + ["{}={}".format(k, opts["httpx"][k]) for k in HTTPX_OPTS] +
                            ["max={}".format(opts["timeout"] + 5)])
            http = tool("httpx", HTTPX, [head] + subs)
            for line in http.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                h = (d.get("input") or d.get("host") or "").strip()
                h = re.sub(r"^\w+://", "", h).split("/")[0].split(":")[0]
                if h in by_host:
                    by_host[h].setdefault("http", []).append({
                        "url": d.get("url"), "status": d.get("status_code") or d.get("status-code"),
                        "title": d.get("title"), "tech": d.get("tech") or d.get("technologies") or [],
                        "webserver": d.get("webserver")})
        if cut:
            update(run_id, error="Results are incomplete: {}. Raise the limits in Settings > Subdomain Discovery.".format("; ".join(cut)))
        _finalize(run_id, by_host, "completed")
    except (OSError, socket.error) as exc:
        update(run_id, status="failed", error="recon tool unreachable ({}). Are the recon-* containers running?".format(exc),
               finished_at=_now())
    except Exception as exc:
        log.exception("recon %s", run_id)
        update(run_id, status="failed", error=str(exc), finished_at=_now())
    finally:
        with _lock:
            _active.pop(run_id, None)


def _finalize(run_id, by_host, status):
    results = sorted(by_host.values(), key=lambda r: r["host"])
    live = sum(1 for r in results if r.get("http"))
    resolved = sum(1 for r in results if r.get("resolved"))
    update(run_id, results=results, status=status, stage=None, finished_at=_now(),
           stats={"subdomains": len(results), "resolved": resolved, "live_http": live})
    st.audit("subdomain_run_done", run_id=run_id, subdomains=len(results), live=live)


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def summary(r):
    """History row: everything except the (large) result lists."""
    return {k: v for k, v in row(r).items() if k not in ("subdomains", "results")}


def row(r):
    return {"id": r.id, "domain": r.domain, "status": r.status, "stage": r.stage, "error": r.error, "options": r.options,
            "subdomains": r.subdomains, "results": r.results, "stats": r.stats, "active": is_active(r.id),
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None}
