"""Security Center client and per-sensor ssh connections, rebuilt when the
settings or the sensor definitions change."""
import threading

from wastools.core import SC, SSH, Fatal, WasHost

from . import sensors
from . import settings as st

_lock = threading.Lock()
_cache = {"ver": None, "sc": None, "was": {}}


def _cfg():
    return st.get_all(include_secrets=True)


def _reset_if_stale():
    ver = (st.version(), sensors.version())
    if _cache["ver"] != ver:
        _cache.update({"ver": ver, "sc": None, "was": {}})


def sc():
    with _lock:
        _reset_if_stale()
        if _cache["sc"] is None:
            c = _cfg()
            if not c["sc.url"]:
                raise Fatal("Security Center URL is not set (Settings > Security Center)")
            _cache["sc"] = SC(c["sc.url"], c["sc.access_key"], c["sc.secret_key"],
                              verify=c["sc.verify_tls"] == "true", timeout=45)
        return _cache["sc"]


def sensor(sensor_id=None):
    s = sensors.get(sensor_id, secrets=True)
    if not s:
        raise Fatal("no sensor is defined (Sensors > Add sensor)")
    return s


def was(sensor_id=None):
    """WasHost (ssh) for a sensor; the default sensor when sensor_id is empty."""
    s = sensor(sensor_id)
    with _lock:
        _reset_if_stale()
        w = _cache["was"].get(s["id"])
        if w is None:
            jump, jump_user, jump_pw = s["jump_host"] or None, s["jump_user"] or None, s["jump_password"] or None
            if jump == "sc":  # reach the scanner through the Security Center host
                c = _cfg()
                jump, jump_user, jump_pw = c["sc.ssh_host"], c["sc.ssh_user"], c["sc.ssh_password"] or None
            ssh = SSH(s["host"], user=s["username"] or "osadmin", port=int(s["port"] or 22),
                      password=s["password"] or None, key=s["key_path"] or None,
                      jump=jump, jump_user=jump_user, jump_password=jump_pw)
            w = WasHost(ssh, s["log_path"] or "/var/log/nessus-was/scanner.log")
            w.sensor = {"id": s["id"], "name": s["name"]}
            _cache["was"][s["id"]] = w
        return w


def sc_host():
    """ssh to the Security Center host itself (diagnostics, jump host)."""
    c = _cfg()
    if not c["sc.ssh_host"]:
        raise Fatal("Security Center ssh is not set (Settings > Security Center)")
    return SSH(c["sc.ssh_host"], user=c["sc.ssh_user"] or "osadmin", port=int(c["sc.ssh_port"] or 22),
               password=c["sc.ssh_password"] or None)


def drop_was(sensor_id=None):
    with _lock:
        if sensor_id is None:
            _cache["was"] = {}
        else:
            _cache["was"].pop(int(sensor_id), None)
