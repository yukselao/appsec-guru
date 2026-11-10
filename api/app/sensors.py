"""Sensors: WAS scanner hosts. Passwords are encrypted with the app secret key.
The first sensor is created from the .env WAS_SSH_* values."""
from sqlalchemy import select, update as sql_update

from wtdb.database import session_scope
from wtdb.models import Sensor

from . import settings as st

FIELDS = ("name", "description", "host", "port", "username", "key_path", "jump_host", "jump_user", "log_path",
          "sc_scanner_name", "zone_id")
SECRETS = {"password": "password_enc", "jump_password": "jump_password_enc"}
_version = {"n": 0}


def version():
    return _version["n"]


def _bump():
    _version["n"] += 1


def _enc(v):
    return st._secretbox().encrypt(v.encode("utf-8")) if v else None


def _dec(b):
    return st._secretbox().decrypt(b).decode("utf-8") if b else ""


def row(s, secrets=False):
    out = {k: getattr(s, k) for k in FIELDS}
    out.update({"id": s.id, "is_default": s.is_default,
                "updated_at": s.updated_at.isoformat() if s.updated_at else None})
    for k, col in SECRETS.items():
        out[k] = _dec(getattr(s, col)) if secrets else (st.SECRET_MASK if getattr(s, col) else "")
    return out


def all_rows():
    with session_scope() as s:
        return [row(x) for x in s.execute(select(Sensor).order_by(Sensor.is_default.desc(), Sensor.name)).scalars()]


def get(sensor_id=None, secrets=False):
    """A sensor by id, or the default one."""
    with session_scope() as s:
        x = s.get(Sensor, int(sensor_id)) if sensor_id else None
        if x is None:
            x = s.execute(select(Sensor).order_by(Sensor.is_default.desc(), Sensor.id)).scalars().first()
        return row(x, secrets=secrets) if x else None


def save(sensor_id, data):
    name = str(data.get("name") or "").strip()
    host = str(data.get("host") or "").strip()
    if not name or not host:
        raise ValueError("name and host are required")
    with session_scope() as s:
        x = s.get(Sensor, int(sensor_id)) if sensor_id else Sensor()
        if sensor_id and not x:
            raise ValueError("sensor not found")
        for k in FIELDS:
            if k in data:
                v = data[k]
                if k in ("port", "zone_id"):
                    v = int(v) if v not in (None, "") else (22 if k == "port" else None)
                elif isinstance(v, str):
                    v = v.strip() or None
                setattr(x, k, v)
        x.name, x.host = name, host
        x.log_path = x.log_path or "/var/log/nessus-was/scanner.log"
        x.username = x.username or "osadmin"
        for k, col in SECRETS.items():
            if k in data and data[k] != st.SECRET_MASK:
                setattr(x, col, _enc(data[k] or ""))
        if not sensor_id:
            s.add(x)
        s.flush()
        if data.get("is_default") or s.execute(select(Sensor)).scalars().first() is x:
            s.execute(sql_update(Sensor).values(is_default=False))
            x.is_default = True
        sid = x.id
    _bump()
    return sid


def make_default(sensor_id):
    with session_scope() as s:
        s.execute(sql_update(Sensor).values(is_default=False))
        s.get(Sensor, int(sensor_id)).is_default = True
    _bump()


def delete(sensor_id):
    with session_scope() as s:
        x = s.get(Sensor, int(sensor_id))
        if not x:
            return
        was_default = x.is_default
        s.delete(x)
        s.flush()
        if was_default:
            other = s.execute(select(Sensor).order_by(Sensor.id)).scalars().first()
            if other:
                other.is_default = True
    _bump()


def seed_from_env():
    """First start: create a sensor from WAS_SSH_* (.env) when the table is empty."""
    with session_scope() as s:
        if s.execute(select(Sensor)).scalars().first():
            return None
    c = st.get_all(include_secrets=True)
    if not c["ssh.host"]:
        return None
    return save(None, {"name": c["ssh.host"], "description": "created from .env", "host": c["ssh.host"],
                       "port": c["ssh.port"], "username": c["ssh.user"], "password": c["ssh.password"],
                       "key_path": c["ssh.key_path"], "jump_host": c["ssh.jump_host"], "jump_user": c["ssh.jump_user"],
                       "jump_password": c["ssh.jump_password"], "log_path": c["ssh.log_path"], "is_default": True})
