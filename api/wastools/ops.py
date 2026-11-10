from .core import *  # noqa: F401,F403
from .core import _OUT  # noqa: F401
# ---------------------------------------------------------------------------
# ops: policy derivation and WAS scan creation
# ---------------------------------------------------------------------------
def local_db_families(pid):
    """Fallback verification on the SC host itself (osadmin + sudo -n)."""
    if not os.path.isdir("/opt/sc"):
        return None
    sh = ("for f in /opt/sc/orgs/*/organization.db; do "
          "/opt/sc/support/bin/sqlite3 -readonly \"$f\" "
          "\"select familyID from PolicyFamily where policyID={} and type='enabled'\" 2>/dev/null; done").format(int(pid))
    try:
        out = subprocess.check_output(["sudo", "-n", "sh", "-c", sh], stderr=subprocess.DEVNULL,
                                      universal_newlines=True, timeout=30)
    except Exception:
        return None
    ids = sorted(set(l.strip() for l in out.splitlines() if l.strip()))
    return ids


def current_families(sc, pid):
    pol = sc.policy(pid, fields="id,families")
    ids = family_ids_from_policy(pol)
    if ids is not None:
        return ids, "api"
    ids = local_db_families(pid)
    if ids is not None:
        return ids, "sc-db"
    return None, None


def set_policy_families(sc, pid, fam_ids, audit):
    """WAS (template 40) family payload is not documented; try known shapes and
    keep the first one that verifies."""
    want = sorted(str(i) for i in fam_ids)
    variants = [
        ("id", {"families": [{"id": i} for i in want]}),
        ("id+state", {"families": [{"id": i, "state": "unlocked"} for i in want]}),
        ("id+type+state", {"families": [{"id": i, "type": "enabled", "state": "unlocked"} for i in want]}),
    ]
    errors = []
    for label, body in variants:
        try:
            sc.patch("policy/{}".format(pid), body)
        except SCError as exc:
            errors.append("{}: {}".format(label, exc))
            continue
        got, src = current_families(sc, pid)
        audit.write("policy_patch_families", policy_id=pid, variant=label, families=want, verified_by=src)
        if got is None:
            warn("aileler API'den okunamiyor ve SC veritabani yerelde yok; '{}' bicimi dogrulanamadi".format(label))
            return label, None
        if got == want:
            ok("aileler dogrulandi ({}): {}".format(src, ", ".join(got)))
            return label, src
        errors.append("{}: kabul edildi ama okunan aileler {}".format(label, got))
    die("aile ayari dogrulanamadi. Denenenler:\n  " + "\n  ".join(errors))


def set_policy_prefs(sc, pid, prefs, audit):
    if not prefs:
        return
    tries = [("dict", {"preferences": dict(prefs)}),
             ("list", {"preferences": [{"name": k, "value": v} for k, v in prefs.items()]})]
    errors = []
    for label, body in tries:
        try:
            sc.patch("policy/{}".format(pid), body)
        except SCError as exc:
            errors.append("{}: {}".format(label, exc))
            continue
        got = prefs_dict(sc.policy(pid, fields="id,preferences"))
        bad = dict((k, got.get(k)) for k, v in prefs.items() if str(got.get(k)) != str(v))
        audit.write("policy_patch_prefs", policy_id=pid, variant=label,
                    prefs=dict((k, ("***" if SECRET_PREF_RE.search(k) else v)) for k, v in prefs.items()))
        if not bad:
            ok("tercihler dogrulandi: {}".format(", ".join("{}={}".format(k, v) for k, v in prefs.items())))
            return
        errors.append("{}: farkli kalanlar {}".format(label, bad))
    die("tercihler yazilamadi:\n  " + "\n  ".join(errors))


def parse_sets(items):
    out = {}
    for it in items or []:
        if "=" not in it:
            die("--set bicimi 'ad=deger' olmali: {}".format(it))
        k, v = it.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def derive_policy(sc, src_ref, name, families_spec, fast, sets, audit):
    src_id = sc.resolve_policy(src_ref)
    src = sc.policy(src_id, fields="id,name,modifiedTime,policyTemplate")
    tpl = (src.get("policyTemplate") or {}).get("id")
    if str(tpl) != WAS_TEMPLATE_ID:
        warn("kaynak politika sablonu {} (WAS=40 bekleniyordu)".format(tpl))
    src_mtime = src.get("modifiedTime")
    info("kaynak: {} '{}' kopyalaniyor -> '{}'".format(src_id, src.get("name"), name))
    try:
        new = sc.post("policy/{}/copy".format(src_id), {"name": name})
    except SCError as exc:
        die("politika kopyalanamadi: {}".format(exc))
    new_id = str(new.get("id"))
    audit.write("policy_copy", source_id=src_id, policy_id=new_id, name=name)
    if new.get("name") != name:
        sc.patch("policy/{}".format(new_id), {"name": name})
    ok("yeni politika id {}".format(new_id))
    if families_spec:
        fams = resolve_families(sc, families_spec)
        info("acilacak aileler: {}".format(", ".join("{} ({})".format(n, i) for i, n in fams)))
        set_policy_families(sc, new_id, [i for i, _ in fams], audit)
    prefs = {}
    if fast:
        prefs.update(FAST_PREFS)
    prefs.update(sets or {})
    set_policy_prefs(sc, new_id, prefs, audit)
    after = sc.policy(src_id, fields="id,modifiedTime")
    if str(after.get("modifiedTime")) != str(src_mtime):
        warn("KAYNAK politikanin modifiedTime degeri degisti ({} -> {})!".format(src_mtime, after.get("modifiedTime")))
    else:
        ok("kaynak politika {} degismedi".format(src_id))
    return new_id


def pick_repo(sc, repo):
    if repo:
        return int(repo)
    repos = sc.repositories()
    if len(repos) == 1:
        return int(repos[0]["id"])
    table([[r.get("id"), r.get("name"), r.get("dataFormat")] for r in repos], ["id", "ad", "format"])
    die("birden fazla repository var, --repo ile sec")


def create_was_scan(sc, name, policy_id, url, repo_id, zone_id, desc):
    body = {
        "name": name,
        "description": desc,
        "type": "policy",
        "policy": {"id": str(policy_id)},
        "repository": {"id": int(repo_id)},
        "schedule": {"type": "template"},
        "urlList": url,
        "emailOnLaunch": "false",
        "emailOnFinish": "false",
        "reports": [],
        "credentials": [],
        "timeoutAction": "rollover",
        "rolloverType": "template",
        "maxScanTime": "unlimited",
        "inactivityTimeout": 43200,
        "classifyMitigatedAge": 0,
    }
    if zone_id is not None:
        body["zone"] = {"id": int(zone_id)}
    return sc.post("wasScan", body)


def download_result(sc, rid, out_dir, wait=180):
    path = os.path.join(out_dir, "scanResult-{}.zip".format(rid))
    t0 = time.time()
    while True:
        try:
            r = sc.call("POST", "scanResult/{}/download".format(rid), body={"downloadType": "v2"}, raw=True)
            with open(path, "wb") as fh:
                shutil.copyfileobj(r, fh, 65536)
            ok("tarama sonucu indirildi: {} ({} KB)".format(path, os.path.getsize(path) // 1024))
            return path
        except SCPending as exc:
            if time.time() - t0 > wait:
                warn("sonuc {} sn icinde hazir olmadi: {}".format(wait, exc))
                return None
            time.sleep(5)
        except SCError as exc:
            warn("sonuc indirilemedi: {}".format(exc))
            return None
