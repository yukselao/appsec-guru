"""Tables. Schema changes go through a new Alembic revision in alembic/versions."""
from sqlalchemy import (BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, Numeric, Float,
                        String, Text, func)
from sqlalchemy.dialects.postgresql import JSONB

from .database import Base


class Setting(Base):
    """Key/value settings. Secrets (API keys, passwords) are stored encrypted in
    `secret_value` with the app secret key; `value` stays empty for them."""
    __tablename__ = "settings"
    key = Column(String(100), primary_key=True)
    value = Column(Text)
    secret_value = Column(LargeBinary)
    is_secret = Column(Boolean, nullable=False, server_default="false")
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class ScanRun(Base):
    """A WAS scan started from this tool (manually or by a scan profile schedule)."""
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True)
    profile_id = Column(Integer, ForeignKey("tenable_was_scans.id", ondelete="SET NULL"), index=True)
    sensor_id = Column(Integer, ForeignKey("sensors.id", ondelete="SET NULL"), index=True)
    trigger = Column(String(20), nullable=False, server_default="manual")
    name = Column(String(200), nullable=False)
    target_url = Column(Text, nullable=False)
    source_policy_id = Column(String(20))
    derived_policy_id = Column(String(20))
    families = Column(JSONB, nullable=False, server_default="[]")
    fast = Column(Boolean, nullable=False, server_default="false")
    debug_mode = Column(String(10), nullable=False, server_default="none")
    keep_objects = Column(Boolean, nullable=False, server_default="true")
    sc_scan_id = Column(String(20))
    sc_result_id = Column(String(20), index=True)
    scan_uuid = Column(String(40), index=True)
    status = Column(String(30), nullable=False, server_default="pending")
    error = Column(Text)
    log_file = Column(Text)
    log_counts = Column(JSONB, nullable=False, server_default="{}")
    findings = Column(JSONB, nullable=False, server_default="[]")
    summary = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))


class ScanRunEvent(Base):
    """Tool-side progress messages of a run (what the tool did, not scanner log lines)."""
    __tablename__ = "scan_run_events"
    id = Column(BigInteger, primary_key=True)
    run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    ts = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    level = Column(String(10), nullable=False)
    message = Column(Text, nullable=False)


class ScanLogStat(Base):
    """Per-minute scanner log metrics of a run, for the charts."""
    __tablename__ = "scan_log_stats"
    run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), primary_key=True)
    minute = Column(DateTime(timezone=True), primary_key=True)
    debug = Column(Integer, nullable=False, server_default="0")
    info = Column(Integer, nullable=False, server_default="0")
    notice = Column(Integer, nullable=False, server_default="0")
    warn = Column(Integer, nullable=False, server_default="0")
    error = Column(Integer, nullable=False, server_default="0")
    pages_audited = Column(Integer, nullable=False, server_default="0")
    plugins_started = Column(Integer, nullable=False, server_default="0")
    urls_found = Column(Integer, nullable=False, server_default="0")
    req_per_sec = Column(Numeric(8, 2))


class AuditLog(Base):
    """Every change this tool makes on SC or the scanner host."""
    __tablename__ = "audit_log"
    id = Column(BigInteger, primary_key=True)
    ts = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    action = Column(String(60), nullable=False)
    details = Column(JSONB, nullable=False, server_default="{}")
    client_ip = Column(String(64))


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id = Column(BigInteger, primary_key=True)
    session = Column(String(40), nullable=False, index=True)
    role = Column(String(12), nullable=False)
    content = Column(Text, nullable=False)
    model = Column(String(100))
    stats = Column(JSONB)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class SastRun(Base):
    """A SAST review of one repository by the sast-agent."""
    __tablename__ = "sast_runs"
    id = Column(Integer, primary_key=True)
    repo_url = Column(Text, nullable=False)
    ref = Column(String(200))
    commit = Column(String(64))
    status = Column(String(30), nullable=False, server_default="pending")
    model = Column(String(100))
    options = Column(JSONB, nullable=False, server_default="{}")
    stats = Column(JSONB, nullable=False, server_default="{}")
    error = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))


class SastFunction(Base):
    """A function extracted from the repository (function-extraction skill)."""
    __tablename__ = "sast_functions"
    id = Column(BigInteger, primary_key=True)
    run_id = Column(Integer, ForeignKey("sast_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    file = Column(Text, nullable=False)
    name = Column(Text, nullable=False)
    language = Column(String(20))
    start_line = Column(Integer)
    end_line = Column(Integer)
    params = Column(JSONB, nullable=False, server_default="[]")
    sinks = Column(JSONB, nullable=False, server_default="[]")
    route = Column(Text)
    priority = Column(Integer, nullable=False, server_default="0")
    status = Column(String(20), nullable=False, server_default="extracted")  # extracted|candidate|analysed|skipped|error
    verdict = Column(String(20))
    summary = Column(Text)
    agent_stats = Column(JSONB)


class SastFinding(Base):
    __tablename__ = "sast_findings"
    id = Column(BigInteger, primary_key=True)
    run_id = Column(Integer, ForeignKey("sast_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    function_id = Column(BigInteger, ForeignKey("sast_functions.id", ondelete="SET NULL"))
    file = Column(Text, nullable=False)
    line = Column(Integer)
    function = Column(Text)
    parameter = Column(Text)
    cwe = Column(String(20))
    title = Column(Text, nullable=False)
    severity = Column(String(10), nullable=False)
    confidence = Column(String(10), nullable=False)
    description = Column(Text)
    evidence = Column(Text)
    recommendation = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class SastEvent(Base):
    __tablename__ = "sast_events"
    id = Column(BigInteger, primary_key=True)
    run_id = Column(Integer, ForeignKey("sast_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    ts = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    level = Column(String(10), nullable=False)
    message = Column(Text, nullable=False)


class ScanFolder(Base):
    """Folder tree for scan profiles (parent_id NULL = top level)."""
    __tablename__ = "scan_folders"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    parent_id = Column(Integer, ForeignKey("scan_folders.id", ondelete="CASCADE"), index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class TenableWasScan(Base):
    """A saved DAST scan definition: target, policy, families, options, schedule."""
    __tablename__ = "tenable_was_scans"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    folder_id = Column(Integer, ForeignKey("scan_folders.id", ondelete="SET NULL"), index=True)
    sensor_id = Column(Integer, ForeignKey("sensors.id", ondelete="SET NULL"), index=True)
    target_url = Column(Text, nullable=False)
    source_policy_id = Column(String(20), nullable=False)
    families = Column(JSONB, nullable=False, server_default="[]")
    debug_mode = Column(String(10), nullable=False, server_default="none")
    scope = Column(String(10), nullable=False, server_default="fast")
    prefs = Column(JSONB, nullable=False, server_default="[]")
    keep_objects = Column(Boolean, nullable=False, server_default="true")
    repo_id = Column(Integer)
    zone_id = Column(Integer)
    credential_ids = Column(JSONB, nullable=False, server_default="[]")
    report_ids = Column(JSONB, nullable=False, server_default="[]")
    max_scan_time = Column(String(16), nullable=False, server_default="unlimited")
    inactivity_hours = Column(Integer, nullable=False, server_default="12")
    remove_unresponsive = Column(Boolean, nullable=False, server_default="true")
    schedule = Column(JSONB, nullable=False, server_default='{"type": "on_demand"}')
    enabled = Column(Boolean, nullable=False, server_default="true")
    next_run_at = Column(DateTime(timezone=True), index=True)
    last_run_at = Column(DateTime(timezone=True))
    last_run_id = Column(Integer)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class Sensor(Base):
    """A WAS scanner host reached over ssh (logs, debug level, processes).
    One Security Center, any number of sensors."""
    __tablename__ = "sensors"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False, server_default="22")
    username = Column(String(100), nullable=False, server_default="osadmin")
    password_enc = Column(LargeBinary)
    key_path = Column(Text)
    jump_host = Column(String(255))
    jump_user = Column(String(100))
    jump_password_enc = Column(LargeBinary)
    log_path = Column(Text, nullable=False, server_default="/var/log/nessus-was/scanner.log")
    sc_scanner_name = Column(String(200))
    zone_id = Column(Integer)
    is_default = Column(Boolean, nullable=False, server_default="false")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class FuzzRun(Base):
    """A Hidden Path Discovery (ffuf) run against a target URL."""
    __tablename__ = "fuzz_runs"
    id = Column(Integer, primary_key=True)
    target_url = Column(Text, nullable=False)
    wordlist = Column(String(300), nullable=False)
    extensions = Column(String(300))
    methods = Column(String(100), nullable=False, server_default="GET")
    match_codes = Column(String(200), nullable=False, server_default="200,204,301,302,307,401,403,405,500")
    filter_codes = Column(String(200))
    threads = Column(Integer, nullable=False, server_default="40")
    rate = Column(Integer, nullable=False, server_default="0")
    extra_headers = Column(JSONB, nullable=False, server_default="[]")
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    total_words = Column(Integer)
    hits = Column(JSONB, nullable=False, server_default="[]")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class SubdomainRun(Base):
    """A subdomain discovery run: subfinder -> dnsx -> httpx."""
    __tablename__ = "subdomain_runs"
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, server_default="pending")
    stage = Column(String(20))
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    subdomains = Column(JSONB, nullable=False, server_default="[]")
    results = Column(JSONB, nullable=False, server_default="[]")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class PortScanRun(Base):
    """A RustScan port scan of one target."""
    __tablename__ = "port_scan_runs"
    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False)
    ports = Column(String(200))
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="[]")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class NucleiRun(Base):
    """A Nuclei run (CVE / template vulnerability discovery) against a target URL."""
    __tablename__ = "nuclei_runs"
    id = Column(Integer, primary_key=True)
    target = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="[]")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class KatanaRun(Base):
    """A Katana crawl (endpoint discovery) of a target URL."""
    __tablename__ = "katana_runs"
    id = Column(Integer, primary_key=True)
    target = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="[]")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class SqlmapRun(Base):
    """A SQLMap run (SQL-injection detection) against a target URL."""
    __tablename__ = "sqlmap_runs"
    id = Column(Integer, primary_key=True)
    target = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="[]")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class CommixRun(Base):
    """A Commix run (OS command-injection detection) against a target URL."""
    __tablename__ = "commix_runs"
    id = Column(Integer, primary_key=True)
    target = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="[]")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class TrivyScan(Base):
    """A Trivy scan of a container image (vulnerabilities, secrets, misconfig, SBOM)."""
    __tablename__ = "trivy_scans"
    id = Column(Integer, primary_key=True)
    target = Column(Text, nullable=False)          # image reference
    digest = Column(String(120))                   # resolved image digest, when available
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="{}")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class Cluster(Base):
    """A registered Kubernetes cluster. The kubeconfig is stored encrypted with
    the app secret key; never returned to the UI. The API server must be
    reachable from the Docker network."""
    __tablename__ = "clusters"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    server = Column(Text)                          # display only (API server URL)
    context = Column(Text)                         # kubeconfig context name
    kubeconfig_enc = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ClusterScan(Base):
    """A scan against a registered cluster: posture (Kubescape), node CIS
    benchmark (kube-bench Job) or running-image inventory (feeds Trivy)."""
    __tablename__ = "cluster_scans"
    id = Column(Integer, primary_key=True)
    cluster_id = Column(Integer, ForeignKey("clusters.id", ondelete="SET NULL"))
    cluster_name = Column(Text)
    kind = Column(String(30), nullable=False)      # posture | node-bench | image-inventory
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="{}")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class Registry(Base):
    """A container registry connection. The access token/password is stored
    encrypted (token_enc) with the app secret key; never returned to the UI."""
    __tablename__ = "registries"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    host = Column(Text, nullable=False)            # e.g. ghcr.io, registry:5000
    username = Column(Text)
    token_enc = Column(LargeBinary)
    insecure = Column(Boolean, nullable=False, server_default="false")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class TrivyConfigScan(Base):
    """A Trivy misconfiguration / IaC scan (Dockerfile, K8s, Compose, Terraform)."""
    __tablename__ = "trivyconfig_scans"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)            # user label / filename
    kind = Column(String(40))                      # dockerfile | kubernetes | compose | terraform
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="{}")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class KubescapeScan(Base):
    """A Kubescape scan of Kubernetes manifests / Helm output against compliance
    frameworks (NSA, MITRE, CIS...). Manifest mode needs no cluster access."""
    __tablename__ = "kubescape_scans"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)            # user label for the manifest / source
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    score = Column(Float)                          # overall compliance score (0-100)
    options = Column(JSONB, nullable=False, server_default="{}")
    results = Column(JSONB, nullable=False, server_default="{}")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class KubeBenchScan(Base):
    """A kube-bench CIS Kubernetes benchmark run. Meaningful results require
    running on / targeting a real Kubernetes node (via a sensor)."""
    __tablename__ = "kubebench_scans"
    id = Column(Integer, primary_key=True)
    benchmark = Column(String(40), nullable=False)     # e.g. cis-1.9
    targets = Column(Text)                              # comma list: master,node,...
    status = Column(String(20), nullable=False, server_default="pending")
    error = Column(Text)
    results = Column(JSONB, nullable=False, server_default="{}")
    stats = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True))
