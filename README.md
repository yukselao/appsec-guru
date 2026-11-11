# AppSec Guru

A self-hosted application-security cockpit around **Tenable Security Center** and
its **WAS (Web Application Scanning)** sensors, with an offensive AI assistant.

> A Tenable Cyber Exchange project. Designed and developed with care by Ali Okan Yüksel.
> If it saves you time: [buy me a coffee](https://buymeacoffee.com/ayuksel).

## Demo

A motion tour of every screen — dashboard, scan wizard, offensive AI analysis,
live logs, subdomain/path/port discovery, SAST, sensors and more:

![AppSec Guru demo](docs/demo.gif)

Full-quality version: [`docs/demo.mp4`](docs/demo.mp4).

## What it does

| Area | Feature |
| --- | --- |
| **Dashboard** | Live view of scans running on Security Center and on each sensor, scanner load, log level, recent runs and findings. |
| **Hidden Path Discovery** | `ffuf`-based content discovery with built-in and uploadable wordlists. |
| **Scans** | Saved **scan profiles** in a folder tree, each with a target, policy, plugin families, sensor and a **schedule** (on-demand, once, interval, daily, weekly). A background scheduler runs them. |
| **Create Scan** | A step-by-step wizard: pick a target (or a built-in test app), compare policies, choose plugin families, set options, review and launch. |
| **Logs** | Live scanner-log stream (SSE) filtered to one scan, with level toggles, quick filters and per-10s charts. |
| **Scan Results** | Per-run detail: findings, captured log, activity charts, and the **offensive AI analysis** (attack paths, categories, reconnaissance from informational plugins, quick wins) rendered as a downloadable HTML report. |
| **Deploy Test Apps** | Ready `docker-compose.yml` snippets for OWASP Juice Shop, DVWA, WebGoat, Mutillidae, bWAPP, VAmPI and DVGA. |
| **SAST Scan** | An agentic harness clones a Git repo, extracts functions, and the offensive-security agent reviews each argument from source to sink with the local LLM. |
| **DevOps** | Copy-paste `curl` and CLI recipes for the whole REST API. |
| **Sensors** | One Security Center, many WAS scanner hosts; each a reusable ssh profile. |
| **AI assistant** | A chat (Ollama) on every page; attach on-screen logs, errors or scan status and ask. |

## Architecture

```
browser ── nginx ──┬── php-fpm (Twig pages in wwwroot/)
                   └── FastAPI (api/) ──┬── PostgreSQL (data, bind-mounted)
                                        ├── Tenable.sc REST API
                                        ├── ssh to each WAS sensor (logs, debug, processes)
                                        ├── ffuf (Hidden Path Discovery)
                                        └── Ollama (AI chat, findings analysis, SAST agent)
```

- **Services** (`docker-compose.yml`): `postgres`, `migrate` (Alembic), `api`, `php`, `web`.
- **No data in containers:** PostgreSQL, logs and wordlists are host bind mounts.
- **Bind-mounted code:** `api/`, `wwwroot/` and `ai/` are mounted read-only; a change needs only `docker compose restart api` (Python) or nothing (PHP/JS).
- **Agentic harness** in `ai/` (`agents/`, `skills/`, `tools/`) is read at run time; edit a Markdown file and the next run uses it.

## First run

```sh
cp .env.example .env            # set pg_password, sc_url + API keys, was_ssh_host, ollama_url
mkdir -p secrets
openssl rand -hex 32 > secrets/app_secret_key && chmod 600 secrets/app_secret_key
docker compose up -d --build
```

Open `http://127.0.0.1:8091` (set `web_bind=0.0.0.0` to reach it on the LAN).
Everything in **Settings** and **Sensors** can also come from `.env`; the UI overrides it.

### Configuration

`.env` holds the connection details (never committed; `.env.example` is the template):
Security Center URL + API keys, each WAS sensor's ssh host/credentials, the Ollama URL
and model, and PostgreSQL. Secrets saved from the UI are encrypted with `secrets/app_secret_key`.

## Day to day

```sh
docker compose restart api                 # after an api/ code change
docker compose logs -f api                 # api log (scheduler, runs, SAST)
docker compose exec postgres psql -U was_troubleshooter -d was_troubleshooter
docker compose down                        # stop (data stays on the host)
```

## Tenable Web App Scanning — CLI cheatsheet

Every screen is backed by the REST API at `http://127.0.0.1:8091/api`, so the whole
WAS workflow — create a scan, watch it live, read its log, cancel it — can be driven
from a terminal with `curl` + `jq`. The same recipes live on the **DevOps** page in the UI.

### 0 · Clone and prepare
```sh
git clone https://github.com/yukselao/appsec-guru.git
cd appsec-guru
mkdir -p secrets
openssl rand -hex 32 > secrets/app_secret_key && chmod 600 secrets/app_secret_key
```

### 1 · Write a ready-to-use `.env`
Paste this block to create a filled-in `.env`, then bring the stack up. Replace the
IPs / keys / passwords with your own — these are lab placeholders. `.env` is never committed.
```sh
cat > .env <<'EOF'
# ---- Tenable.sc ----
sc_url=https://10.0.0.54
sc_access_key=REPLACE_WITH_ACCESS_KEY
sc_secret_key=REPLACE_WITH_SECRET_KEY
sc_verify_tls=false

# ---- WAS scanner (ssh) ----
was_ssh_host=10.0.0.68
was_ssh_user=osadmin
was_ssh_password=REPLACE_WITH_SSH_PASSWORD
was_log_path=/var/log/nessus-was/scanner.log

# ---- AI assistant (Ollama) ----
ollama_url=http://10.0.0.140:11434
ollama_model=gemma4:31b

# ---- PostgreSQL ----
pg_user=was_troubleshooter
pg_password=REPLACE_WITH_DB_PASSWORD
pg_db=was_troubleshooter
pg_port=5439
pg_data_dir=./data/postgres

# ---- Stack ----
app_secret_key_file=./secrets/app_secret_key
ssh_dir=~/.ssh
web_bind=127.0.0.1
web_port=8091
tz=Europe/Istanbul
EOF
docker compose up -d --build
```

Set a base URL and confirm the sensor and a source policy to copy (AppSec Guru derives a
per-scan policy copy — your original is never modified):
```sh
export BASE=http://127.0.0.1:8091/api
curl -s $BASE/sensors     | jq '.[] | {id, name, host, default}'
curl -s $BASE/sc/policies | jq '.[] | {id, name}' | head
```
```json
{ "id": 1, "name": "was4", "host": "10.0.0.68", "default": true }
{ "id": "1000002", "name": "WAS Authentication Scan" }
```

### Create Scan
Launch an ad-hoc scan against a target with a source policy and chosen plugin families.
`debug` is one of `none` · `sc` · `host` · `both`; add `-H 'X-Sensor: 1'` to pick a sensor.
```sh
RUN=$(curl -s -X POST $BASE/scans -H 'Content-Type: application/json' -d '{
  "url":      "http://10.0.0.82:3000",
  "policy":   "1000002",
  "families": ["Authentication & Session", "Injection"],
  "fast":     true,
  "debug":    "both"
}' | jq -r .run_id)
echo "started run #$RUN"
```
```
started run #42
```

### List Scans
```sh
curl -s $BASE/scans | jq '.runs[] | {id, name, target_url, status, active, findings: .findings_count, severity}'
```
```json
{ "id": 42, "name": "guru-20260111-0815", "target_url": "http://10.0.0.82:3000",
  "status": "running",   "active": true,  "findings": 0,  "severity": {} }
{ "id": 41, "name": "nightly-juice",      "target_url": "http://10.0.0.82:3000",
  "status": "completed", "active": false, "findings": 17,
  "severity": { "High": 2, "Medium": 6, "Low": 9 } }
```

### Check logs of a running scan
Glance at progress, then tail or live-stream the scanner log straight from the sensor:
```sh
curl -s $BASE/scans/$RUN | jq '{status, counts: .log_counts, uuid: .scan_uuid, sc_result_id}'
```
```json
{ "status": "running",
  "counts": { "DEBUG": 820, "INFO": 2143, "WARN": 7, "ERROR": 0 },
  "uuid": "4f9c8b1e-…", "sc_result_id": "15002" }
```
```sh
# last 20 captured lines, filtered to the levels you care about
curl -s "$BASE/scans/$RUN/log?tail=20&level=INFO,WARN,ERROR" | jq -r '.lines[]'
```
```
2026-01-11 08:16:03 [INFO] [scanUuid=4f9c…] crawl: 128 URLs queued, 41 audited
2026-01-11 08:16:07 [INFO] [scanUuid=4f9c…] plugin 98058 (SQL Injection) started
2026-01-11 08:16:11 [WARN] [scanUuid=4f9c…] 503 from target, backing off 2s
```
```sh
# or follow the live SSE stream, matched to this run's scan UUID (Ctrl-C to stop)
UUID=$(curl -s $BASE/scans/$RUN | jq -r .scan_uuid)
curl -sN "$BASE/logs/stream?uuid=$UUID"
```

### Check logs of a completed scan
The full captured log stays with the run — filter it, or download the whole file:
```sh
curl -s "$BASE/scans/$RUN/log?level=WARN,ERROR" | jq -r '.lines[]'
curl -s  $BASE/scans/$RUN/log/download -o was-run-$RUN.log
```
And the findings the scan produced:
```sh
curl -s $BASE/scans/$RUN | jq '.findings[] | {plugin_id, severity, family, name}'
```
```json
{ "plugin_id": 98058, "severity": "High", "family": "Injection", "name": "SQL Injection" }
{ "plugin_id": 112526, "severity": "Medium", "family": "Authentication & Session", "name": "Session Token in URL" }
```
Want the offensive-AI write-up? Kick it off and pull the HTML report:
```sh
curl -s -X POST $BASE/scans/$RUN/analyze -d '{}'            # runs the agent
curl -s $BASE/scans/$RUN/report -o report-$RUN.html         # standalone report
```

### Cancel a Scan
```sh
curl -s -X POST $BASE/scans/$RUN/cancel | jq
```
```json
{ "cancelled": true }
```
AppSec Guru stops the scan on Security Center, reverts any debug settings it enabled on
the sensor, and marks the run `cancelled`. A `false` result means the run had already finished.

## The single-file CLI tools

`../tsc-was-debug-scanctl.py` and `../tsc-was-scanmon.py` (Python 3.6, standard library
only) do the same scan + debug-log work from a terminal on the Security Center host.
See the **DevOps** page for recipes and `../was-notes.html` for the full guide.

## Security

- The UI has no login; publish it on `127.0.0.1` or behind your own gateway.
- It connects to real scanners and starts real scans — point it at systems you are authorised to test.
- The test apps under **Deploy Test Apps** are intentionally vulnerable; run them on an isolated lab host only.
