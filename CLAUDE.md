# AppSec Guru — project notes for Claude

Application-security cockpit for Tenable Security Center + WAS sensors, with an
offensive AI assistant. Docker Compose stack. User: Ali Okan Yüksel.

## Stack and layout

```
docker-compose.yml        postgres · migrate (alembic) · api (FastAPI) · php (Twig) · web (nginx)
.env / .env.example       all connection settings (SC, sensors, Ollama, PostgreSQL); .env is git-ignored
secrets/app_secret_key    encrypts UI-saved secrets (PyNaCl)
data/{postgres,sast,wordlists}   host bind mounts — no data lives in containers
api/                      FastAPI. main.py = routes; app/ = settings,conn,sensors,runs,profiles,fuzz,wasfindings,ai;
                          harness/ = agentic SAST + findings analysis; wastools/ = SC REST + ssh (shared with CLI tools)
db/                       alembic (versions 0001..0005) + wtdb/{database,models}.py
wwwroot/                  php-fpm + Twig. public/index.php routes; templates/pages/*.twig; public/assets/pages/*.js
ai/                       agentic harness definitions: agents/ skills/ tools/ (Markdown, read at run time)
```

Served on `http://127.0.0.1:8091` (`web_bind`/`web_port` in `.env`). nginx proxies
`/api/` to FastAPI (SSE and AI streams unbuffered) and `*.php` to php-fpm.

## Conventions

- **No data in containers.** PostgreSQL + logs + wordlists are host bind mounts.
- **Bind-mounted code.** Edit `api/` then `docker compose restart api`; `wwwroot/` and `ai/` need no restart.
- **Secrets from .env first, UI overrides.** `api/app/settings.py` FIELDS map keys to env vars; UI-saved values win and are encrypted.
- **One SC, many sensors.** `api/app/sensors.py`; scan profiles and runs reference a sensor; the default is used otherwise.
- **English UI.** All user-facing text is English. User messages go through `WT.ok/warn/fail` → top-right toasts (`wwwroot/public/assets/app.js`).
- **Palette.** Turquoise `#2f9c8b` + dark gray + black, pastel. Bootstrap vars overridden at the end of `app.css`. Brand = teal wolf.
- **Vendored assets** (jQuery, Bootstrap, Chart.js) are minified + gzipped under `wwwroot/public/assets/vendor/`; nginx serves `.gz`.

## Live environment (lab)

- Security Center `sc4` 192.168.1.54 (SC 6.9.1). Default WAS sensor `was4` 192.168.1.68 (scanner 2.113.12), ssh osadmin, sudo. Ollama 192.168.1.140:11434 (models incl. `gemma4:31b`). Juice Shop 192.168.1.82:3000.
- Credentials are in `.env` (git-ignored). osadmin password is shared by sc4 and was4; sudo available.

## How things work

- **Scan run** (`api/app/runs.py`): derive a policy copy with the chosen families/prefs, optionally enable debug, launch on SC, capture that scan's scanner log over ssh (matched by `[scanUuid=...]`), poll SC, pull findings, revert debug, clean up. `resume_orphans()` continues runs after an api restart.
- **Scheduler** (`api/app/profiles.py`): a thread wakes every 30s and starts due profiles.
- **Findings AI analysis** (`api/harness/analysis.py` + `report.py`): offensive-security agent returns findings-analysis JSON (attack paths, categories, recon from informational plugins); rendered to a standalone HTML report.
- **SAST** (`api/harness/sast.py` + `agent.py` + `extract.py` + `sinks.py`): clone → extract functions → rank by sink severity → the sast-agent reviews each argument with tools (`get_function`, `read_file`, `search_code`, `report_finding`). Tool-calling model, else JSON mode.
- **Hidden Path Discovery** (`api/app/fuzz.py`): ffuf in the api container; built-in wordlists seeded on start; ffuf `-json` input is base64 (decoded).

## Adding things

- **DB change:** edit `db/wtdb/models.py`, add `db/alembic/versions/000N_*.py`, `docker compose up -d migrate`.
- **API route:** add to `api/main.py` (router has `/api` prefix); restart api.
- **Page:** add to `PAGES` in `wwwroot/src/bootstrap.php`, a `templates/pages/*.twig` and `public/assets/pages/*.js`, an icon in `partials/icons.twig`.
- **Harness skill/agent/tool:** add a Markdown file under `ai/`; for a tool, implement it in `api/harness/tools.py` and list it on the agent.

## Related

Single-file CLI tools `../tsc-was-debug-scanctl.py`, `../tsc-was-scanmon.py` (Python 3.6,
stdlib only) share `wastools/`. Guide: `../was-notes.html`.
