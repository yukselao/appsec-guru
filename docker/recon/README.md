# Open-source tool containers — deterministic I/O contract

Each OSS tool (subfinder, dnsx, httpx, RustScan) runs in its **own container**,
built from the official upstream image plus `socat`, and exposes a single TCP
port with one **standard request/response contract**:

1. The API opens a TCP connection to the tool's port.
2. It writes the request: one item per line (a domain, a host list, or
   `<target> [ports]`), then a final line `__END__`.
3. The container's `run.sh` reads lines until `__END__` into a temp file, runs
   the tool against that file (tool stdin is redirected from `/dev/null` so the
   tool never blocks on the socket), and streams the tool's stdout back.
4. The API reads the response until EOF, then closes.

This makes every tool **deterministic**: the same input always produces the same
framing, with no dependence on TCP half-close propagation (which socat does not
forward to an `EXEC` child). Output is one record per line — plain text
(subfinder: subdomains; RustScan: `host -> [ports]`) or JSON (dnsx, httpx).

| Tool | Port | Input | Output |
| --- | --- | --- | --- |
| subfinder | 7001 | one domain | subdomains, one per line |
| dnsx | 7002 | host list | JSON per host (A/AAAA/CNAME/MX/NS/TXT) |
| httpx | 7003 | optional `__OPTS__` line, host list | JSON per host (status, title, tech) |
| RustScan | 7004 | `<target> [ports]` | `host -> [open ports]` |
| Nuclei | 7005 | one argv token per line | JSONL findings (merged stderr) |
| Katana | 7006 | one argv token per line | JSONL endpoints (merged stderr) |
| SQLMap | 7007 | one argv token per line | verbose log (merged stderr) |
| Commix | 7008 | one argv token per line | verbose log (merged stderr) |

The offensive tools (Nuclei/Katana/SQLMap/Commix) use a **one-argument-per-line**
framing: the api sends the whole, already-validated argv — one argument per line —
then `__END__`; `run-<tool>.sh` reads each line as a literal argument into `"$@"`
and `exec`s the tool (no `eval`, no word-splitting), so URLs, cookies and POST
data with special characters are safe. The container forces the non-interactive /
machine-output flags (`-jsonl`, `--batch`) and merges stderr so progress shows in
the live log. The api is responsible for all safety: it validates the target URL
and only ever emits a fixed whitelist of flags, with user strings used only as
flag *values* — never as flag names, and never exploitation/file/shell flags.

httpx also accepts one optional first line with numeric options:
`__OPTS__ timeout=10 threads=50 rate_limit=150 retries=0 max=905`. Unknown keys
and non-numeric values are ignored. The values, the idle limit and the stage
limit come from Settings > Subdomain Discovery. When a limit stops a stage early,
the run is stored with an "incomplete" message.

Adding a tool: drop `Dockerfile.<tool>`, `run-<tool>.sh` (reads the request,
runs the tool, writes stdout) and `serve-<tool>.sh` (the socat listener), add a
`recon-<tool>` service to `docker-compose.yml`, and a small client in `api/app`.
