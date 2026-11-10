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
| httpx | 7003 | host list | JSON per host (status, title, tech) |
| RustScan | 7004 | `<target> [ports]` | `host -> [open ports]` |

Adding a tool: drop `Dockerfile.<tool>`, `run-<tool>.sh` (reads the request,
runs the tool, writes stdout) and `serve-<tool>.sh` (the socat listener), add a
`recon-<tool>` service to `docker-compose.yml`, and a small client in `api/app`.
