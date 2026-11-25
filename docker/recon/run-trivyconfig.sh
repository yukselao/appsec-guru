#!/bin/sh
# Trivy misconfiguration / IaC scanning (Dockerfile, Kubernetes YAML, Docker
# Compose, Terraform) over TCP (socat), port 7012. Distinct protocol from the
# image scan (run-trivy.sh): line 1 is a filename hint (Trivy auto-detects the
# config type from the name + content), then "__END__", then the raw file
# content until EOF (the client half-closes the socket). The misconfiguration
# check bundle is baked into the image at build time; --skip-check-update keeps
# the scan offline and pinned. Progress goes to the socket first, then a
# sentinel, then the JSON report (collected and parsed by the api, no AI).
IFS= read -r fname
while IFS= read -r l; do [ "$l" = "__END__" ] && break; done
d=$(mktemp -d)
fname=$(basename "$fname" 2>/dev/null)
[ -z "$fname" ] && fname=Dockerfile
cat > "$d/$fname"
out=$(mktemp)
trivy config "$d" --format json --skip-check-update --cache-dir /root/.cache/trivy 2>&1 1>"$out" </dev/null
echo "__TRIVYCONFIG_JSON__"
cat "$out"
rm -rf "$d" "$out"
