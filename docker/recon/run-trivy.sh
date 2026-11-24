#!/bin/sh
# Request: one argv token per line, then "__END__" (see run-nuclei.sh). Each line
# becomes a literal argument (no eval). The api builds and validates the whole
# argv. Trivy prints progress to stderr and the JSON report to stdout, so we send
# progress live first, then a sentinel, then the JSON report (which the api
# collects and parses). JSON format and the baked offline DB are forced here.
set --
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  set -- "$@" "$l"
done
tmp=$(mktemp)
# stderr (progress) -> socket, stdout (JSON) -> tmp file
trivy "$@" --format json --skip-db-update --cache-dir /root/.cache/trivy 2>&1 1>"$tmp" </dev/null
echo "__TRIVY_JSON__"
cat "$tmp"
rm -f "$tmp"
