#!/bin/sh
# Live cluster posture scan. Protocol: argv tokens one per line until __END__
# (e.g. "scan framework nsa,mitre"), then the kubeconfig on stdin until EOF. We
# scan the live cluster the kubeconfig points at, using the baked offline
# artifacts, and emit progress then a sentinel then the JSON report. argv is
# built and whitelisted by the API; it is never eval'd. The API server must be
# reachable from this container's network.
set --
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  set -- "$@" "$l"
done
kc=$(mktemp /tmp/kc-XXXXXX.yaml)
cat > "$kc"
out=$(mktemp /tmp/ksc-XXXXXX.json)
kubescape "$@" --kubeconfig "$kc" --use-artifacts-from /artifacts --format json --output "$out" </dev/null 2>&1
echo "__KUBESCAPE_JSON__"
cat "$out" 2>/dev/null
rm -f "$kc" "$out"
