#!/bin/sh
# Protocol: argv tokens one per line until __END__, then the manifest YAML on
# stdin until EOF. We scan it offline and emit progress, then a sentinel and the
# JSON report. argv is built and whitelisted by the API; it is never eval'd.
set --
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  set -- "$@" "$l"
done
tmp=$(mktemp /tmp/ks-XXXXXX.yaml)
cat > "$tmp"
out=$(mktemp /tmp/ksout-XXXXXX.json)
kubescape "$@" "$tmp" --use-artifacts-from /artifacts --format json --output "$out" </dev/null 2>&1
echo "__KUBESCAPE_JSON__"
cat "$out" 2>/dev/null
rm -f "$tmp" "$out"
