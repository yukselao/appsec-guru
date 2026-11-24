#!/bin/sh
# argv tokens one per line until __END__, then run kube-bench and return its
# native JSON after a sentinel. argv is built and whitelisted by the API.
cd /opt/kube-bench 2>/dev/null || exit 1
set --
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  set -- "$@" "$l"
done
out=$(mktemp)
kube-bench "$@" --json 2>&1 1>"$out"
echo "__KUBEBENCH_JSON__"
cat "$out" 2>/dev/null
rm -f "$out"
