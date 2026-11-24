#!/bin/sh
# One argv token per line, then "__END__" (see run-nuclei.sh). JSONL output is
# forced; stderr merged for progress. The api builds/validates the argv.
set --
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  set -- "$@" "$l"
done
exec katana -jsonl -silent -no-color "$@" 2>&1 </dev/null
