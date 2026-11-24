#!/bin/sh
# Request: one argv token per line, then "__END__". Each line becomes a literal
# argument (no eval, no word-splitting), so URLs/tags with special characters are
# safe. The api builds and validates the whole argv. JSONL output is forced here;
# stderr is merged so progress/errors show in the live log (the api parses only
# the lines that start with '{').
set --
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  set -- "$@" "$l"
done
exec nuclei -jsonl -no-color "$@" 2>&1 </dev/null
