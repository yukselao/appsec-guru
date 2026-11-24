#!/bin/sh
# One argv token per line, then "__END__" (see run-nuclei.sh). --batch forces the
# non-interactive run; stderr merged for the live log. The api builds and
# validates the whole argv and never includes os-shell/os-cmd or file flags.
set --
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  set -- "$@" "$l"
done
exec python /opt/commix/commix.py --batch "$@" 2>&1 </dev/null
