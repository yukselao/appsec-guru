#!/bin/sh
# One argv token per line, then "__END__" (see run-nuclei.sh). --batch forces the
# non-interactive run; stderr merged for the live log. The api builds and
# validates the whole argv and never includes OS/file/shell flags.
set --
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  set -- "$@" "$l"
done
exec python /opt/sqlmap/sqlmap.py --batch --disable-coloring "$@" 2>&1 </dev/null
