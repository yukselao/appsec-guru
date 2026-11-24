#!/bin/sh
# Reads "<target> [ports]" from stdin (both validated by the api). No eval.
# Live mode: not greppable, so RustScan streams a line per open port as it is
# found (the api parses "Open <ip>:<port>" and also shows the lines live).
# --accessible drops the ASCII-art banner and colour so the log stays readable.
read t p
case "$t" in *[!A-Za-z0-9.-]*|"") exit 1 ;; esac
case "$p" in *[!0-9,-]*) p="" ;; esac
set -- -a "$t" --no-config --accessible -b 1000 -t 2500
if [ -n "$p" ]; then
  # a range (1-65535) needs -r; a comma list (22,80,443) needs -p
  case "$p" in
    *-*) set -- "$@" -r "$p" ;;
    *)   set -- "$@" -p "$p" ;;
  esac
fi
exec rustscan "$@" </dev/null
