#!/bin/sh
# Request: an optional "__OPTS__ batch=.. timeout=.." line, then "<target> [ports]"
# (both validated by the api). No eval. Live mode: not greppable, so RustScan
# streams a line per open port as it is found; --accessible drops the banner/colour.
b=1000 t=2500
read first
case "$first" in
  "__OPTS__ "*)
    for kv in ${first#__OPTS__ }; do
      v=${kv#*=}
      case "$v" in ""|*[!0-9]*) continue ;; esac
      case "${kv%%=*}" in batch) b=$v ;; timeout) t=$v ;; esac
    done
    read line ;;
  *) line=$first ;;
esac
# shellcheck disable=SC2086
set -- $line
tt=$1 p=$2
case "$tt" in *[!A-Za-z0-9.,/-]*|"") exit 1 ;; esac
case "$p" in *[!0-9,-]*) p="" ;; esac
set -- -a "$tt" --no-config --accessible -b "$b" -t "$t"
if [ -n "$p" ]; then
  # a range (1-65535) needs -r; a comma list (22,80,443) needs -p
  case "$p" in
    *-*) set -- "$@" -r "$p" ;;
    *)   set -- "$@" -p "$p" ;;
  esac
fi
exec rustscan "$@" </dev/null
