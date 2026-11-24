#!/bin/sh
# Request: an optional "__OPTS__ key=value ..." line, the hosts, then "__END__".
# Only known keys with plain numbers are used; anything else keeps the default.
timeout=10 threads=50 rate_limit=150 retries=0 max=3700
f=$(mktemp)
while IFS= read -r l; do
  [ "$l" = "__END__" ] && break
  case "$l" in
    "__OPTS__ "*)
      for kv in ${l#__OPTS__ }; do
        v=${kv#*=}
        case "$v" in ""|*[!0-9]*) continue ;; esac
        case "${kv%%=*}" in
          timeout) timeout=$v ;;
          threads) threads=$v ;;
          rate_limit) rate_limit=$v ;;
          retries) retries=$v ;;
          max) max=$v ;;
        esac
      done ;;
    *) printf '%s\n' "$l" >> "$f" ;;
  esac
done
timeout "$max" httpx -l "$f" -silent -json -title -status-code -tech-detect -no-color \
  -timeout "$timeout" -threads "$threads" -rate-limit "$rate_limit" -retries "$retries" </dev/null
rm -f "$f"
