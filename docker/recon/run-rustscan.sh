#!/bin/sh
read t p
case "$t" in *[!A-Za-z0-9.-]*|"") exit 1 ;; esac
case "$p" in *[!0-9,-]*) p="" ;; esac
if [ -n "$p" ]; then rustscan -a "$t" -p "$p" -g --no-config -b 4500 -t 2500 </dev/null
else rustscan -a "$t" -g --no-config -b 4500 -t 2500 </dev/null; fi
