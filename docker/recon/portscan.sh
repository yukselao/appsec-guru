#!/bin/sh
# Reads "<target> [ports]" from stdin (both validated by the api). No eval.
read t p
case "$t" in *[!A-Za-z0-9.-]*|"") exit 1 ;; esac
case "$p" in *[!0-9,-]*) p="" ;; esac
if [ -n "$p" ]; then exec rustscan -a "$t" -p "$p" -g --no-config -b 4500 -t 2500
else exec rustscan -a "$t" -g --no-config -b 4500 -t 2500; fi
