#!/bin/sh
f=$(mktemp); while IFS= read -r l; do [ "$l" = "__END__" ] && break; printf '%s\n' "$l" >> "$f"; done
dnsx -l "$f" -silent -a -aaaa -cname -mx -ns -txt -resp -json </dev/null; rm -f "$f"
