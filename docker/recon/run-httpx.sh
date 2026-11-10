#!/bin/sh
f=$(mktemp); while IFS= read -r l; do [ "$l" = "__END__" ] && break; printf '%s\n' "$l" >> "$f"; done
httpx -l "$f" -silent -json -title -status-code -tech-detect -no-color </dev/null; rm -f "$f"
