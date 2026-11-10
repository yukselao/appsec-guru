#!/bin/sh
f=$(mktemp); while IFS= read -r l; do [ "$l" = "__END__" ] && break; printf '%s\n' "$l" >> "$f"; done
subfinder -dL "$f" -silent </dev/null; rm -f "$f"
