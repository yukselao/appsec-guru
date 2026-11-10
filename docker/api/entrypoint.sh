#!/bin/sh
# Copies the host's ssh keys/config (mounted read-only at /ssh-host) into
# ~/.ssh with the permissions ssh insists on. macOS-only options in the host
# config (UseKeychain ...) are ignored instead of failing every connection.
set -e
if [ -d /ssh-host ]; then
    for f in /ssh-host/*; do
        [ -f "$f" ] || continue
        case "$(basename "$f")" in
            known_hosts*|authorized_keys|*.sock) continue ;;
        esac
        cp "$f" "$HOME/.ssh/" 2>/dev/null || true
    done
    if [ -f "$HOME/.ssh/config" ]; then
        { echo "IgnoreUnknown UseKeychain,AddKeysToAgent"; cat "$HOME/.ssh/config"; } > "$HOME/.ssh/config.tmp"
        mv "$HOME/.ssh/config.tmp" "$HOME/.ssh/config"
    fi
    if [ -f /ssh-host/known_hosts ] && [ ! -f "$HOME/.ssh/known_hosts" ]; then
        cp /ssh-host/known_hosts "$HOME/.ssh/known_hosts" 2>/dev/null || true
    fi
    chmod 700 "$HOME/.ssh"
    chmod 600 "$HOME/.ssh"/* 2>/dev/null || true
fi
exec "$@"
