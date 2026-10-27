#!/bin/sh
# Docker Compose on Linux mounts /run/secrets/* as root:root with mode 0400
# (service `uid`/`gid`/`mode` are unsupported and ignored), so the non-root
# app user cannot read them. Copy each secret to a world-readable path owned
# by app, then drop privileges and run the service.
set -e

KEYS=/run/app-secrets
mkdir -p "$KEYS"
for f in /run/secrets/*; do
    [ -e "$f" ] || continue
    cp "$f" "$KEYS/$(basename "$f")"
    chmod 0444 "$KEYS/$(basename "$f")"
done
chown -R app:app "$KEYS"

# Shared data volume (vision writes snapshots/, api and frontend read): a fresh named volume is
# root-owned, so hand the top level to app. Not recursive: existing files keep their owners.
if [ -d /data ]; then
    mkdir -p /data/snapshots
    chown app:app /data /data/snapshots
    chmod 0755 /data /data/snapshots
fi

# Opt-in only (cyber with CYBER_FIREWALL=iptables must edit netfilter rules, which needs root).
if [ "${RUN_AS_ROOT:-0}" = "1" ]; then
    exec "$@"
fi
exec gosu app "$@"