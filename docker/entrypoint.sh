#!/bin/sh
# Docker Compose on Linux mounts /run/secrets/* as root:root with mode 0400
# (service `uid`/`gid`/`mode` are unsupported and ignored), so the non-root
# app user cannot read them. Copy each secret to a path owned by app with the
# same 0400 the mount used, then drop privileges and run the service. Only the
# service user reads them, so they never need to be group/other readable.
set -e

KEYS=/run/app-secrets
mkdir -p "$KEYS"
for f in /run/secrets/*; do
    [ -e "$f" ] || continue
    target="$KEYS/$(basename "$f")"
    cp "$f" "$target"
    chown app:app "$target"
    chmod 0400 "$target"
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