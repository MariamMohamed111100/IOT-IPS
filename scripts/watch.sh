#!/usr/bin/env bash
# Live view of MQTT traffic through the TLS broker.   ./scripts/watch.sh ['home/#']
set -uo pipefail
cd "$(dirname "$0")/.."
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' ;; esac
set -a; . ./.env; set +a
exec docker compose exec -T mosquitto mosquitto_sub -h localhost -p 8883 \
  --cafile /mosquitto/config/certs/ca.crt \
  --cert /mosquitto/config/certs/admin.crt --key /mosquitto/config/certs/admin.key \
  -u admin -P "$MQTT_PASSWORD_ADMIN" -t "${1:-home/+/+/+/event}" -v
