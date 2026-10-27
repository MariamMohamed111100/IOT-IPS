#!/usr/bin/env bash
# Send a block/unblock command to the cyber service as the broker admin (same payload the engine
# sends on system/block). Handy to demo the IPS or to lift a block so a demo can be re-run.
#   ./scripts/block-admin.sh block   203.0.113.9 [seconds]
#   ./scripts/block-admin.sh unblock 203.0.113.9
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' ;; esac
action="${1:-}"; ip="${2:-}"; seconds="${3:-3600}"
[[ "$action" == "block" || "$action" == "unblock" ]] || { echo "usage: $0 block|unblock <ip> [seconds]"; exit 1; }
[[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]] || { echo "not an IP address: $ip"; exit 1; }
[[ "$seconds" =~ ^[0-9]+$ ]] || { echo "seconds must be a number"; exit 1; }
set -a; . ./.env; set +a
id="admin-$(date +%s)-$RANDOM"
payload="{\"id\":\"$id\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"ip\":\"$ip\",\"action\":\"$action\",\"reason\":\"manual\",\"window_seconds\":$seconds}"
docker compose exec -T mosquitto mosquitto_pub -h localhost -p 8883 \
  --cafile /mosquitto/config/certs/ca.crt \
  --cert /mosquitto/config/certs/admin.crt --key /mosquitto/config/certs/admin.key \
  -u admin -P "$MQTT_PASSWORD_ADMIN" -t system/block -q 1 -m "$payload"
echo ">> sent $action for $ip; watch the confirmation with: ./scripts/watch.sh 'security/alerts/cyber'"
