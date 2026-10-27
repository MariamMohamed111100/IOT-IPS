#!/usr/bin/env bash
# Run once after pushing the repo. Needs the GitHub CLI: gh auth login
set -euo pipefail
for l in "api:0e8a00" "sim:1d76db" "vision:5319e7" "cyber:b60205" "engine:fbca04" "ui:0075ca" "infra:6a737d" "blocked:d73a4a"; do
  gh label create "${l%%:*}" --color "${l##*:}" --force
done
for m in "M1 Simulated MVP" "M2 Stabilize" "M3 Feature depth" "M4 Raspberry Pi bring-up" "M5 Security hardening" "M6 Pilot and finish"; do
  gh api "repos/{owner}/{repo}/milestones" -f title="$m" >/dev/null || true
done
mk() { gh issue create --title "$1" --label "$2" --milestone "M1 Simulated MVP" --body "$3" >/dev/null; echo "created: $1"; }
mk "[P2] API + DB + MQTT ingestion + WebSocket"   api    "Done when: Swagger docs live, every MQTT event persisted."
mk "[P3] ~15 simulated devices + scenario runner + HAL" sim "Done when: 3+ repeatable YAML scenarios."
mk "[P4] Vision: YOLO + faces + fire/smoke on looped RTSP" vision "Done when: clip yields correct alerts on security/alerts/vision."
mk "[P5] Cyber: Suricata + attack sim + auto-block"  cyber "Done when: scan/brute-force raises alert and triggers block."
mk "[P6] Risk engine + correlation + response + timeline" engine "Done when: proposal garage scenario reproduces end to end (score 85, alarm)."
mk "[P7] Digital twin dashboard + timeline + risk gauge" ui "Done when: dashboard updates live during a scenario run."
mk "[P1] Integration + demo script + Pi-readiness notes" infra "Done when: full scenario runs from docs/DEMO_SCRIPT.md without edits."
