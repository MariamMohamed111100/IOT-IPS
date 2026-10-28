# cyber (Person 5): detection and IPS

Suricata sees the traffic, this service decides what it means, tells the risk engine (P6) in the
shared contract format, and enforces `system/block` commands.

```text
attacker ──► smartlock (victim)
   │  (shared network namespace)
suricata ──► eve.json ──► cyber ──► security/alerts/cyber ──► engine ──► system/block ──┐
                            ▲                                                           │
                            └───────────────────────────────────────────────────────────┘
```

## What it detects (one event per attack, never one per packet)

| Event | Trigger (defaults) | Auto-block |
|---|---|---|
| `cyber.port_scan` | 15+ distinct host:port pairs from one source in 10 s | yes, 10 min |
| `cyber.brute_force` | 5+ HTTP `POST /login` (or SSH connects) from one source in 60 s | yes, 10 min |
| `cyber.rogue_device` | unknown MAC asks for DHCP (or shows in ARP with `ROGUE_ARP=true`) | no (only the engine decides) |

Cyber also publishes `cyber.ip_blocked` / `cyber.ip_unblocked` and, for every block decision,
`cyber.block_applied` or `cyber.block_refused` (contract 3.1, never scored; `CYBER_BLOCK_RESULTS=false` turns them off). Payloads and the
`data.src_ip` rule are in `docs/CONTRACT.md` section 11.

## Run the demo

```bash
make setup && make demo-up         # everything + attacker, smartlock, suricata, ntfy
make demo-rogue                    # DHCP from an unknown MAC       -> cyber.rogue_device
make demo-brute                    # hydra vs the smart lock        -> cyber.brute_force + block
make demo-scan                     # nmap -sS -p 1-200              -> cyber.port_scan + block
./scripts/watch.sh 'security/alerts/cyber'      # in another terminal
make demo-unblock IP=<attacker ip>              # to run it again
```

The attacker's IP is its container address: look at the `BLOCKED <ip>` line in
`docker compose logs cyber`. After a block, the smart lock refuses that address
(the "block-list API" simulation). `make demo-attack` runs rogue, brute, scan in order.

Suricata shares the attacker's network namespace (`network_mode: service:attacker`). If you
recreate the attacker, recreate Suricata with it in the same command
(`docker compose --profile demo up -d --force-recreate attacker suricata`); otherwise
Suricata stays attached to the old namespace and silently stops seeing traffic.

Rogue-device detection is OFF until `known_devices.yaml` lists your devices (an empty allowlist
would flag everything). The demo's DHCP probe only fires if the attacker MAC is not listed.

## Firewall backends (`CYBER_FIREWALL`)

| Value | What it does |
|---|---|
| `blocklist` (default) | only the shared state file; the demo victim refuses blocked sources |
| `shadow` | logs "would block" and reports `dry_run: true`; enforces nothing. Run it first on a real network |
| `nftables` | table `inet smartsecure_ips`, one set element per block **with a kernel timeout** (it expires even if this service dies); base chains on input, forward and output |
| `iptables` | chain `SMARTSECURE_BLOCK` hooked into INPUT and FORWARD |

Both real backends rebuild their own table or chain at start (startup flush) and the BlockManager re-applies the
unexpired blocks from `BLOCKLIST_FILE`. A block can be undone early with `{"action": "unblock", "ip": ...}`.
**Isolating a device** is a `system/block` command with `"direction": "both"` (drops traffic from and to the
address; only a private address is accepted).

## Real IPS on the Pi / gateway

Set `CYBER_FIREWALL=nftables` (or `iptables`) and `RUN_AS_ROOT=1` for the cyber service, add `cap_add: [NET_ADMIN]`
and `network_mode: host` (rules must live in the namespace that carries the traffic). Cyber manages
only its own table or chain. Put the gateway, DNS and your
admin laptop in `CYBER_NEVER_BLOCK` first. Never enable this on a machine you are not prepared to
lock yourself out of. Test in a network namespace (`unshare -n`) or the lab container, never on your own
firewall: `tests/test_nftables_shadow.py` does exactly that (root + `nft` needed, otherwise it is skipped).

## Safety rules (enforced and tested)

* Every IP is parsed strictly; CIDRs, hostnames, scopes and option-like strings are refused.
* Never blocked: loopback, multicast, link-local, reserved, `CYBER_NEVER_BLOCK`.
* Block window clamped (30 s to 24 h), at most `MAX_BLOCKS`, duplicate command ids ignored.
* At most `CYBER_MAX_EVENTS_PER_MIN` events leave the service; all detector state is bounded.
* iptables and nft are called with a fixed argument list, no shell; the address is parsed first.

## Settings (env, all optional)

`CYBER_FIREWALL`, `CYBER_AUTOBLOCK`, `CYBER_AUTOBLOCK_S`, `CYBER_NEVER_BLOCK`, `PORTSCAN_MIN_TARGETS`,
`PORTSCAN_WINDOW_S`, `PORTSCAN_COOLDOWN_S`, `BRUTE_MIN_ATTEMPTS`, `BRUTE_WINDOW_S`,
`BRUTE_COOLDOWN_S`, `ROGUE_ARP`, `ROGUE_COOLDOWN_S`, `BLOCK_MIN_S`, `BLOCK_MAX_S`, `MAX_BLOCKS`,
`CYBER_MAX_SOURCES`, `CYBER_MAX_EVENTS_PER_MIN`, `EVE_PATH`, `EVE_FROM_START`, `BLOCKLIST_FILE`.
Invalid values stop the service at startup with a clear message.

## Tests

`pytest services/cyber/tests -q` (no Docker). Includes a closed loop with the real engine, and
`CYBER_TEST_REAL_IPTABLES=1` (root) runs one real iptables round trip.
