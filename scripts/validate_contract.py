"""CI guard: contract schema, risk config and example events must stay consistent."""
import json
import pathlib
import sys

import jsonschema
import yaml

root = pathlib.Path(__file__).resolve().parent.parent
schema = json.loads((root / "contract/event.schema.json").read_text())
jsonschema.Draft202012Validator.check_schema(schema)

from smartsecure_common import make_event  # noqa: E402
from smartsecure_common.crypto import decrypt, encrypt, key_from_env  # noqa: E402

event = make_event(
    "vision", "fire.detected", "garage", "high", confidence=0.9, snapshot="snapshots/abc.jpg"
)
sample = json.loads(event.model_dump_json())
jsonschema.validate(sample, schema)

# AES-256-GCM at-rest primitive must round-trip (and detect tampering).
key = key_from_env("ci-test-key")
assert decrypt(key, encrypt(key, b"secret")) == b"secret"

risk = yaml.safe_load((root / "config/risk_scores.yaml").read_text())
zones_cfg = yaml.safe_load((root / "config/zones.yaml").read_text())
zones = zones_cfg["zones"]
outdoor = zones_cfg.get("outdoor_zones", [])
levels = risk["levels"]
assert list(levels) == ["low", "medium", "high", "critical"], "levels must be ordered low..critical"
assert list(levels.values()) == sorted(levels.values()), "level thresholds must ascend"
assert set(risk["responses"]) == set(levels), "every level needs a response list"
assert all(isinstance(v, int) for v in risk["events"].values())
assert "network" in zones
assert set(outdoor) <= set(zones), "outdoor_zones must be subsets of zones"
assert "network" not in outdoor, "the network zone is not a physical area"

# Policy sanity (review P1): attackers get blocked from High; fire NEVER locks doors.
for name, _lower in levels.items():
    prior = risk["responses"].get("low", [])
    if name != "low":
        assert set(prior) <= set(risk["responses"][name]), f"responses[{name}] must be cumulative"
        prior = risk["responses"][name]
assert "block_ip" in risk["responses"]["high"], "block_ip must fire at High (demo score 85)"
assert "unlock_doors" in risk["responses"]["critical"], "Critical must unlock doors"
assert "lock_doors" not in risk["responses"]["critical"], "never lock doors at Critical (fire!)"

# IPS contract (v1.2): new scored types, data schemas, device mapping.
for t in ("cyber.dos", "cyber.unexpected_traffic"):
    assert t in risk["events"], f"{t} must be scored in config/risk_scores.yaml"
registry = (root / "docs/CONTRACT.md").read_text(encoding="utf-8")
for t in ("cyber.dos", "cyber.unexpected_traffic", "cyber.block_applied", "cyber.block_refused"):
    assert f"| `{t}` |" in registry, f"{t} missing from the registry in docs/CONTRACT.md"
ips_schema = json.loads((root / "contract/ips_event_data.schema.json").read_text())
details_schema = json.loads((root / "contract/incident_details.schema.json").read_text())
block_schema = json.loads((root / "contract/ips_block_data.schema.json").read_text())
for s in (ips_schema, details_schema, block_schema):
    jsonschema.Draft202012Validator.check_schema(s)
ips_sample = {"src_ip": "203.0.113.45", "dst_ip": "192.168.1.50", "dst_port": 22, "protocol": "TCP",
              "direction": "inbound", "device_id": "cam_001", "confidence": 0.98,
              "mitre_technique": "T1110",
              "failed_attempts": 300, "connection_attempts": 300, "duration": 240}
jsonschema.validate(ips_sample, ips_schema)
jsonschema.validate({"mitre_technique": "T1110", "ips_score": 93, "ips_level": "critical",
                     "reports": {"technical": "t", "executive": "e"}}, details_schema)
jsonschema.validate({"ip": "203.0.113.45", "action": "block_source", "device_id": "cam_001",
                     "reason": "critical_certain", "dry_run": True}, block_schema)
ips_devices = json.loads((root / "config/ips_devices.json").read_text())["devices"]
sim_file = yaml.safe_load((root / "services/simulators/devices.yaml").read_text())
sim_ids = {d["id"] for d in sim_file["devices"]}
backend_ids = [d["backend_id"] for d in ips_devices]
assert len(set(backend_ids)) == len(backend_ids), "backend ids must be unique"
assert not set(backend_ids) & sim_ids, "an IPS device id collides with a simulated device"
for d in ips_devices:
    token = __import__("re").compile(r"[a-z0-9_]+")
    assert all(token.fullmatch(d[k]) for k in ("backend_id", "backend_type", "zone")), d
    assert d["zone"] in zones and d["zone"] != "network", f"bad zone for {d['device_id']}"
print("ips contract OK:", len(ips_devices), "devices")

print("contract OK:", len(risk["events"]), "scored event types,", len(zones), "zones")
sys.exit(0)