from conftest import REPO  # noqa: F401


def demo(rig):
    rig.send("pir_garage", "motion.night", "garage")
    rig.send("vision", "face.unknown", "garage")
    rig.send("cyber", "cyber.port_scan", "network", src_ip="192.168.1.15")


def test_demo_scores_85_high_with_responses(rig):
    demo(rig)
    risk = rig.risk("garage")
    assert risk["score"] == 85 and risk["level"] == "high"
    inc = rig.last("security/incidents")
    assert inc["score"] == 85 and inc["level"] == "high" and inc["zone"] == "garage"
    assert len(inc["events"]) == 3
    assert {"lights_on", "siren", "block_ip"} <= set(inc["actions"])
    cmds = {t: p["action"] for t, p in rig.topic("home/")}
    assert cmds == {"home/garage/bulb/bulb_garage/cmd": "on",
                    "home/living_room/siren/siren_main/cmd": "on"}
    (_, block), = rig.topic("system/block")
    assert block["ip"] == "192.168.1.15" and block["window_seconds"] == 3600


def test_risk_is_retained_and_incident_id_is_stable(rig):
    demo(rig)
    assert all(r for t, _, r in rig.out if t == "security/risk")
    assert len({p["id"] for _, p in rig.topic("security/incidents")}) == 1


def test_no_duplicate_commands_on_more_events(rig):
    demo(rig)
    rig.send("vision", "face.unknown", "garage")
    assert len(rig.topic("home/")) == 2 and len(rig.topic("system/block")) == 1


def test_duplicate_event_id_ignored(rig):
    ev = rig.send("vision", "face.unknown", "garage")
    rig.engine.on_message("security/alerts/vision", ev.model_dump_json())
    assert rig.risk("garage")["score"] == 40


def test_decay_closes_incident_and_silences_siren(rig):
    demo(rig)
    rig.advance(11 * 60)
    risk = rig.risk("garage")
    assert risk["score"] == 0 and risk["level"] == "low"
    inc = rig.last("security/incidents")
    assert "closed" in inc["summary"].lower()
    assert ("home/living_room/siren/siren_main/cmd", "off") in [
        (t, p["action"]) for t, p in rig.topic("home/")]


def test_startup_reset_clears_stale_zone_risk(rig):
    demo(rig)
    assert rig.risk("garage")["score"] == 85
    rig.engine.reset_zones(["garage", "network"])      # what the service does on every start
    assert rig.risk("garage")["score"] == 0
    assert rig.risk("network")["score"] == 0


def test_repeat_cap(rig):
    for _ in range(6):
        rig.send("vision", "face.unknown", "garage")
    assert rig.risk("garage")["score"] == 100      # 3 x 40 would be 120: capped


def test_correlation_bonus_once(rig):
    rig.send("vision", "face.unknown", "entrance")
    rig.send("lock_front", "lock.login_failed", "entrance")
    risk = rig.risk("entrance")
    assert risk["score"] == 95
    assert any(f["type"].startswith("correlation.") for f in risk["factors"])


def test_intrusion_critical_never_unlocks(rig):
    for t, z in [("face.unknown", "entrance"), ("lock.login_failed", "entrance"),
                 ("door.open", "entrance")]:
        rig.send("x", t, z)
    assert rig.risk("entrance")["level"] == "critical"
    assert not [p for t, p in rig.topic("home/") if p["action"] in ("unlock", "lock")]


def test_fire_critical_unlocks_doors(rig):
    rig.send("smoke_kitchen", "fire.detected", "kitchen")
    cmds = [(t, p["action"]) for t, p in rig.topic("home/")]
    assert ("home/entrance/lock/lock_front/cmd", "unlock") in cmds


def test_water_leak_closes_valve(rig):
    rig.send("leak", "water.leak", "kitchen")
    assert ("home/kitchen/valve/valve_main/cmd", "close") in [
        (t, p["action"]) for t, p in rig.topic("home/")]


def test_bad_input_is_dropped(rig):
    e = rig.engine
    e.on_message("security/alerts/vision", b"not json")
    e.on_message("security/alerts/vision", b"[1]")
    e.on_message("security/alerts/vision", b"{}")
    e.on_message("security/alerts/vision", b"x" * 70000)
    e.on_message("home/garage/pir/p/event",
                 b'{"id":"1","ts":"t","source":"s","type":"motion.night","zone":"kitchen",'
                 b'"severity_hint":"info","data":{}}')           # zone != topic
    e.on_message("security/alerts/engine", b"{}")                 # own topic ignored
    assert not rig.out


def test_unknown_event_type_scores_nothing(rig):
    rig.send("x", "weird.thing", "garage")
    assert not rig.topic("security/incidents")
    assert all(p["score"] == 0 for _, p in rig.topic("security/risk"))


def test_loopback_ip_is_not_blocked(rig):
    rig.send("pir", "motion.night", "garage")
    rig.send("vision", "face.unknown", "garage")
    rig.send("cyber", "cyber.port_scan", "network", src_ip="127.0.0.1")
    assert not rig.topic("system/block")


def test_block_ip_recorded_on_every_live_incident(rig):
    rig.send("vision", "face.unknown", "entrance")
    rig.send("vision", "face.unknown", "garage")
    rig.send("cyber", "cyber.port_scan", "network", src_ip="192.168.1.15")
    by_zone = {}
    for _, p in rig.topic("security/incidents"):
        by_zone[p["zone"]] = p
    for zone in ("entrance", "garage"):
        assert by_zone[zone]["score"] >= 61
        assert {"lights_on", "siren", "block_ip"} <= set(by_zone[zone]["actions"])
    (_, block), = rig.topic("system/block")
    assert block["ip"] == "192.168.1.15" and block["window_seconds"] == 3600


def test_payload_shapes_follow_the_contract(rig):
    import re
    demo(rig)
    risk, inc = rig.risk("garage"), rig.last("security/incidents")
    assert set(risk) == {"ts", "zone", "level", "score", "factors", "actions"}
    assert type(risk["score"]) is int and re.fullmatch(r"[a-z0-9_]+", risk["zone"])
    assert all(set(f) == {"type", "weight"} for f in risk["factors"])
    assert set(inc) == {"id", "ts", "zone", "level", "score", "trigger", "events", "actions",
                        "summary"}
    assert 1 <= len(inc["id"]) <= 100 and len(inc["summary"]) <= 4000


def test_zones_are_scored_separately(rig):
    """The bug: a leak in the kitchen must not add to an intruder in the garage."""
    rig.send("leak", "water.leak", "kitchen")
    rig.send("pir", "motion.outdoor", "entrance")
    demo(rig)
    assert rig.risk("garage")["score"] == 85
    # only the house-wide port scan (+25) is shared; no garage face/motion leaks into them
    assert rig.risk("kitchen")["score"] == 35 + 25
    assert rig.risk("entrance")["score"] == 20 + 25 + 25      # + correlation: scan + outdoor motion
    zones = {p["zone"] for _, p in rig.topic("security/incidents")}
    assert zones == {"garage", "kitchen", "entrance"}          # each zone has its own incident


def test_network_event_is_shared_by_zones_with_live_risk(rig):
    rig.send("vision", "face.unknown", "garage")
    rig.send("leak", "water.leak", "kitchen")
    rig.send("cyber", "cyber.port_scan", "network", src_ip="192.168.1.15")
    assert rig.risk("garage")["score"] == 65 and rig.risk("kitchen")["score"] == 60


def test_quiet_zone_is_closed_while_another_stays_open(rig):
    rig.send("leak", "water.leak", "kitchen")
    rig.advance(6 * 60)
    rig.send("vision", "face.unknown", "garage")
    rig.advance(5 * 60)                                          # kitchen is 11 min old now
    assert rig.risk("kitchen")["score"] == 0 and rig.risk("garage")["score"] == 40


def test_block_note_is_not_repeated_on_every_event(rig):
    demo(rig)
    for _ in range(3):
        rig.send("vision", "face.unknown", "garage")
    assert rig.last("security/incidents")["summary"].count("block_ip ->") == 1


def test_cyber_only_attack_opens_a_network_incident_and_blocks(rig):
    """No physical event at all: a brute force from the LAN must still be handled."""
    rig.send("cyber", "cyber.brute_force", "network", src_ip="192.168.1.77", target="lock_front")
    rig.send("cyber", "cyber.rogue_device", "network", mac="aa:bb:cc:dd:ee:ff",
             ip="192.168.1.77")
    (_, block), = rig.topic("system/block")
    assert block["ip"] == "192.168.1.77" and block["reason"] == "cyber.brute_force"
    inc = rig.last("security/incidents")
    assert inc["zone"] == "network" and inc["score"] == 65 and inc["level"] == "high"
    assert "block_ip" in inc["actions"] and "notify" in inc["actions"]
    assert not rig.topic("home/")            # no siren, no lights for a pure network attack


def test_port_scan_alone_is_below_medium_so_the_engine_does_nothing(rig):
    """CONTRACT 12: cyber autoblocks a lone scan itself; the engine's block_ip starts at High."""
    rig.send("cyber", "cyber.port_scan", "network", src_ip="192.168.1.77")
    assert rig.risk("network")["score"] == 25
    assert not rig.topic("system/block")
    assert not rig.topic("security/incidents")          # 25 points is below Medium


def test_network_incident_closes_when_it_decays(rig):
    rig.send("cyber", "cyber.brute_force", "network", src_ip="192.168.1.77")
    rig.send("cyber", "cyber.rogue_device", "network", mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.77")
    rig.advance(11 * 60)
    assert rig.risk("network")["score"] == 0
    assert "closed" in rig.last("security/incidents")["summary"].lower()
