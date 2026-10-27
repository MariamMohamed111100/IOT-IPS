"""
risk_scenarios.py - hand-written reference scenarios for the risk engine.

Used by compare_weights.py (to compare weight sets) and test_risk.py (to test
that each scenario lands in the level we expect).

The expected level of each scenario is a HUMAN judgement written from the story
("a weak-confidence scan of a smart bulb from a trusted PC is not worth waking
anyone up"), not something copied from the engine's output. Documentation IP
ranges are used for outside addresses (203.0.113.0/24 is reserved for examples).
"""

DEVICES = {
    "CAM-001": {
        "device_id": "CAM-001", "device_type": "surveillance_camera", "ip": "192.168.1.50",
        "criticality": "high", "expected_protocols": ["RTSP", "HTTPS", "DNS"], "expected_ports": [554, 443],
    },
    "BULB-001": {
        "device_id": "BULB-001", "device_type": "smart_bulb", "ip": "192.168.1.60",
        "criticality": "low", "expected_protocols": ["HTTP", "DNS"], "expected_ports": [80],
    },
    "TEMP-001": {
        "device_id": "TEMP-001", "device_type": "temperature_sensor", "ip": "192.168.1.70",
        "criticality": "medium", "expected_protocols": ["MQTT", "HTTP"], "expected_ports": [80, 1883],
    },
    "IND-001": {
        "device_id": "IND-001", "device_type": "industrial_sensor", "ip": "192.168.1.80",
        "criticality": "critical", "expected_protocols": ["MODBUS"], "expected_ports": [502],
    },
}


def _s(sid, level, story, device, attack, confidence, src_ip, dst_port, failed=0, conns=0, label="ATTACK"):
    return {
        "id": sid,
        "expected_level": level,
        "story": story,
        "device": device,
        "detection": {"label": label, "attack_type": attack, "confidence": confidence, "mitre_technique": "T0000"},
        "event": {
            "device_id": device, "src_ip": src_ip, "dst_port": dst_port, "protocol": "TCP",
            "failed_attempts": failed, "connection_attempts": conns,
        },
    }


SCENARIOS = [
    # ---- Low -------------------------------------------------------------
    _s("L1", "Low", "weak scan of a smart bulb from a trusted PC", "BULB-001", "port_scan", 0.50, "192.168.1.20", 80, conns=3),
    _s("L2", "Low", "very weak recon of a smart bulb from a trusted PC", "BULB-001", "reconnaissance", 0.40, "192.168.1.30", 80, conns=1),
    # ---- Medium ----------------------------------------------------------
    _s("M1", "Medium", "scan of the camera from an unknown LAN device, odd port", "CAM-001", "port_scan", 0.75, "192.168.1.77", 22, conns=25),
    _s("M2", "Medium", "light brute force on a bulb from an unknown LAN device", "BULB-001", "brute_force", 0.65, "192.168.1.77", 22, failed=12),
    # ---- High ------------------------------------------------------------
    _s("H1", "High", "brute force on the camera from the internet", "CAM-001", "brute_force", 0.85, "203.0.113.5", 22, failed=40),
    _s("H2", "High", "DoS on a temperature sensor from the internet", "TEMP-001", "dos", 0.85, "203.0.113.9", 80, conns=150),
    # ---- Critical --------------------------------------------------------
    _s("C1", "Critical", "431 failed logins on the camera, 94% confidence (PDF example)", "CAM-001", "brute_force", 0.94, "192.168.1.77", 22, failed=431),
    _s("C2", "Critical", "Mirai on an industrial sensor from the internet", "IND-001", "mirai", 0.97, "203.0.113.50", 23, conns=500),
    _s("C3", "Critical", "device takeover attempt on the camera from the internet", "CAM-001", "device_takeover", 0.90, "203.0.113.7", 22, failed=60),
    # ---- Benign ----------------------------------------------------------
    _s("B1", "Low", "benign verdict on the camera", "CAM-001", "benign", 0.99, "192.168.1.20", 554, conns=2, label="BENIGN"),
]
