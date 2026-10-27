import json


def test_command_is_published_to_the_contract_topic(client, auth, fake_mqtt, house):
    r = client.post("/devices/siren_main/command",
                    json={"action": "on", "reason": "incident-42"}, headers=auth)
    assert r.status_code == 200
    topic, payload = fake_mqtt.published[-1]
    assert topic == "home/living_room/siren/siren_main/cmd"
    assert payload["action"] == "on" and payload["reason"] == "incident-42"
    assert payload["requested_by"] == "admin"
    assert {"id", "ts"} <= payload.keys() and payload["ts"].endswith("+00:00")


def test_simulator_obeys_the_api_command(client, auth, fake_mqtt, house):
    client.post("/devices/valve_main/command", json={"action": "close"}, headers=auth)
    topic, payload = fake_mqtt.published[-1]
    start = len(house.bus.published)
    house.bus.publish(topic, json.dumps(payload))               # broker delivers it to the device
    house.deliver(start)                                        # ...and its answer reaches the API
    status = json.loads(house.bus.retained["home/kitchen/valve/valve_main/status"])
    assert status["state"] == {"open": False}
    assert client.get("/devices?zone=kitchen", headers=auth).json()[0]["state"] is not None
    events = client.get("/events?type=valve.closed", headers=auth).json()
    assert [e["data"] for e in events] == [{"valve_id": "valve_main"}]


def test_command_validation(client, auth, house):
    post = lambda dev, body, **kw: client.post(f"/devices/{dev}/command", json=body, **kw)  # noqa: E731
    assert post("siren_main", {"action": "lock"}, headers=auth).status_code == 400
    assert post("temp_kitchen", {"action": "on"}, headers=auth).status_code == 400
    assert post("ghost", {"action": "on"}, headers=auth).status_code == 404
    assert post("siren_main", {"action": "explode"}, headers=auth).status_code == 422
    too_long = {"action": "on", "reason": "x" * 500}
    assert post("siren_main", too_long, headers=auth).status_code == 422
    assert post("siren_main", {"action": "on"}).status_code == 401


def test_command_fails_clearly_when_mqtt_is_down(client, auth, fake_mqtt, house):
    fake_mqtt.connected = False
    r = client.post("/devices/siren_main/command", json={"action": "on"}, headers=auth)
    assert r.status_code == 503


def test_commands_are_audited_with_the_user(client, auth, fake_mqtt, house):
    client.post("/devices/lock_front/command", json={"action": "unlock", "reason": "guest"},
                headers=auth)
    (entry,) = [a for a in client.get("/audit", headers=auth).json()
                if a["action"] == "device.command"]
    assert (entry["actor"], entry["target"]) == ("admin", "lock_front")
    assert entry["details"]["action"] == "unlock" and entry["details"]["reason"] == "guest"
    assert entry["details"]["command_id"] == fake_mqtt.published[-1][1]["id"]


def test_logins_are_audited_and_details_are_encrypted(client, auth, sql):
    client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    actions = [a["action"] for a in client.get("/audit", headers=auth).json()]
    assert "login.ok" in actions and "login.failed" in actions
    blobs = [row[0] for row in sql("SELECT details_encrypted FROM audit_log")]
    assert blobs and all(b"admin" not in b for b in blobs)


def test_a_failing_audit_write_never_breaks_a_command(client, auth, fake_mqtt, house, monkeypatch):
    import audit

    def boom():
        raise RuntimeError("db down")
    monkeypatch.setattr(audit, "SessionLocal", boom)
    r = client.post("/devices/siren_main/command", json={"action": "off"}, headers=auth)
    assert r.status_code == 200


def test_device_registration_rejects_topic_injection(client, auth):
    base = {"device_id": "d1", "name": "d", "device_type": "bulb", "zone": "kitchen"}
    assert client.post("/devices", json=base, headers=auth).status_code == 201
    assert client.post("/devices", json=base, headers=auth).status_code == 409
    for field in ("device_id", "device_type", "zone"):
        bad = {**base, field: "a/b#+", "device_id": "d2" if field != "device_id" else "a/b"}
        assert client.post("/devices", json=bad, headers=auth).status_code == 422
