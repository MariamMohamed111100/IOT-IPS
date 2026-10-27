from conftest import make_event


def _seed(feed, n=6):
    for i in range(n):
        feed("security/alerts/vision", make_event(
            f"evt-{i:08d}", ts=f"2026-10-08T10:30:{i:02d}+00:00",
            type="face.unknown" if i % 2 else "person.detected",
            zone="garage" if i < 4 else "kitchen"))


def test_events_are_newest_first_and_paginated(client, auth, feed):
    _seed(feed)
    ids = [e["id"] for e in client.get("/events", headers=auth).json()]
    assert ids == [f"evt-{i:08d}" for i in range(5, -1, -1)]
    page = client.get("/events?limit=2&offset=2", headers=auth).json()
    assert [e["id"] for e in page] == ["evt-00000003", "evt-00000002"]


def test_events_filters(client, auth, feed):
    _seed(feed)
    get = lambda q: [e["id"] for e in client.get("/events?" + q, headers=auth).json()]  # noqa: E731
    assert len(get("zone=kitchen")) == 2
    assert len(get("type=face.unknown")) == 3
    assert get("zone=garage&type=face.unknown") == ["evt-00000003", "evt-00000001"]
    assert get("since=2026-10-08T10:30:04Z") == ["evt-00000005", "evt-00000004"]
    assert get("until=2026-10-08T10:30:01Z") == ["evt-00000001", "evt-00000000"]
    assert get("ids=evt-00000000,evt-00000005,nope") == ["evt-00000005", "evt-00000000"]
    assert get("source=cyber") == []


def test_listing_limits_are_enforced(client, auth):
    for query in ("limit=0", "limit=501", "offset=-1", "zone=A/B", "type=notatype"):
        assert client.get("/events?" + query, headers=auth).status_code == 422


def test_single_event(client, auth, feed):
    _seed(feed, 1)
    assert client.get("/events/evt-00000000", headers=auth).json()["data"]["confidence"] == 0.93
    assert client.get("/events/ghost", headers=auth).status_code == 404


def test_zones_are_seeded_from_the_shared_config(client, auth):
    zones = {z["name"]: z["is_outdoor"] for z in client.get("/zones", headers=auth).json()}
    assert len(zones) == 7 and zones["backyard"] is True and zones["garage"] is False
    assert client.post("/zones", json={"name": "garage"}, headers=auth).status_code == 409
    assert client.post("/zones", json={"name": "Bad Zone"}, headers=auth).status_code == 422


def test_seeding_twice_adds_nothing(client):
    from zones_seed import seed_zones
    assert seed_zones() == 0


def test_events_and_incidents_cannot_be_forged_over_rest(client, auth):
    """Forensic history only enters through validated MQTT messages."""
    event = make_event("forged-0001")
    assert client.post("/events", json=event, headers=auth).status_code == 405
    assert client.post("/incidents", json={"id": "forged-0001"}, headers=auth).status_code == 405
    assert client.delete("/events/forged-0001", headers=auth).status_code == 405
