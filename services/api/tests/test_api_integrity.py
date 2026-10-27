"""CONTRACT 8: tampered records fail closed: flagged, logged, content withheld."""
import logging

from conftest import make_event

INCIDENT = {"id": "incident-42", "ts": "2026-10-08T10:30:28+00:00", "zone": "garage",
            "level": "high", "score": 85, "trigger": "cyber.port_scan",
            "events": ["evt-00000001"], "actions": ["siren"], "summary": "Port scan"}


def test_tampered_event_is_flagged_not_silently_empty(client, auth, feed, sql, caplog):
    feed("security/alerts/vision", make_event("evt-00000001"))
    feed("security/alerts/vision", make_event("evt-00000002"))
    sql("UPDATE events SET data_encrypted = :b WHERE id = 'evt-00000001'", b=b"\x00" * 40)
    with caplog.at_level(logging.ERROR, logger="api.storage"):
        events = {e["id"]: e for e in client.get("/events", headers=auth).json()}
    assert events["evt-00000001"]["integrity_ok"] is False
    assert events["evt-00000001"]["data"] == {}
    assert events["evt-00000002"]["integrity_ok"] is True           # one bad row breaks nothing
    assert events["evt-00000002"]["data"]["confidence"] == 0.93
    assert "INTEGRITY CHECK FAILED" in caplog.text and "evt-00000001" in caplog.text


def test_ciphertext_copied_to_another_row_is_rejected(client, auth, feed, sql):
    feed("security/alerts/vision", make_event("evt-00000001", data={"a": 1}))
    feed("security/alerts/vision", make_event("evt-00000002", data={"b": 2}))
    sql("UPDATE events SET data_encrypted = (SELECT data_encrypted FROM events "
        "WHERE id = 'evt-00000001') WHERE id = 'evt-00000002'")
    swapped = client.get("/events/evt-00000002", headers=auth).json()
    assert swapped["integrity_ok"] is False and swapped["data"] == {}


def test_tampered_incident_and_audit_are_flagged(client, auth, feed, sql):
    feed("security/incidents", INCIDENT)
    sql("UPDATE incidents SET summary_encrypted = :b", b=b"\x01" * 50)
    incident = client.get("/incidents/incident-42", headers=auth).json()
    assert incident["integrity_ok"] is False and incident["summary"] == ""
    assert incident["score"] == 85                                  # plain columns still readable
    sql("UPDATE audit_log SET details_encrypted = :b", b=b"\x02" * 50)
    assert all(a["integrity_ok"] is False for a in client.get("/audit", headers=auth).json())


def test_wrong_storage_key_is_detected(client, auth, feed, monkeypatch):
    feed("security/alerts/vision", make_event("evt-00000001"))
    monkeypatch.setenv("STORAGE_KEY", "a-different-key-" * 4)
    assert client.get("/events", headers=auth).json()[0]["integrity_ok"] is False
