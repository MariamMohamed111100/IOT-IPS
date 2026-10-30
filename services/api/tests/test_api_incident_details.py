"""Incident `details` (MITRE, IPS score, reports): stored encrypted, returned, replaced on update.

The engine puts the strongest IPS alert's details on the incident (CONTRACT 4.4).
The API keeps them like events, actions and the summary, limits their size,
and adds the column to a database created before it existed.
"""
import json

import main
from sqlalchemy import inspect

from database import engine

INCIDENT = {"id": "incident-ips-1", "ts": "2026-10-08T10:30:28+00:00", "zone": "network",
            "level": "critical", "score": 100, "trigger": "cyber.dos",
            "events": ["evt-00000001"], "actions": ["log", "notify"],
            "summary": "Critical risk 100"}
DETAILS = {"mitre_technique": "T1498", "ips_score": 91, "ips_level": "critical",
           "ips_score_raw": 80,
           "reports": {"technical": "# Technical\n| a | b |", "executive": "# Executive"}}


def stored(client, auth):
    (inc,) = client.get("/incidents", headers=auth).json()
    return inc


def test_details_are_stored_and_returned(client, auth, feed):
    feed("security/incidents", {**INCIDENT, "details": DETAILS})
    inc = stored(client, auth)
    assert inc["details"] == DETAILS and inc["integrity_ok"] is True


def test_an_incident_without_details_returns_none(client, auth, feed):
    feed("security/incidents", INCIDENT)
    assert stored(client, auth)["details"] is None


def test_details_are_encrypted_in_the_database(client, auth, feed, sql):
    feed("security/incidents", {**INCIDENT, "details": DETAILS})
    (blob,) = sql("SELECT details_encrypted FROM incidents").fetchone()
    assert blob and b"T1498" not in bytes(blob) and b"Technical" not in bytes(blob)


def test_an_update_replaces_and_can_clear_the_details(client, auth, feed):
    feed("security/incidents", {**INCIDENT, "details": DETAILS})
    feed("security/incidents", {**INCIDENT, "details": {**DETAILS, "ips_score": 95}})
    assert stored(client, auth)["details"]["ips_score"] == 95
    feed("security/incidents", INCIDENT)                      # a later update without details
    assert stored(client, auth)["details"] is None


def test_oversized_details_reject_the_incident(client, auth, feed):
    big = {**DETAILS, "reports": {"technical": "x" * 40_000, "executive": "e"}}
    feed("security/incidents", {**INCIDENT, "details": big})
    assert client.get("/incidents", headers=auth).json() == []


def test_tampered_details_fail_the_integrity_check(client, auth, feed, sql):
    feed("security/incidents", {**INCIDENT, "details": DETAILS})
    sql("UPDATE incidents SET details_encrypted = :b", b=b"\x02" * 60)
    inc = stored(client, auth)
    assert inc["integrity_ok"] is False and inc["details"] is None


def test_details_are_pushed_over_the_websocket(client, auth, feed):
    token = auth["Authorization"].split()[1]
    with client.websocket_connect("/ws/events", subprotocols=["bearer." + token]) as ws:
        feed("security/incidents", {**INCIDENT, "details": DETAILS})
        msg = json.loads(ws.receive_text())
    assert msg["kind"] == "incident" and msg["data"]["details"]["mitre_technique"] == "T1498"


def test_an_old_database_gets_the_details_column(client, sql):
    sql("ALTER TABLE incidents DROP COLUMN details_encrypted")
    assert "details_encrypted" not in {c["name"] for c in inspect(engine).get_columns("incidents")}
    main._prepare_database()
    assert "details_encrypted" in {c["name"] for c in inspect(engine).get_columns("incidents")}
    main._prepare_database()                                   # running it again is harmless
