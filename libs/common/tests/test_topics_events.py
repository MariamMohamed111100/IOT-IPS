import pytest
from pydantic import ValidationError

from smartsecure_common import make_event, topics


def test_topics():
    assert topics.sensor_event("garage", "pir", "pir_01") == "home/garage/pir/pir_01/event"
    assert topics.device_cmd("garage", "siren", "s1") == "home/garage/siren/s1/cmd"
    assert topics.alert("vision") == "security/alerts/vision"
    assert topics.heartbeat("api") == "system/heartbeat/api"


@pytest.mark.parametrize("bad", ["Garage", "a/b", "#", "+", "has space", ""])
def test_topic_token_injection_rejected(bad):
    with pytest.raises(ValueError):
        topics.sensor_event(bad, "pir", "x")


def test_unknown_alert_source():
    with pytest.raises(ValueError):
        topics.alert("hacker")


def test_event_defaults_and_validation():
    e = make_event("vision", "face.unknown", "garage", "high", confidence=0.93)
    assert e.id and e.ts.endswith("+00:00") and e.data["confidence"] == 0.93
    with pytest.raises(ValidationError):
        make_event("vision", "BadType", "garage")
