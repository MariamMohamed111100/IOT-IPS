import jwt
import main
import pytest
from fastapi.routing import APIRoute

from security import hash_password

PUBLIC = {("GET", "/health"), ("POST", "/auth/login")}


def test_missing_and_garbage_tokens_are_rejected(client):
    assert client.get("/devices").status_code == 401
    assert client.get("/devices", headers={"Authorization": "Bearer abc"}).status_code == 401
    assert client.get("/devices", headers={"Authorization": "Basic abc"}).status_code == 401


def test_expired_and_foreign_tokens_are_rejected(client):
    expired = jwt.encode({"sub": "admin", "exp": 1}, "j" * 48, algorithm="HS256")
    foreign = jwt.encode({"sub": "admin", "exp": 4102444800}, "other-secret" * 4, algorithm="HS256")
    for token in (expired, foreign):
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401


def test_login(client):
    for user, password in (("admin", "no"), ("ghost", "x"), ("admin", "x" * 80)):
        r = client.post("/auth/login", json={"username": user, "password": password})
        assert r.status_code == 401
    r = client.post("/auth/login", json={"username": "admin", "password": "correct-horse"})
    body = r.json()
    assert r.status_code == 200 and body["token_type"] == "bearer"
    assert body["role"] == "admin" and body["username"] == "admin"


def test_brute_force_is_rate_limited(client):
    codes = [client.post("/auth/login", json={"username": "bob", "password": "x"}).status_code
             for _ in range(7)]
    assert codes == [401] * 5 + [429] * 2


def test_failed_attempts_never_lock_a_correct_password_out(client):
    """Five wrong tries must throttle guessing, not deny the real user (the API sits behind
    nginx, so the limiter key degenerates to the username)."""
    for _ in range(6):
        r = client.post("/auth/login", json={"username": "admin", "password": "x"})
        assert r.status_code in (401, 429)
    ok = client.post("/auth/login", json={"username": "admin", "password": "correct-horse"})
    assert ok.status_code == 200 and ok.json()["role"] == "admin"


def test_an_oversized_request_body_is_refused(client, auth):
    huge = {"device_id": "d1", "name": "x" * 200, "device_type": "bulb", "zone": "kitchen",
            "state": {"blob": "y" * (200 * 1024)}}
    r = client.post("/devices", json=huge, headers=auth)
    assert r.status_code == 413


def test_device_state_is_bounded_far_below_the_body_cap(client, auth):
    r = client.post("/devices", json={"device_id": "d1", "name": "plug", "device_type": "bulb",
                                      "zone": "kitchen", "state": {"note": "z" * 6000}},
                    headers=auth)
    assert r.status_code == 422


def test_me(client, auth):
    body = client.get("/auth/me", headers=auth).json()
    assert body["username"] == "admin" and body["role"] == "admin"


def test_a_user_without_a_role_label_only_reads(client, monkeypatch):
    """Least privilege: `bob:secret` must not become an operator just because it is not "viewer"."""
    monkeypatch.setenv("API_USERS", "bob:secret")
    r = client.post("/auth/login", json={"username": "bob", "password": "secret"})
    assert r.status_code == 401                            # plaintext secrets never authenticate
    monkeypatch.setenv("API_USERS", f"bob:{hash_password('secret')}")
    r = client.post("/auth/login", json={"username": "bob", "password": "secret"})
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/devices", headers=headers).status_code == 200       # reading is allowed
    new_device = {"device_id": "d1", "name": "x", "device_type": "bulb", "zone": "kitchen"}
    assert client.post("/devices", json=new_device, headers=headers).status_code == 403


def test_scrypt_users_authenticate(client, monkeypatch):
    from security import hash_password

    monkeypatch.setenv("API_USERS", f"admin:{hash_password('correct-horse')}:admin")
    bad = client.post("/auth/login", json={"username": "admin", "password": "nope"})
    assert bad.status_code == 401
    ok = client.post("/auth/login", json={"username": "admin", "password": "correct-horse"})
    assert ok.status_code == 200 and ok.json()["role"] == "admin"


def test_jwt_without_audience_is_rejected(client):
    token = jwt.encode(
        {"sub": "admin", "role": "admin", "exp": 4102444800}, "j" * 48, algorithm="HS256"
    )
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_viewer_cannot_command_or_audit(client, house):
    token = client.post("/auth/login", json={"username": "viewer", "password": "other-pass"}).json()
    headers = {"Authorization": "Bearer " + token["access_token"]}
    assert token["role"] == "viewer"
    assert client.get("/devices", headers=headers).status_code == 200
    assert client.post(
        "/devices/siren_main/command", json={"action": "on"}, headers=headers
    ).status_code == 403
    assert client.post("/zones", json={"name": "lab"}, headers=headers).status_code == 403
    assert client.get("/audit", headers=headers).status_code == 403


def test_health_is_public_and_reports_dependencies(client):
    body = client.get("/health").json()
    assert body == {"status": "ok", "mqtt_connected": True, "db": True}


def test_swagger_is_off_unless_enabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def _http_routes(routes=None):
    """Every HTTP route the app serves.

    FastAPI wraps included routers lazily (`_IncludedRouter`), so they do not show up as plain
    `APIRoute` in ``app.routes``; unwrap them so a route added later without auth is really
    exercised instead of silently skipped."""
    for route in main.app.routes if routes is None else routes:
        included = getattr(route, "original_router", None)
        if included is not None:
            yield from _http_routes(included.routes)
        elif isinstance(route, APIRoute):
            yield route


@pytest.mark.parametrize("route", list(_http_routes()),
                         ids=lambda r: f"{sorted(r.methods)[0]} {r.path}")
def test_every_http_route_requires_a_token(client, route):
    """Secure by default: a route added later without auth fails this test."""
    method = sorted(route.methods)[0]
    path = route.path.replace("{device_id}", "x").replace("{event_id}", "x") \
        .replace("{incident_id}", "x")
    status = client.request(method, path).status_code
    if (method, route.path) in PUBLIC:
        assert status != 401, "public route must not demand a token"
    else:
        assert status == 401
