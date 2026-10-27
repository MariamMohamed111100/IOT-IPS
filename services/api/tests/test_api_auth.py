import jwt
import main
import pytest
from fastapi.routing import APIRoute

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
    for user, password in (("admin", "no"), ("ghost", "x")):
        r = client.post("/auth/login", json={"username": user, "password": password})
        assert r.status_code == 401
    r = client.post("/auth/login", json={"username": "admin", "password": "correct-horse"})
    assert r.status_code == 200 and r.json()["token_type"] == "bearer"


def test_brute_force_is_rate_limited(client):
    codes = [client.post("/auth/login", json={"username": "bob", "password": "x"}).status_code
             for _ in range(7)]
    assert codes == [401] * 5 + [429] * 2


def test_me(client, auth):
    assert client.get("/auth/me", headers=auth).json()["username"] == "admin"


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
