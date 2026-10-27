#!/usr/bin/env bash
# Passes only if: every service heartbeats through the TLS broker, the broker
# rejects cert-less clients (mTLS) and cross-service ACL reads (least
# privilege), the API enforces JWT (contract section 5), and the frontend
# nginx proxy serves REST (/api/*) and WebSocket (/ws/*) on the dashboard
# origin (http://localhost:8080).
set -uo pipefail
cd "$(dirname "$0")/.."
# Windows (Git Bash/MSYS): disable argument path conversion. Without this, MSYS
# rewrites --cafile /mosquitto/certs/ca.crt into a Windows path, docker exec
# passes it through, and mosquitto_sub dies with "File not found".
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' ;;
esac
# Windows: the `docker` CLI is not on PATH for Git Bash unless added manually.
if ! command -v docker >/dev/null 2>&1; then
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      for p in "/c/Program Files/Docker/Docker/resources/bin" \
               "${LOCALAPPDATA:-/c/Users/$USER/AppData/Local}/Programs/DockerDesktop/resources/bin"; do
        if [ -x "$p/docker.exe" ]; then export PATH="$p:$PATH"; break; fi
      done
      ;;
  esac
fi
set -a; . ./.env; set +a
EXPECTED=(api simulators vision cyber engine)
# admin client cert is copied into the mosquitto container by its entrypoint
CERT="--cert /mosquitto/config/certs/admin.crt --key /mosquitto/config/certs/admin.key"
fail=0

echo ">> Listening for heartbeats (15s)..."
OUT=$(docker compose exec -T mosquitto mosquitto_sub -h localhost -p 8883 \
  --cafile /mosquitto/config/certs/ca.crt $CERT -u admin -P "$MQTT_PASSWORD_ADMIN" \
  -t 'system/heartbeat/#' -v -W 15 2>&1 || true)

for s in "${EXPECTED[@]}"; do
  if grep -q "system/heartbeat/$s " <<<"$OUT"; then echo "  OK    $s"; else echo "  FAIL  $s"; fail=1; fi
done

echo ">> mTLS: the broker must reject clients without a certificate..."
PLAIN=$(docker compose exec -T mosquitto mosquitto_sub -h localhost -p 8883 \
  --cafile /mosquitto/config/certs/ca.crt -u admin -P "$MQTT_PASSWORD_ADMIN" \
  -t 'system/heartbeat/#' -W 3 2>&1 || true)
if grep -q "system/heartbeat/" <<<"$PLAIN"; then
  echo "  FAIL  broker accepted a client without a certificate"; fail=1
else
  echo "  OK    certificate-less client refused"
fi

echo ">> ACL: a service MUST NOT read outside its lane..."
# mosquitto authorises at message DELIVERY, not at SUBSCRIBE time (the SUBACK
# is always granted), so judge by delivery: simulators subscribes while engine
# (allowed to write security/risk) publishes a marker. No message may arrive.
SUB=$(mktemp); trap 'rm -f "$SUB"' EXIT
docker compose exec -T simulators python - <<'PY' >"$SUB" 2>&1 &
import os
import time

import paho.mqtt.client as mqtt

got = []

def on_connect(client, userdata, flags, reason_code, properties=None):
    if not getattr(reason_code, "is_failure", False):
        client.subscribe("security/risk", qos=1)  # engine-only read

def on_message(client, userdata, msg):
    got.append(msg.payload.decode())

c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="acl-negative-sub")
c.tls_set(ca_certs="/certs/ca.crt",
          certfile="/certs/clients/simulators.crt",
          keyfile="/run/app-secrets/sim_client_key")
c.username_pw_set("simulators", os.environ["MQTT_PASSWORD"])
c.on_connect = on_connect
c.on_message = on_message
c.connect("mosquitto", 8883, 60)
c.loop_start()
time.sleep(8)
print("RECEIVED:" + ",".join(got) if got else "NO_MESSAGE")
PY
SUB_PID=$!
sleep 2
docker compose exec -T engine python - <<'PY'
import os
import time

import paho.mqtt.client as mqtt

c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="acl-negative-pub")
c.tls_set(ca_certs="/certs/ca.crt",
          certfile="/certs/clients/engine.crt",
          keyfile="/run/app-secrets/engine_client_key")
c.username_pw_set("engine", os.environ["MQTT_PASSWORD"])

def on_connect(client, userdata, flags, reason_code, properties=None):
    if not getattr(reason_code, "is_failure", False):
        c.publish("security/risk", b"acl-probe", qos=1)

c.on_connect = on_connect
c.connect("mosquitto", 8883, 60)
c.loop_start()
time.sleep(4)
PY
wait "$SUB_PID"
if grep -q NO_MESSAGE "$SUB"; then
  echo "  OK    simulators cannot read security/risk"
else
  echo "  FAIL  ACL negative check: simulators received security/risk"; fail=1
fi

echo ">> API auth: JWT must be required (contract section 5)..."
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
$PY - <<'PYEOF' "${API_USERS#admin:}"
import json
import sys
import urllib.error
import urllib.request
import ssl

password = sys.argv[1]
base = "https://localhost:8443"
ctx = ssl.create_default_context(cafile="infra/certs/ca.crt")
fails = 0


def code(method, path, body=None, token=None):
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def expect(name, want, got):
    global fails
    if want == got:
        print(f"  OK    {name}")
    else:
        print(f"  FAIL  {name}: got {got}, want {want}")
        fails += 1


expect("anonymous /auth/me -> 401", 401, code("GET", "/auth/me")[0])
expect("bad password -> 401", 401, code("POST", "/auth/login", {"username": "admin", "password": "wrong"})[0])
status, payload = code("POST", "/auth/login", {"username": "admin", "password": password})
expect("valid login -> 200", 200, status)
token = json.loads(payload).get("access_token", "") if status == 200 else ""
expect("valid token /auth/me -> 200", 200, code("GET", "/auth/me", token=token)[0])

sys.exit(fails)
PYEOF
[ $? -eq 0 ] || fail=1

echo ">> Simulators: every device must publish retained status..."
STATUS=$(docker compose exec -T mosquitto mosquitto_sub -h localhost -p 8883 \
  --cafile /mosquitto/config/certs/ca.crt $CERT -u admin -P "$MQTT_PASSWORD_ADMIN" \
  -t 'home/+/+/+/status' -v -W 6 2>&1 || true)
N=$(grep -c '^home/' <<<"$STATUS")
if [ "$N" -ge 15 ]; then echo "  OK    $N device statuses"; else echo "  FAIL  only $N device statuses (need >= 15)"; fail=1; fi

echo ">> Simulators: scenario water_leak must produce a contract event through mTLS..."
EV=$(mktemp)
docker compose exec -T mosquitto mosquitto_sub -h localhost -p 8883 \
  --cafile /mosquitto/config/certs/ca.crt $CERT -u admin -P "$MQTT_PASSWORD_ADMIN" \
  -t 'home/+/water_leak/+/event' -C 1 -W 20 >"$EV" 2>&1 &
EV_PID=$!
sleep 3
docker compose exec -T simulators python scenario_runner.py water_leak >/dev/null 2>&1
wait "$EV_PID" || true
if grep -q '"type":"water.leak"' "$EV"; then echo "  OK    water.leak event received"; else echo "  FAIL  no water.leak event"; fail=1; fi
rm -f "$EV"

echo ">> API pipeline: simulators -> mTLS broker -> API -> Postgres -> REST..."
$PY - <<'PYEOF' "${API_USERS#admin:}"
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

base = "https://localhost:8443"
ctx = ssl.create_default_context(cafile="infra/certs/ca.crt")


def call(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


def wait_for(name, check, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if check():
            print(f"  OK    {name}")
            return 0
        time.sleep(1)
    print(f"  FAIL  {name} (not true after {timeout}s)")
    return 1


fails = 0
status, body = call("POST", "/auth/login", {"username": "admin", "password": sys.argv[1]})
token = body["access_token"] if status == 200 else ""
for path in ("/devices", "/events", "/incidents", "/audit"):
    code = call("GET", path)[0]
    if code == 401:
        print(f"  OK    anonymous GET {path} -> 401")
    else:
        print(f"  FAIL  anonymous GET {path} -> {code}")
        fails += 1
fails += wait_for("devices registered from simulator status (>= 15)",
                  lambda: len(call("GET", "/devices", token=token)[1] or []) >= 15, 30)
fails += wait_for("water.leak event stored and readable via REST (integrity ok)",
                  lambda: any(e["integrity_ok"] for e in
                              (call("GET", "/events?type=water.leak&limit=5", token=token)[1] or [])), 20)
fails += wait_for("zones seeded from config/zones.yaml (7)",
                  lambda: len(call("GET", "/zones", token=token)[1] or []) == 7, 10)
sys.exit(fails)
PYEOF
[ $? -eq 0 ] || fail=1

echo ">> Frontend proxy: dashboard origin (8080) -> API /api/health..."
PROXY=$(curl -s -m 10 http://localhost:8080/api/health 2>&1 || true)
if printf '%s' "$PROXY" | grep -q '"status":"ok"' \
   && printf '%s' "$PROXY" | grep -q '"mqtt_connected":true' \
   && printf '%s' "$PROXY" | grep -q '"db":true'; then
  echo "  OK    GET /api/health through nginx (status/mqtt/db all true)"
else
  echo "  FAIL  /api/health through nginx: $PROXY"; fail=1
fi

echo ">> WebSocket via nginx: full loop (scenario -> broker -> API -> WS -> client)..."
WSB=$(mktemp); WSO=$(mktemp)
cat >"$WSB" <<'PY'
import json as _json
import os
import sys
import time
import urllib.request

user, _, password = os.environ["API_USERS"].split(",")[0].partition(":")
req = urllib.request.Request(
    "http://frontend:80/api/auth/login",
    data=_json.dumps({"username": user, "password": password}).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=10) as r:
    token = _json.load(r)["access_token"]

from websockets.sync.client import connect

t0 = time.time()
loops = 0
with connect("ws://frontend:80/ws/events?token=" + token, open_timeout=10) as ws:
    while time.time() - t0 < 30:
        msg = _json.loads(ws.recv(timeout=30))
        loops += 1
        if msg.get("kind") == "event" and msg.get("data", {}).get("type") == "water.leak":
            print("KIND=event TYPE=water.leak t=%.0fs (frames=%d)" %
                  (time.time() - t0, loops), flush=True)
            sys.exit(0)
print("TIMEOUT no water.leak event over WS (frames=%d)" % loops, file=sys.stderr)
sys.exit(1)
PY
docker compose exec -T api python - <"$WSB" >"$WSO" 2>&1 &
WSPID=$!
sleep 3
docker compose exec -T simulators python scenario_runner.py water_leak >/dev/null 2>&1
wait "$WSPID" || true
rm -f "$WSB"
if grep -q "KIND=event TYPE=water.leak" "$WSO"; then
  echo "  OK    water.leak event received over WebSocket via nginx"
else
  echo "  FAIL  no water.leak event over WebSocket via nginx: $(tr '\n' ' ' < "$WSO")"; fail=1
fi
rm -f "$WSO"

[ $fail -eq 0 ] && echo ">> Smoke test PASSED" || { echo ">> Smoke test FAILED"; exit 1; }
