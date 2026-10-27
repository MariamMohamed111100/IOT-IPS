#!/usr/bin/env bash
# Builds infra/mosquitto/passwd from the MQTT_PASSWORD_* values in .env
set -euo pipefail
cd "$(dirname "$0")/.."
# Windows (Git Bash/MSYS): disable argument path conversion. Without this, MSYS
# rewrites the mount target "/work" into "C:/Program Files/Git/work" and the
# password file silently never appears inside the container.
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
USERS=(admin api simulators vision cyber engine)
OUT=infra/mosquitto/passwd
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }   # ${u^^} needs bash 4
: > "$OUT"

if command -v mosquitto_passwd >/dev/null 2>&1; then
  for u in "${USERS[@]}"; do
    v="MQTT_PASSWORD_$(upper "$u")"; mosquitto_passwd -b "$OUT" "$u" "${!v}"
  done
else
  # Run the generator as the invoking user so the written file is ours and the
  # host `chmod 600` below succeeds (Linux) instead of aborting on a root-owned
  # bind-mount file. Omitted on MSYS where Docker Desktop maps the FS itself.
  user_arg=()
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) ;;
    *) command -v id >/dev/null 2>&1 && user_arg=(--user "$(id -u):$(id -g)") || true ;;
  esac
  # Build the file inside the container (owner-only mode, no warnings from a
  # world-readable bind mount) and only then copy it to the shared folder.
  cmds=": > /tmp/passwd; "
  for u in "${USERS[@]}"; do
    v="MQTT_PASSWORD_$(upper "$u")"; cmds+="mosquitto_passwd -b /tmp/passwd $u ${!v}; "
  done
  cmds+="cat /tmp/passwd > /work/passwd"
  docker run "${user_arg[@]}" --rm -v "$PWD/infra/mosquitto:/work" eclipse-mosquitto:2 \
    sh -c "umask 077; $cmds"
fi
chmod 600 "$OUT"   # owner-only; the broker entrypoint fixes ownership in-container
echo ">> MQTT users written: ${USERS[*]}"
