#!/usr/bin/env bash
# Regenerate the hash-pinned requirement locks used by CI and by the Docker images.
#
# OpenSSF Scorecard ("Pinned-Dependencies") requires every `pip install` to pin
# exact versions with hashes, so every install in CI/Docker installs one of these
# lock files with `--require-hashes`. The locks are resolved for the CI/Docker
# target: CPython on x86_64 Linux (GitHub's ubuntu-24.04 runners and
# python:3.12-slim are both glibc/amd64).
#
# Re-run this script and commit the result whenever a dependency changes.
#
#   pip install uv          # or: curl -LsSf https://astral.sh/uv/install.sh | sh
#   ./scripts/lock-requirements.sh
set -euo pipefail
cd "$(dirname "$0")/.."

UV=${UV:-uv}
# (no --no-header: uv writes the exact generation command at the top of each lock)
UV_ARGS=(--quiet --generate-hashes --no-annotate
         --python-platform x86_64-unknown-linux-gnu)

lock() { # lock <output> <python-version> [extra uv args...] <inputs...>
  local out="$1" py="$2"
  shift 2
  echo "==> $out (CPython $py, x86_64-unknown-linux-gnu)"
  $UV pip compile "${UV_ARGS[@]}" --python-version "$py" -o "$out" "$@"
}

# ---------------------------------------------------------------- CI locks
# .github/workflows/ci.yml (lint-test job).
lock requirements/ci-py312.txt 3.12 \
  requirements/ci.in \
  libs/common/pyproject.toml \
  services/api/requirements.txt \
  services/vision/requirements.txt \
  services/engine/requirements.txt \
  services/cyber/requirements.txt
# .github/workflows/ci.yml (pip-audit step). `pip` itself is left out of the
# lock: pip-audit only needs it as a library and the runner ships its own pip.
lock requirements/audit-py312.txt 3.12 --no-emit-package pip requirements/audit.in

# .github/workflows/ips-tests.yml - "ips" job, both matrix versions. The file
# name embeds the matrix version so the workflow can reference it directly.
lock requirements/ips-dev-3.10.txt 3.10 --extra dev ips/pyproject.toml
lock requirements/ips-dev-3.12.txt 3.12 --extra dev ips/pyproject.toml
# .github/workflows/ips-tests.yml - "Dataset checks" step (Python 3.12 only).
lock requirements/ips-data-py312.txt 3.12 --extra data ips/pyproject.toml
# .github/workflows/ips-tests.yml - "ips-cyber" job (ips + ips_cyber + common).
lock requirements/ips-cyber-py312.txt 3.12 --extra dev \
  ips/pyproject.toml \
  services/ips_cyber/requirements.txt \
  libs/common/pyproject.toml

# ------------------------------------------------------------ Docker locks
# One per service built from docker/python-service.Dockerfile. Each lock is
# self-contained: the service requirements plus libs/common's dependencies.
for service in api simulators vision cyber engine; do
  lock "docker/locks/${service}.txt" 3.12 \
    "services/${service}/requirements.txt" \
    libs/common/pyproject.toml
done
