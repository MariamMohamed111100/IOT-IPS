# One Dockerfile for every Python service. Build with --build-arg SERVICE=<folder in services/>
# The base image is pinned to a digest and every pip install is hash-pinned (see
# scripts/lock-requirements.sh), so builds are reproducible and OpenSSF
# Scorecard's Pinned-Dependencies check passes.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ARG SERVICE
# optional extra OS packages for one service (cyber: iptables for the real IPS backend)
ARG APT_EXTRA=""
ENV PYTHONUNBUFFERED=1
WORKDIR /app
# docker/locks/${SERVICE}.txt is a hash-pinned lock of the service requirements
# plus the dependencies of libs/common (see scripts/lock-requirements.sh).
COPY docker/locks/${SERVICE}.txt /tmp/requirements.txt
COPY libs/common /libs/common
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && pip install --no-cache-dir --no-deps -e /libs/common
# WITH_IPS=1 also installs the IoT-IPS package (engine: risk, policy and reports for incident details).
# It is installed editable because its modules read their config files relative to the package
# folder; --no-deps is safe because the lock above already pinned its only dependency (pyyaml).
ARG WITH_IPS=0
COPY ips/pyproject.toml ips/README.md /ips/
COPY ips/src /ips/src
COPY ips/config /ips/config
RUN if [ "$WITH_IPS" = "1" ]; then pip install --no-cache-dir --no-deps -e /ips; else rm -rf /ips; fi
COPY services/${SERVICE}/ /app/
RUN apt-get update && apt-get install -y --no-install-recommends gosu ${APT_EXTRA} \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app \
    && mkdir -p /run/app-secrets && chown app:app /run/app-secrets
COPY docker/entrypoint.sh /usr/local/bin/sim-entrypoint
RUN chmod +x /usr/local/bin/sim-entrypoint
# sim-entrypoint runs as root: it copies Docker secrets (root-only, mode 0400
# on Linux) to /run/app-secrets and chowns them to app, then execs `gosu app`.
ENTRYPOINT ["/usr/local/bin/sim-entrypoint"]
CMD ["python", "main.py"]
