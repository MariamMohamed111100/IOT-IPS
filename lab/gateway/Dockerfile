# Lab gateway: the ips_cyber sensor with the ML model (rules + model, flow events + 10-packet windows).
# Build with the repository root as context (docker-compose.lab.yml does). Same base image and the same
# hash-pinned install style as docker/python-service.Dockerfile; the dependency lock is requirements/ml-py312.txt
# (ips, ips_cyber, ml and libs/common together), so every package is pinned with hashes.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements/ml-py312.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt
COPY libs/common /libs/common
COPY ips/pyproject.toml ips/README.md /ips/
COPY ips/src /ips/src
COPY ips/config /ips/config
COPY services/ml /ml
RUN pip install --no-cache-dir --no-deps -e /libs/common -e /ips -e /ml
COPY services/ips_cyber/ /app/
COPY lab/gateway/gateway.py /lab-gateway.py
RUN apt-get update && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app \
    && mkdir -p /run/app-secrets && chown app:app /run/app-secrets
COPY docker/entrypoint.sh /usr/local/bin/sim-entrypoint
RUN chmod +x /usr/local/bin/sim-entrypoint
ENTRYPOINT ["/usr/local/bin/sim-entrypoint"]
CMD ["python", "/lab-gateway.py"]
