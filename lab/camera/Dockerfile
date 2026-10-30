# Fake camera of the lab (see docker-compose.lab.yml). Standard library only.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
COPY camera.py /camera.py
USER 10001
CMD ["python", "-u", "/camera.py"]
