FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
RUN useradd -r -u 10002 lock
WORKDIR /app
COPY smartlock.py /app/smartlock.py
USER lock
EXPOSE 8080
CMD ["python", "smartlock.py"]
