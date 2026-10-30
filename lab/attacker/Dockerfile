# Attacker of the lab: nmap, hydra, hping3. It runs only on the internal lab network and
# `attack` refuses any target outside 10.77.0.0/24.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
RUN apt-get update && apt-get install -y --no-install-recommends nmap hydra hping3 iputils-ping curl \
    && rm -rf /var/lib/apt/lists/*
COPY attack.sh /usr/local/bin/attack
COPY wordlist.txt /opt/wordlist.txt
RUN chmod +x /usr/local/bin/attack
CMD ["sleep", "infinity"]
