# Demo attacker: nmap (port scan), hydra (brute force), a raw DHCP client (rogue device).
# For use against YOUR OWN demo stack only (it targets the `smartlock` container).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache nmap hydra python3 bash
COPY attack.sh /usr/local/bin/attack
COPY dhcp_discover.py /opt/dhcp_discover.py
COPY wordlist.txt /opt/wordlist.txt
RUN chmod +x /usr/local/bin/attack
CMD ["sleep", "infinity"]
