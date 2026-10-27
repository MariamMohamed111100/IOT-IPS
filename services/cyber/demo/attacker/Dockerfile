# Demo attacker: nmap (port scan), hydra (brute force), a raw DHCP client (rogue device).
# For use against YOUR OWN demo stack only (it targets the `smartlock` container).
FROM alpine:3.20
RUN apk add --no-cache nmap hydra python3 bash
COPY attack.sh /usr/local/bin/attack
COPY dhcp_discover.py /opt/dhcp_discover.py
COPY wordlist.txt /opt/wordlist.txt
RUN chmod +x /usr/local/bin/attack
CMD ["sleep", "infinity"]
