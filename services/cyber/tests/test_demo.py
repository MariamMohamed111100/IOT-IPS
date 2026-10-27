"""The demo rig: the attacker's raw DHCP packet and the victim that plays the firewall."""
import http.client
import importlib.util
import json
import os
import threading
import time
from http.server import ThreadingHTTPServer

import pytest
from conftest import SERVICE

SERVER_ERRORS = (http.client.HTTPException, OSError)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dhcp_discover = load(SERVICE / "demo/attacker/dhcp_discover.py", "dhcp_discover")
smartlock = load(SERVICE / "demo/smartlock/smartlock.py", "smartlock")


def test_dhcp_discover_packet_layout():
    pkt = dhcp_discover.build_discover("de:ad:be:ef:00:01", "rogue-demo", xid=0x01020304)
    assert pkt[0] == 1 and pkt[1] == 1 and pkt[2] == 6                    # BOOTREQUEST, ethernet, 6
    assert pkt[4:8] == bytes([1, 2, 3, 4])
    assert pkt[28:34] == bytes.fromhex("deadbeef0001")                    # chaddr = the fake MAC
    assert pkt[236:240] == dhcp_discover.MAGIC
    options = pkt[240:]
    assert options[:3] == bytes([53, 1, 1]) and options[-1] == 255        # DHCPDISCOVER ... END
    assert bytes([12, 10]) + b"rogue-demo" in options


@pytest.mark.parametrize("bad", ["de:ad:be:ef:00", "zz:zz:zz:zz:zz:zz", ""])
def test_dhcp_discover_rejects_bad_macs(bad):
    with pytest.raises(ValueError):
        dhcp_discover.build_discover(bad)


def test_dhcp_full_handshake_packets_carry_the_lease():
    xid = 0x01020304
    req = dhcp_discover.build_request("de:ad:be:ef:00:01", "rogue-demo", xid=xid)
    assert req[0] == 1 and req[4:8] == bytes([1, 2, 3, 4])
    assert req[28:34] == bytes.fromhex("deadbeef0001")
    assert bytes([53, 1, 3]) in req[240:]                              # DHCPREQUEST
    assert bytes([50, 4, 192, 168, 1, 77]) in req[240:]                # requested IP
    assert bytes([54, 4, 192, 168, 1, 1]) in req[240:]                 # server id

    ack = dhcp_discover.build_reply("ack", "de:ad:be:ef:00:01", xid)
    assert ack[0] == 2                                                 # BOOTREPLY
    assert ack[16:20] == bytes([192, 168, 1, 77])                      # yiaddr = lease
    assert ack[28:34] == bytes.fromhex("deadbeef0001")
    assert bytes([53, 1, 5]) in ack[240:]                              # DHCPACK
    assert bytes([12, 10]) + b"rogue-demo" in ack[240:]

    offer = dhcp_discover.build_reply("offer", "de:ad:be:ef:00:01", xid)
    assert bytes([53, 1, 2]) in offer[240:]                            # DHCPOFFER


def write_blocklist(path, ip, expires_at):
    path.write_text(json.dumps({"version": 1, "blocks": [{"ip": ip, "expires_at": expires_at}]}))


def test_victim_blocklist_semantics(tmp_path):
    f = tmp_path / "bl.json"
    bl = smartlock.Blocklist(f)
    assert bl.is_blocked("1.2.3.4", now=100) is False                    # no file: nobody blocked
    write_blocklist(f, "1.2.3.4", 200)
    assert bl.is_blocked("1.2.3.4", now=100) and not bl.is_blocked("5.6.7.8", now=100)
    assert not bl.is_blocked("1.2.3.4", now=300)                         # expired
    f.write_text("{{{ broken")
    assert bl.is_blocked("1.2.3.4", now=100) is False


def test_victim_blocklist_never_serves_a_stale_answer(tmp_path):
    """Coarse filesystem timestamps (Docker Desktop on Windows) must not freeze the verdict."""
    f = tmp_path / "bl.json"
    bl = smartlock.Blocklist(f)
    write_blocklist(f, "1.2.3.4", 200)
    st = f.stat()
    assert bl.is_blocked("1.2.3.4", now=100)
    write_blocklist(f, "1.2.3.4", 100)                                   # same size, now expired
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))                     # and the same mtime
    assert not bl.is_blocked("1.2.3.4", now=100)


def test_victim_password_check_is_exact():
    assert smartlock.check_login("admin", smartlock.PASSWORD)
    assert not smartlock.check_login("admin", "123456")
    assert not smartlock.check_login("root", smartlock.PASSWORD)


@pytest.fixture
def server(tmp_path):
    smartlock.Handler.blocklist = smartlock.Blocklist(tmp_path / "bl.json")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), smartlock.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, tmp_path / "bl.json"
    srv.shutdown()
    srv.server_close()


def post(srv, body, path="/login"):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=3)
    try:
        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        return resp.status, resp.read().decode()
    finally:
        conn.close()


def test_victim_login_flow(server):
    srv, _ = server
    assert post(srv, "user=admin&pass=123456") == (401, "denied")
    assert post(srv, f"user=admin&pass={smartlock.PASSWORD}") == (200, "unlocked")
    assert post(srv, "user=admin&pass=x", path="/other")[0] == 404
    assert post(srv, "garbage")[0] == 401


def test_victim_drops_blocked_sources_before_reading_anything(server):
    srv, blocklist = server
    assert post(srv, "user=admin&pass=x")[0] == 401
    write_blocklist(blocklist, "127.0.0.1", time.time() + 60)
    with pytest.raises(SERVER_ERRORS):
        post(srv, "user=admin&pass=x")
    write_blocklist(blocklist, "127.0.0.1", time.time() - 1)             # block expired
    assert post(srv, "user=admin&pass=x")[0] == 401
