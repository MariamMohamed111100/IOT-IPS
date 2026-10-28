"""Task 4: nftables backend, shadow mode, isolation, block results. The real-kernel test runs only as root with
`nft` and `unshare` present, and ONLY inside a fresh network namespace, never on the host's firewall."""

import json
import os
import shutil
import subprocess
import sys
import textwrap

import pytest
from conftest import FakeClock

from cyb.blocks import BlockManager
from cyb.firewall import TABLE, FirewallError, NftablesFirewall, ShadowFirewall, make_firewall
from cyb.util import parse_networks

CYB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Runner:
    def __init__(self, fail_on=""):
        self.calls, self.fail_on = [], fail_on

    def __call__(self, cmd):
        self.calls.append(cmd)
        return (1, "boom") if self.fail_on and self.fail_on in " ".join(cmd) else (0, "")

    def text(self):
        return [" ".join(c) for c in self.calls]


def test_setup_flushes_then_builds_the_table():
    run = Runner()
    NftablesFirewall(run).setup()
    lines = run.text()
    assert lines[0] == f"nft delete table inet {TABLE}"  # startup flush
    assert any(
        "add set inet %s src4 { type ipv4_addr ; flags timeout ; }" % TABLE in x for x in lines
    )
    assert any(
        "add chain inet %s input { type filter hook input priority -10 ; policy accept ; }" % TABLE
        in x
        for x in lines
    )
    assert all(c[0] == "nft" for c in run.calls)


def test_block_uses_a_timeout_and_an_exact_argv():
    run = Runner()
    NftablesFirewall(run).block("203.0.113.9", 600)
    assert run.calls[-1] == [
        "nft",
        "add",
        "element",
        "inet",
        TABLE,
        "src4",
        "{",
        "203.0.113.9",
        "timeout",
        "600s",
        "}",
    ]
    NftablesFirewall(run).block("2001:db8::9", 30.2, both=True)
    assert run.calls[-1] == [
        "nft",
        "add",
        "element",
        "inet",
        TABLE,
        "iso6",
        "{",
        "2001:db8::9",
        "timeout",
        "31s",
        "}",
    ]


def test_a_bad_address_never_reaches_nft():
    run = Runner()
    for bad in ("-j ACCEPT", "1.2.3.4/24", "x; reboot", "1.2.3.4 }"):
        with pytest.raises(FirewallError):
            NftablesFirewall(run).block(bad, 60)
    assert run.calls == []


def test_unblock_ignores_a_missing_element_and_a_failing_add_raises():
    assert NftablesFirewall(Runner(fail_on="delete element")).unblock("203.0.113.9") is None
    with pytest.raises(FirewallError):
        NftablesFirewall(Runner(fail_on="add element")).block("203.0.113.9", 60)


def test_make_firewall_knows_the_new_backends():
    assert make_firewall("nftables").name == "nftables" and make_firewall("shadow").dry_run is True


class Rec:
    def __init__(self):
        self.items = []

    def __call__(self, type_, severity, data):
        self.items.append((type_, severity, data))


def manager(tmp_path, fw, **kw):
    rec = Rec()
    return BlockManager(
        fw,
        tmp_path / "bl.json",
        rec,
        default_s=3600,
        min_s=30,
        max_s=86400,
        max_blocks=3,
        never_block=parse_networks("192.168.1.1"),
        report_results=True,
        clock=FakeClock(1000.0),
        **kw,
    ), rec


def types(rec):
    return [t for t, _, _ in rec.items]


def test_shadow_mode_reports_dry_run_and_enforces_nothing(tmp_path):
    mgr, rec = manager(tmp_path, ShadowFirewall())
    assert mgr.block("203.0.113.9", 600, "cyber.port_scan", "engine")
    applied = [d for t, _, d in rec.items if t == "cyber.block_applied"][0]
    assert (
        applied["dry_run"] is True
        and applied["action"] == "temporary_block"
        and applied["reason"] == "cyber_port_scan"
    )


def test_isolation_blocks_both_directions_and_only_private_devices(tmp_path):
    run = Runner()
    mgr, rec = manager(tmp_path, NftablesFirewall(run))
    cmd = {
        "id": "iso-12345",
        "ip": "192.168.1.50",
        "direction": "both",
        "device_id": "cam_001",
        "window_seconds": 300,
    }
    assert mgr.handle_command(json.dumps(cmd))
    assert run.calls[-1][5] == "iso4"
    applied = [d for t, _, d in rec.items if t == "cyber.block_applied"][0]
    assert applied["action"] == "isolate_device" and applied["device_id"] == "cam_001"
    assert json.loads((tmp_path / "bl.json").read_text())["blocks"][0]["both"] is True
    # a public address is never "a device": refused and reported
    assert not mgr.handle_command(
        json.dumps({"id": "iso-22222", "ip": "8.8.8.8", "direction": "both"})
    )
    assert (
        rec.items[-1][2]["reason"] == "device_ip_not_private"
        and rec.items[-1][0] == "cyber.block_refused"
    )
    assert not mgr.handle_command(
        json.dumps({"id": "iso-33333", "ip": "203.0.113.9", "direction": "sideways"})
    )


def test_protected_address_and_limits_are_reported_as_refusals(tmp_path):
    mgr, rec = manager(tmp_path, NftablesFirewall(Runner()))
    assert not mgr.block("192.168.1.1", 60, "x", "engine")  # never_block (the gateway)
    for n in range(3):
        assert mgr.block("203.0.113.%d" % (10 + n), 60, "x", "engine")
    assert not mgr.block("203.0.113.99", 60, "x", "engine")  # MAX_BLOCKS
    reasons = [d["reason"] for t, _, d in rec.items if t == "cyber.block_refused"]
    assert reasons == ["source_never_block", "max_blocks_reached"]


def test_a_firewall_failure_is_reported_and_nothing_is_recorded(tmp_path):
    mgr, rec = manager(tmp_path, NftablesFirewall(Runner(fail_on="add element")))
    assert not mgr.block("203.0.113.9", 60, "x", "engine")
    assert mgr.blocks == {} and rec.items[-1][2]["reason"] == "firewall_error"


def test_renewing_a_block_refreshes_the_kernel_timeout(tmp_path):
    run = Runner()
    mgr, rec = manager(tmp_path, NftablesFirewall(run))
    mgr.block("203.0.113.9", 60, "x", "engine")
    mgr.block("203.0.113.9", 600, "x", "engine")
    last = [c for c in run.calls if c[2] == "element"][-3:]
    assert [c[1] for c in last] == ["delete", "delete", "add"] and last[-1][9] == "600s"
    assert types(rec).count("cyber.block_applied") == 1  # one result, not one per renewal


def test_restart_restores_isolation_with_the_remaining_time(tmp_path):
    run = Runner()
    mgr, _ = manager(tmp_path, NftablesFirewall(run))
    mgr.block("192.168.1.50", 600, "x", "engine", both=True, device_id="cam_001")
    run2 = Runner()
    mgr2, _ = manager(tmp_path, NftablesFirewall(run2))
    mgr2.restore()
    assert run2.text()[0].startswith("nft delete table")  # flushed, then re-applied
    assert any(c[5] == "iso4" and c[8] == "timeout" for c in run2.calls if c[2] == "element")
    assert mgr2.blocks["192.168.1.50"].both is True


# ----------------------------------------------------------------------------- the real kernel, in a fresh netns
# `os.geteuid` only exists on POSIX (on Windows the module has no such attribute, which used to
# break collection of this whole file), so ask for it instead of calling it blindly.
IS_ROOT = bool(getattr(os, "geteuid", lambda: -1)() == 0)
REAL = bool(IS_ROOT and shutil.which("nft") and shutil.which("unshare"))

SCRIPT = textwrap.dedent(
    """
    import fcntl, socket, struct, subprocess, sys
    sys.path.insert(0, %r)
    from cyb.firewall import NftablesFirewall
    s = socket.socket(); ifr = struct.pack("16sH", b"lo", 0)
    flags = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, ifr))[1]                # SIOCGIFFLAGS
    fcntl.ioctl(s, 0x8914, struct.pack("16sH", b"lo", flags | 1))                # SIOCSIFFLAGS: IFF_UP
    server = socket.socket(); server.bind(("127.0.0.1", 9)); server.listen(8)
    def reach(src):
        c = socket.socket(); c.settimeout(1.0); c.bind((src, 0))
        try:
            c.connect(("127.0.0.1", 9)); return True
        except OSError:
            return False
        finally:
            c.close()
    fw = NftablesFirewall(); fw.setup()
    out = {"before": [reach("127.0.0.2"), reach("127.0.0.3")]}
    fw.block("127.0.0.2", 30)
    out["blocked"] = [reach("127.0.0.2"), reach("127.0.0.3")]                    # attacker cut off, client untouched
    out["listing"] = subprocess.run(["nft", "list", "set", "inet", "smartsecure_ips", "src4"], capture_output=True, text=True).stdout
    fw.unblock("127.0.0.2")
    out["unblocked"] = [reach("127.0.0.2"), reach("127.0.0.3")]
    fw.block("127.0.0.3", 1)
    import time; time.sleep(2.2)
    out["expired"] = reach("127.0.0.3")                                          # the kernel removed it by itself
    fw.block("127.0.0.2", 30); fw.setup()                                        # startup flush
    out["flushed"] = reach("127.0.0.2")
    import json; print(json.dumps(out))
"""
    % CYB_DIR
)


@pytest.mark.privileged
@pytest.mark.skipif(not REAL, reason="needs root, nft and unshare")
def test_real_nftables_in_a_private_network_namespace():
    done = subprocess.run(
        ["unshare", "-n", sys.executable, "-c", SCRIPT], capture_output=True, text=True, timeout=60
    )
    if "Operation not permitted" in done.stderr or done.returncode != 0 and "nft" in done.stderr:
        pytest.skip("this environment does not allow nftables: " + done.stderr.strip()[-200:])
    assert done.returncode == 0, done.stderr
    out = json.loads(done.stdout.strip().splitlines()[-1])
    assert out["before"] == [True, True]
    assert out["blocked"] == [False, True]
    assert "127.0.0.2" in out["listing"] and "timeout" in out["listing"]
    assert out["unblocked"] == [True, True]
    assert out["expired"] is True
    assert out["flushed"] is True
