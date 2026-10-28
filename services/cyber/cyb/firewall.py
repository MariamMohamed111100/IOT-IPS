"""Firewall backends. The engine decides WHO to block; these only enforce it, idempotently."""
from __future__ import annotations

import ipaddress
import logging
import subprocess
from collections.abc import Callable
from typing import Protocol

log = logging.getLogger("cyber.firewall")
CHAIN = "SMARTSECURE_BLOCK"


class FirewallError(RuntimeError):
    pass


class Firewall(Protocol):
    name: str

    dry_run: bool

    def setup(self) -> None: ...
    def block(self, ip: str, seconds: float | None = None, both: bool = False) -> None: ...
    def unblock(self, ip: str) -> None: ...


class BlocklistFirewall:
    """The block-list API simulation: enforcement is the shared state file the BlockManager writes
    (services/cyber/demo/smartlock reads it and refuses blocked sources). Nothing to execute."""

    name = "blocklist"
    dry_run = False

    def __init__(self) -> None:
        self.blocked: set[str] = set()

    def setup(self) -> None:
        self.blocked.clear()

    def block(self, ip: str, seconds: float | None = None, both: bool = False) -> None:
        self.blocked.add(ip)

    def unblock(self, ip: str) -> None:
        self.blocked.discard(ip)


Runner = Callable[[list[str]], tuple[int, str]]


def run_command(cmd: list[str]) -> tuple[int, str]:
    """No shell, fixed argv, short timeout: an IP can never become a command-line option."""
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise FirewallError(f"{cmd[0]} failed: {exc}") from exc
    return done.returncode, (done.stdout + done.stderr).strip()


class IptablesFirewall:
    """Drops traffic from blocked sources in a dedicated chain (INPUT and FORWARD jump to it).

    Needs root + NET_ADMIN in the netns that carries the traffic (see services/cyber/README.md).
    The chain is flushed at start; the BlockManager re-applies the persisted, unexpired blocks.
    """

    name = "iptables"
    dry_run = False

    def __init__(self, run: Runner = run_command) -> None:
        self.run = run

    @staticmethod
    def _checked(ip: str) -> tuple[str, str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise FirewallError(f"not an IP address: {ip!r}") from None
        return ("ip6tables" if addr.version == 6 else "iptables"), str(addr)

    def setup(self) -> None:
        for binary, required in (("iptables", True), ("ip6tables", False)):
            try:
                self._setup_one(binary)
            except FirewallError as exc:
                if required:
                    raise
                log.warning("IPv6 blocking unavailable: %s", exc)

    def _setup_one(self, binary: str) -> None:
        rc, out = self.run([binary, "-N", CHAIN])
        if rc != 0 and "exist" not in out.lower():
            raise FirewallError(f"{binary} -N {CHAIN}: {out}")
        self._must([binary, "-F", CHAIN])
        for hook in ("INPUT", "FORWARD"):
            if self.run([binary, "-C", hook, "-j", CHAIN])[0] != 0:
                self._must([binary, "-I", hook, "1", "-j", CHAIN])

    def block(self, ip: str, seconds: float | None = None, both: bool = False) -> None:
        binary, addr = self._checked(ip)
        if self.run([binary, "-C", CHAIN, "-s", addr, "-j", "DROP"])[0] != 0:
            self._must([binary, "-A", CHAIN, "-s", addr, "-j", "DROP"])
        if both and self.run([binary, "-C", CHAIN, "-d", addr, "-j", "DROP"])[0] != 0:
            self._must([binary, "-A", CHAIN, "-d", addr, "-j", "DROP"])      # isolation: nothing goes TO it either

    def unblock(self, ip: str) -> None:
        binary, addr = self._checked(ip)
        for _ in range(10):                                   # duplicates are possible: remove all
            gone = True
            for flag in ("-s", "-d"):
                if self.run([binary, "-C", CHAIN, flag, addr, "-j", "DROP"])[0] == 0:
                    self._must([binary, "-D", CHAIN, flag, addr, "-j", "DROP"])
                    gone = False
            if gone:
                return

    def _must(self, cmd: list[str]) -> None:
        rc, out = self.run(cmd)
        if rc != 0:
            raise FirewallError(f"{' '.join(cmd)}: {out or 'exit ' + str(rc)}")


TABLE = "smartsecure_ips"

# `nft delete element` prints one of these when the element simply was not there. Anything else is
# a real failure and must not be mistaken for "already gone".
_MISSING_ELEMENT_MARKERS = (
    "no such file or directory",
    "does not exist",
    "no such element",
    "no such set",
)


def _element_is_missing(output: str) -> bool:
    low = (output or "").lower()
    return any(marker in low for marker in _MISSING_ELEMENT_MARKERS)


class NftablesFirewall:
    """Drops blocked sources with nftables. Every block is a set element WITH A TIMEOUT, so the kernel removes
    it by itself even if this service dies (the BlockManager still unblocks earlier on request).

    One table of our own (`inet smartsecure_ips`), deleted and rebuilt at start (startup flush). It has base
    chains on input, forward and output with priority -10 (before other rules). A plain block drops traffic FROM
    the address; isolation (`both=True`) also drops traffic TO it, i.e. both directions of a device.
    Needs root + NET_ADMIN in the network namespace that carries the traffic.
    """

    name = "nftables"
    dry_run = False
    SETS = ("src4", "src6", "iso4", "iso6")

    def __init__(self, run: Runner = run_command) -> None:
        self.run = run

    @staticmethod
    def _checked(ip: str) -> tuple[int, str]:
        # Self-defence: the command line is assembled from these tokens, so refuse anything that is
        # not a plain address. `ipaddress` alone accepts a scope id (fe80::1%eth0), and nft joins
        # its argv before parsing, so a "%" or ";" could be re-read as nft syntax.
        if not isinstance(ip, str) or "%" in ip or "/" in ip or len(ip) > 45:
            raise FirewallError(f"not an IP address: {ip!r}")
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            raise FirewallError(f"not an IP address: {ip!r}") from None
        if str(addr) != ip.strip():
            raise FirewallError(f"not a canonical IP address: {ip!r}")
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped                       # same host, one representation
        return addr.version, str(addr)

    def _must(self, cmd: list[str]) -> None:
        rc, out = self.run(cmd)
        if rc != 0:
            raise FirewallError(f"{' '.join(cmd)}: {out or 'exit ' + str(rc)}")

    def setup(self) -> None:
        self.run(["nft", "delete", "table", "inet", TABLE])          # startup flush; fails when absent: fine
        self._must(["nft", "add", "table", "inet", TABLE])
        for name in self.SETS:
            kind = "ipv6_addr" if name.endswith("6") else "ipv4_addr"
            self._must(["nft", "add", "set", "inet", TABLE, name, "{", "type", kind, ";", "flags", "timeout", ";", "}"])
        rules = {
            "input": ["ip saddr @src4 drop", "ip6 saddr @src6 drop", "ip saddr @iso4 drop", "ip6 saddr @iso6 drop"],
            "forward": ["ip saddr @src4 drop", "ip6 saddr @src6 drop", "ip saddr @iso4 drop", "ip6 saddr @iso6 drop",
                        "ip daddr @iso4 drop", "ip6 daddr @iso6 drop"],
            "output": ["ip daddr @iso4 drop", "ip6 daddr @iso6 drop"],
        }
        for hook, items in rules.items():
            self._must(["nft", "add", "chain", "inet", TABLE, hook, "{", "type", "filter", "hook", hook,
                        "priority", "-10", ";", "policy", "accept", ";", "}"])
            for rule in items:
                self._must(["nft", "add", "rule", "inet", TABLE, hook, *rule.split()])

    def block(self, ip: str, seconds: float | None = None, both: bool = False) -> None:
        version, addr = self._checked(ip)
        name = ("iso" if both else "src") + str(version)
        self.unblock(ip)                                            # re-adding must also renew the timeout
        element = [addr] if seconds is None else [addr, "timeout", "%ds" % max(1, int(seconds + 0.999))]
        self._must(["nft", "add", "element", "inet", TABLE, name, "{", *element, "}"])

    def unblock(self, ip: str) -> None:
        version, addr = self._checked(ip)
        for prefix in ("src", "iso"):
            name = prefix + str(version)
            rc, out = self.run(["nft", "delete", "element", "inet", TABLE, name, "{", addr, "}"])
            # Removing an element that is not there has to be a no-op, but every other failure must
            # surface: the caller drops its own state and "unblocked" it would leave the kernel
            # still dropping traffic, with no way for an operator to lift it.
            if rc != 0 and not _element_is_missing(out):
                raise FirewallError(f"could not remove {addr} from {name}: {out.strip()[:200]}")


class ShadowFirewall:
    """Shadow mode: logs what it WOULD block and enforces nothing. The events it causes say dry_run = true."""

    name = "shadow"
    dry_run = True

    def setup(self) -> None:
        log.warning("SHADOW MODE: blocks are logged and reported but nothing is enforced")

    def block(self, ip: str, seconds: float | None = None, both: bool = False) -> None:
        log.warning("shadow: would %s %s for %s s", "isolate" if both else "block", ip, seconds)

    def unblock(self, ip: str) -> None:
        log.warning("shadow: would unblock %s", ip)


def make_firewall(name: str) -> Firewall:
    if name == "iptables":
        return IptablesFirewall()
    if name == "nftables":
        return NftablesFirewall()
    if name == "shadow":
        return ShadowFirewall()
    if name == "blocklist":
        return BlocklistFirewall()
    raise ValueError(f"unknown firewall backend {name!r}")
