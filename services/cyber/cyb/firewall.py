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

    def setup(self) -> None: ...
    def block(self, ip: str) -> None: ...
    def unblock(self, ip: str) -> None: ...


class BlocklistFirewall:
    """The block-list API simulation: enforcement is the shared state file the BlockManager writes
    (services/cyber/demo/smartlock reads it and refuses blocked sources). Nothing to execute."""

    name = "blocklist"

    def __init__(self) -> None:
        self.blocked: set[str] = set()

    def setup(self) -> None:
        self.blocked.clear()

    def block(self, ip: str) -> None:
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

    def block(self, ip: str) -> None:
        binary, addr = self._checked(ip)
        if self.run([binary, "-C", CHAIN, "-s", addr, "-j", "DROP"])[0] != 0:
            self._must([binary, "-A", CHAIN, "-s", addr, "-j", "DROP"])

    def unblock(self, ip: str) -> None:
        binary, addr = self._checked(ip)
        for _ in range(10):                                   # duplicates are possible: remove all
            if self.run([binary, "-C", CHAIN, "-s", addr, "-j", "DROP"])[0] != 0:
                return
            self._must([binary, "-D", CHAIN, "-s", addr, "-j", "DROP"])

    def _must(self, cmd: list[str]) -> None:
        rc, out = self.run(cmd)
        if rc != 0:
            raise FirewallError(f"{' '.join(cmd)}: {out or 'exit ' + str(rc)}")


def make_firewall(name: str) -> Firewall:
    if name == "iptables":
        return IptablesFirewall()
    if name == "blocklist":
        return BlocklistFirewall()
    raise ValueError(f"unknown firewall backend {name!r}")
