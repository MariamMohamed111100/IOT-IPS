import os

import pytest
from conftest import FakeClock, write_lines

from cyb.allowlist import Allowlist
from cyb.arp import read_arp
from cyb.eve import EveTailer


def test_missing_file_means_detection_off(tmp_path):
    al = Allowlist(tmp_path / "nope.yaml")
    assert not al.enabled and not al.known("aa:bb:cc:00:00:01")


def test_loads_macs_and_skips_invalid_entries(tmp_path):
    f = tmp_path / "k.yaml"
    f.write_text('devices:\n  - mac: "AA-BB-CC-00-00-01"\n    name: lock\n  - mac: nonsense\n'
                 '  - "aa:bb:cc:00:00:02"\n  - 42\n', encoding="utf-8")
    al = Allowlist(f)
    assert al.enabled and set(al.macs) == {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}
    assert al.macs["aa:bb:cc:00:00:01"] == "lock"


@pytest.mark.parametrize("text", ["", "devices: []", "- just\n- a list", "devices: {a: b}",
                                  "{{{ not yaml"])
def test_empty_or_broken_files_keep_detection_off(tmp_path, text):
    f = tmp_path / "k.yaml"
    f.write_text(text, encoding="utf-8")
    assert not Allowlist(f).enabled


def test_file_changes_are_picked_up_without_restart(tmp_path):
    f, clock = tmp_path / "k.yaml", FakeClock()
    f.write_text('devices:\n  - mac: "aa:bb:cc:00:00:01"\n', encoding="utf-8")
    al = Allowlist(f, clock=clock, recheck_s=5)
    f.write_text('devices:\n  - mac: "aa:bb:cc:00:00:09"\n', encoding="utf-8")
    os.utime(f, ns=(1, 1))                                   # guarantee a different mtime
    al.refresh()
    assert al.known("aa:bb:cc:00:00:01")                     # too soon to re-check
    clock.advance(6)
    al.refresh()
    assert al.known("aa:bb:cc:00:00:09") and not al.known("aa:bb:cc:00:00:01")


def test_arp_table_parsing(tmp_path):
    f = tmp_path / "arp"
    f.write_text("IP address       HW type     Flags       HW address            Mask     Device\n"
                 "192.168.1.5      0x1         0x2         aa:bb:cc:00:00:05     *        eth0\n"
                 "192.168.1.6      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
                 "garbage line\n", encoding="utf-8")
    assert read_arp(f) == [("192.168.1.5", "aa:bb:cc:00:00:05")]
    assert read_arp(tmp_path / "missing") == []


def test_tailer_starts_at_the_end_and_returns_only_new_records(tmp_path):
    f = tmp_path / "eve.json"
    write_lines(f, {"old": 1})
    t = EveTailer(f)
    assert t.poll() == []
    write_lines(f, {"n": 1}, {"n": 2})
    assert t.poll() == [{"n": 1}, {"n": 2}]
    assert t.poll() == []


def test_tailer_from_start_replays_the_file(tmp_path):
    f = tmp_path / "eve.json"
    write_lines(f, {"old": 1})
    assert EveTailer(f, from_start=True).poll() == [{"old": 1}]


def test_a_file_that_appears_later_is_read_from_its_first_byte(tmp_path):
    f = tmp_path / "eve.json"
    t = EveTailer(f)
    assert t.poll() == []
    write_lines(f, {"n": 1})
    assert t.poll() == [{"n": 1}]
    write_lines(f, {"n": 2})
    assert t.poll() == [{"n": 2}]


def test_tailer_keeps_a_half_written_line_until_complete(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text("", encoding="utf-8")
    t = EveTailer(f)
    t.poll()
    write_lines(f, raw='{"n": ')
    assert t.poll() == []
    write_lines(f, raw="7}\n")
    assert t.poll() == [{"n": 7}]


def test_tailer_survives_rotation_and_truncation(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text("", encoding="utf-8")
    t = EveTailer(f)
    t.poll()
    write_lines(f, {"n": 1})
    assert t.poll() == [{"n": 1}]
    os.replace(f, tmp_path / "eve.json.1")                   # logrotate: new file, new inode
    write_lines(f, {"n": 2})
    assert t.poll() == [{"n": 2}]
    write_lines(f, mode="w")                                 # copytruncate-style: emptied in place
    assert t.poll() == []
    write_lines(f, {"n": 3})
    assert t.poll() == [{"n": 3}]


def test_tailer_drops_junk_lines(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text("", encoding="utf-8")
    t = EveTailer(f)
    t.poll()
    write_lines(f, {"ok": 1}, raw="not json\n[1,2]\n\n\"str\"\n")
    assert t.poll() == [{"ok": 1}]
