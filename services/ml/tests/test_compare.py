"""compare_pcap must report a perfect match when the CSV came from our own extractor, and must
notice when a feature was computed differently."""
import random
import sys
from pathlib import Path

import dpkt
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_extractor import CAM, PHONE, tcp, udp

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from compare_pcap import compare

from ids_ml.extractor import extract, read_pcap


def capture(tmp_path):
    rnd = random.Random(1)
    path = tmp_path / "c.pcap"
    with path.open("wb") as f:
        w = dpkt.pcap.Writer(f)
        t = 0.0
        for i in range(400):
            t += rnd.uniform(0.001, 0.2)
            if rnd.random() < 0.7:
                fl = rnd.choice([dpkt.tcp.TH_ACK, dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH])
                fr = tcp(PHONE, CAM, 40000 + i % 7, 22, fl, payload=b"x" * rnd.randint(0, 300))
            else:
                fr = udp(CAM, PHONE, 5000, 53, payload=b"y" * rnd.randint(1, 200))
            w.writepkt(fr, ts=1000 + t)
    return read_pcap(str(path))


def test_own_output_matches_perfectly(tmp_path):
    packets = capture(tmp_path)
    csv = pd.DataFrame(extract(packets, 10))
    n_ours, n_theirs, n_match, scores = compare(packets, csv, 10)
    assert n_ours == n_theirs == 40 and n_match > 30
    assert all(s == 1.0 for s in scores.values())


def test_a_differently_computed_feature_is_caught(tmp_path):
    packets = capture(tmp_path)
    csv = pd.DataFrame(extract(packets, 10))
    csv["IAT"] = csv["IAT"] * 3                      # "their" IAT measured some other way
    _, _, _, scores = compare(packets, csv, 10)
    assert scores["IAT"] < 0.1 and scores["Tot sum"] == 1.0


REAL = Path(__file__).resolve().parents[1] / "pcap" / "CommandInjection.pcap"


@pytest.mark.dataset
@pytest.mark.skipif(not REAL.is_file(), reason="needs the dataset's CommandInjection.pcap")
def test_real_dataset_pcap_reproduces_the_dataset_csv():
    csv = pd.read_csv(REAL.with_suffix(".pcap.csv"))
    n_ours, n_theirs, n_match, scores = compare(read_pcap(str(REAL), split_mb=10), csv)
    assert n_ours == n_theirs == 5409 and n_match > 3800
    assert all(s == 1.0 for s in scores.values())
