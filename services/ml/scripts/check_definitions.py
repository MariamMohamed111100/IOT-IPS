"""Prove feature definitions from the CSV data itself (step 1 evidence).

    python check_definitions.py      # needs the raw CICIoT2023 CSVs in ips/data/raw/ (about 600 MB,
                                     # not in the repository - see ips/data/README.md)

Each line: the share of all CSV rows where the relation holds. 100% = the definition is certain.
"""
import sys
from pathlib import Path

import numpy as np

# The raw-data loader already exists in the IPS package (ips/scripts/data/prepare_data.py,
# which reads ips/data/raw/); reuse it instead of a private copy.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "ips" / "scripts" / "data"))
import prepare_data  # noqa: E402


def main() -> None:
    if not (prepare_data.DATA / "Merged01_partial.csv").is_file():
        sys.exit(f"ERROR: the raw CICIoT2023 CSVs are not in {prepare_data.DATA} (about 600 MB, "
                 "not in the repository - see ips/data/README.md)")
    df, _, _ = prepare_data.load()
    close = lambda a, b, tol=0.02: np.isclose(a, b, rtol=tol, atol=1e-6)
    tcp, udp, icmp = df["TCP"], df["UDP"], df["ICMP"]
    majority = np.select([tcp >= np.maximum(udp, icmp), udp >= icmp], [6, 17], 1)
    checks = [
        ("Number is the window size (10 or 100, fewer at a file end)",
         df["Number"].isin(range(1, 101))),
        ("AVG = Tot sum / Number", close(df["AVG"], df["Tot sum"] / df["Number"])),
        ("Tot size = AVG", close(df["Tot size"], df["AVG"])),
        ("Variance = Std^2", close(df["Variance"], df["Std"] ** 2)),
        ("Min <= AVG <= Max", (df["Min"] <= df["AVG"] + 1e-9) & (df["AVG"] <= df["Max"] + 1e-9)),
        *[(f"{k}_count = {k}_flag_number x Number",
           close(df[f"{k}_count"], df[f"{k}_flag_number"] * df["Number"], 0.05))
          for k in ("ack", "syn", "fin", "rst")],
        ("IPv = LLC", close(df["IPv"], df["LLC"])),
        ("IPv + ARP = 1", close(df["IPv"] + df["ARP"], 1, 0.001)),
        ("Protocol Type = protocol of the majority of packets", df["Protocol Type"] == majority),
        ("Header_Length = 8 when all packets are UDP (UDP header)",
         close(df.loc[udp >= 0.99, "Header_Length"], 8, 0.08)),
        ("Rate = 1 / IAT  (it is not: Rate = Number / window duration, see compare_pcap.py)",
         close(df["Rate"], 1 / df["IAT"].replace(0, np.nan))),
    ]
    print(f"{len(df):,} rows")
    for name, mask in checks:
        print(f"{np.mean(mask):8.2%}  {name}")

    # Std: sample (n-1) or population (n)? Windows whose packets have only two sizes (Min and
    # Max) let us count the packets of each size from Tot sum and recompute Std exactly.
    d = df[(df["Max"] > df["Min"]) & (df["Number"] >= 3)]
    n = d["Number"]
    k = (d["Tot sum"] - n * d["Min"]) / (d["Max"] - d["Min"])
    two = d[np.isclose(k, k.round(), atol=1e-9) & (k >= 1) & (k <= n - 1)]
    p = ((two["Tot sum"] - two["Number"] * two["Min"]) / (two["Max"] - two["Min"])).round() \
        / two["Number"]
    pop = (two["Max"] - two["Min"]) * np.sqrt(p * (1 - p))
    sample = pop * np.sqrt(two["Number"] / (two["Number"] - 1))
    print(f"\nStd test on {len(two):,} two-size windows: sample std (n-1) matches "
          f"{np.isclose(two['Std'], sample, rtol=1e-3).mean():.2%}, population std (n) "
          f"{np.isclose(two['Std'], pop, rtol=1e-3).mean():.2%}")


if __name__ == "__main__":
    main()
