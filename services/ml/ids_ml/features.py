"""Which features the model may use: only those our extractor computes like the dataset does.

CONFIRMED = our extractor reproduces the dataset's value. Evidence:
  - the dataset authors' own converter (Supplementary Materials/pcap2csv), which extractor.py
    follows rule by rule
  - compare_pcap.py on the dataset's CommandInjection.pcap: all 39 features agree on 100% of
    the 3,887 rows that pair one-to-one, and 5,406 of all 5,409 rows are identical (the other 3
    differ only by rounding in the 5th digit of Variance)  -> extractor_check.csv
  - check_definitions.py on all 735,352 CSV rows (AVG = Tot sum / Number, Variance = Std^2, ...)
PENDING   = none left.

WINDOW_SIZE = features that only tell how many packets the window holds. The dataset used
windows of 100 packets for every flood (DDoS, DoS, Mirai) and 10 for everything else, so in the
data Number = 100 means "flood": a shortcut that cannot work live, where windows are always 10.
Without them the model is as good (F1 0.8825 vs 0.8821) and catches floods in 10-packet
windows too (99.9%).
"""
from .extractor import FEATURES

CONFIRMED = list(FEATURES)
PENDING: list[str] = []
WINDOW_SIZE = ["Number", "Tot sum", "ack_count", "syn_count", "fin_count", "rst_count"]

# Person 2's 18 selected features (Person 2's features.txt); the model uses the CONFIRMED ones
# that do not depend on the window size
SELECTED_18 = ["Max", "Variance", "AVG", "HTTPS", "Tot sum", "Number", "Time_To_Live", "IAT",
               "ack_flag_number", "Header_Length", "Min", "psh_flag_number", "TCP", "UDP", "DNS",
               "syn_flag_number", "HTTP", "SSH"]
MODEL_FEATURES = [f for f in SELECTED_18 if f in CONFIRMED and f not in WINDOW_SIZE]
