"""Entry point: python main.py --source csv|pcap|live ... (see README.md)."""
import sys

from ips_cyber.service import main

if __name__ == "__main__":
    sys.exit(main())
