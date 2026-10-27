"""engine service: risk scoring, correlation, incidents and automated response."""
import logging

from eng.service import run

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    run("engine")
