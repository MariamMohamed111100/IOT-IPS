"""
service.py - the IPS cyber service (detection side of the IoT-IPS).

    event source  ->  iot_ips.detector.detect(event, profile)  ->  alert envelope  ->  security/alerts/cyber

Run from the service folder (after `pip install -e ../../ips`):
    python main.py --source csv  --file ../../ips/data/sample_events.csv --devices ../../ips/config/devices.json --publisher stdout
    python main.py --source pcap --file capture.pcap --devices ../../ips/config/devices.json --publisher file --out alerts.jsonl
    python main.py --source live --iface eth0 --devices ../../ips/config/devices.json --publisher mqtt     (needs root + MQTT_* variables)

Rules the service follows:
  * there is ONE detector: iot_ips.detector (the one the pipeline, the tests and the calibration use);
    detect_fn is the slot the ML model fills later;
  * a BENIGN event publishes nothing;
  * a bad row / bad payload is counted and skipped - it never crashes the service;
  * a broken detector_rules.yaml is fatal at start-up (DetectorConfigError), because running with wrong rules
    is worse than not running;
  * alert ids are deterministic, so replaying the same input is safe.
"""
import argparse
import json
import logging
import os
import sys
import time

import yaml
from iot_ips import detector
from iot_ips.detector import DetectorConfigError

from . import envelope, sources
from . import publisher as pub
from .flow_engine import FlowEngineError

log = logging.getLogger("cyber")
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "config.yaml")


class ConfigError(ValueError):
    """config.yaml of the service is not valid."""

_CONFIG_KEYS = {"topic", "source", "default_zone", "severity", "flow_engine"}


def load_service_config(path=DEFAULT_CONFIG):
    """config.yaml, checked: unknown or missing keys raise ConfigError (same idea as rules.yaml)."""
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ConfigError("%s must be a mapping" % path)
    problems = ["unknown key '%s'" % k for k in sorted(set(cfg) - _CONFIG_KEYS)]
    problems += ["missing key '%s'" % k for k in sorted(_CONFIG_KEYS - set(cfg))]
    sev = cfg.get("severity")
    if not isinstance(sev, dict) or set(sev) != {"medium_from", "high_from"}:
        problems.append("severity must have exactly medium_from and high_from")
    elif not (0 <= sev["medium_from"] <= sev["high_from"] <= 1):
        problems.append("severity needs 0 <= medium_from <= high_from <= 1")
    if problems:
        raise ConfigError("%s is not valid:\n  - %s" % (path, "\n  - ".join(problems)))
    return cfg


def load_devices(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    items = data.get("devices", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError('devices file must be a list or {"devices": [...]}')
    return [d for d in items if isinstance(d, dict) and d.get("device_id")]


class IpsCyberService:
    def __init__(self, devices, publisher, config, detect_fn=None, rules_path=detector.DEFAULT_CONFIG):
        self.config = config
        self.publisher = publisher
        self.topic = config["topic"]
        # detect_fn is the slot the ML model fills later: it only has to look like detect(event, profile)
        self.detect = detect_fn or (lambda ev, prof: detector.detect(ev, prof, config_path=rules_path))
        self.profiles = {envelope.token(d["device_id"]): d for d in devices}
        self.profiles_by_ip = {str(d["ip"]): d for d in devices if d.get("ip")}
        self.stats = {"events_read": 0, "alerts_published": 0, "benign": 0,
                      "skipped_bad_input": 0, "publish_errors": 0}
        if detect_fn is None:
            detector.load_config(rules_path)       # fail fast: raises DetectorConfigError on a bad rules file

    def profile_for(self, event):
        prof = self.profiles.get(envelope.token(event.get("device_id")))
        if prof is None:
            ip = event.get("src_ip") if str(event.get("direction", "")).lower() == "outbound" else event.get("dst_ip")
            prof = self.profiles_by_ip.get(str(ip))
        return prof

    def handle_event(self, event_ref, event, source_name):
        """Process one event. Returns the published alert or None."""
        self.stats["events_read"] += 1
        if not isinstance(event, dict) or not event.get("device_id"):
            self.stats["skipped_bad_input"] += 1
            log.warning("skipped %s: no device_id", event_ref)
            return None
        profile = self.profile_for(event)
        detection = self.detect(event, profile)    # DetectorConfigError propagates on purpose
        if detection.get("label") != "ATTACK":
            self.stats["benign"] += 1
            return None
        try:
            alert = envelope.build_alert(event, detection, profile, source_name, event_ref, self.config)
        except (envelope.AlertError, TypeError, ValueError) as exc:
            self.stats["skipped_bad_input"] += 1
            log.warning("skipped %s: %s", event_ref, exc)
            return None
        try:
            self.publisher.publish(self.topic, alert)
        except pub.PublishError as exc:
            self.stats["publish_errors"] += 1
            log.error("not published %s: %s", event_ref, exc)
            return None
        self.stats["alerts_published"] += 1
        return alert

    def run(self, source, source_name):
        for event_ref, event in source:
            try:
                self.handle_event(event_ref, event, source_name)
            except (ConfigError, DetectorConfigError):
                raise
            except Exception as exc:               # one bad event must never stop the service
                self.stats["skipped_bad_input"] += 1
                log.exception("unexpected error on %s: %s", event_ref, exc)
        return self.stats


def build_arg_parser():
    p = argparse.ArgumentParser(description="IoT-IPS cyber service (detection side)")
    p.add_argument("--source", choices=["csv", "pcap", "live"], required=True)
    p.add_argument("--file", help="CSV or PCAP file (csv and pcap sources)")
    p.add_argument("--iface", help="network interface (live source)")
    p.add_argument("--devices", required=True, help="devices.json (ips/config/devices.json)")
    p.add_argument("--publisher", choices=["mqtt", "file", "stdout"], default="stdout")
    p.add_argument("--out", help="output file for --publisher file")
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.add_argument("--rules", default=detector.DEFAULT_CONFIG)
    p.add_argument("--detector", choices=["rules", "combined"], default="rules",
                   help="combined = rules plus the ML model of services/ml (needs `pip install -e services/ml`)")
    p.add_argument("--ml-min-confidence", type=float, default=0.90,
                   help="the model may raise an alert alone only at this confidence (combined mode)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--idle", action="store_true",
                   help="keep the process alive after the source is exhausted (Compose restart policy)")
    return p


def main(argv=None, publisher_override=None):
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    try:
        config = load_service_config(args.config)
        devices = load_devices(args.devices)
        if args.source in ("csv", "pcap") and not args.file:
            raise ValueError("--file is required for --source %s" % args.source)
        if args.source == "live" and not args.iface:
            raise ValueError("--iface is required for --source live")

        if publisher_override is not None:
            publisher = publisher_override
        elif args.publisher == "mqtt":
            publisher = pub.MqttPublisher()
        elif args.publisher == "file":
            if not args.out:
                raise ValueError("--out is required for --publisher file")
            publisher = pub.FilePublisher(args.out)
        else:
            publisher = pub.StdoutPublisher()

        detect_fn = None
        if args.detector == "combined":
            try:
                from ids_ml.combined import make_detect
            except ImportError as exc:
                raise ValueError("--detector combined needs the ML package: pip install -e services/ml (%s)" % exc) from None
            detector.load_config(args.rules)                           # a bad rules file still stops the start
            detect_fn = make_detect(args.ml_min_confidence,
                                    rules=lambda ev, prof=None: detector.detect(ev, prof, config_path=args.rules))
        service = IpsCyberService(devices, publisher, config, detect_fn=detect_fn, rules_path=args.rules)
        if args.source == "csv":
            src = sources.csv_source(args.file)
        elif args.source == "pcap":
            src = sources.pcap_source(args.file, devices, config["flow_engine"])
        else:
            src = sources.live_source(args.iface, devices, config["flow_engine"])
        stats = service.run(src, sources.source_name(args.file))
        print(json.dumps(stats), file=sys.stderr)
        if args.idle:
            log.info("source exhausted; idling so Compose does not replay")
            while True:
                time.sleep(3600)
    except (ConfigError, DetectorConfigError, FlowEngineError, pub.PublishError, ValueError, OSError) as exc:
        log.error("%s", exc)
        return 2
    finally:
        try:
            publisher.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
