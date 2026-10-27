"""
flow_engine.py - turns packets into the event dicts that detect() needs.

    packets (PCAP file or live capture)
        -> flows (one record per connection)
        -> sliding window per (source, device, direction)
        -> event dict: connection_attempts, unique_dst_ports, unique_dst_ips,
                       failed_attempts, direction, Rate, syn_count, ...

Why this exists: CICIoT2023 does not contain these context fields, so they
are MEASURED here on lab traffic.

Input options
  * FlowEngine.flows_from_pcap(path)     - scapy reads a PCAP (pure Python, no libpcap build)
  * FlowEngine.sniff_chunk(iface, secs)  - live capture in short chunks (needs root)
  * FlowEngine.flows_from_records(rows)  - adapter for flow records from NFStream / CICFlowMeter
    exports (the team has not chosen between them yet; the engine only needs the Flow fields)

Approximations (documented limitations):
  * failed_attempts is NOT read from the application protocol (SSH/Telnet/RTSP may be
    encrypted). A flow to an auth port counts as failed when the server never answered,
    or when it was short AND (reset OR only a few packets). Long sessions never count.
  * direction comes from the device IPs in devices.json: a flow towards a device is
    "inbound", a flow started by a device is "outbound".
  * Live chunks are assembled separately, so a connection that spans two chunks is
    counted as two flows.
  * syn_count is the number of connections started (one SYN each). The dataset's syn_count
    is something else (SYN packets inside a 10-packet window), so the detector thresholds on
    this field mean "many connections" here: that is why DoS also needs min_connection_attempts.
  * Events are grouped per (direction, device, source). When at least aggregate_min_sources
    different sources hit one device in the same window, one more inbound event sums them up with
    src_ip 0.0.0.0, so a flood spread over many addresses is still seen. Nothing is blocked
    for that address (see docs: the policy refuses to block 0.0.0.0).
  * A capture over max_packets packets or max_flows flows is refused, not read partly.
"""
import copy
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPV6", 132: "SCTP"}
AGGREGATE_SRC = "0.0.0.0"   # source of an event that sums up many sources (a distributed flood)
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10

DEFAULTS = {
    "window_seconds": 60.0,         # how far back one event looks
    "step_seconds": 10.0,           # how often a snapshot is taken
    "idle_timeout_seconds": 30.0,   # silence after which the same 5-tuple is a new flow
    "auth_ports": [22, 23, 554],    # SSH, Telnet, RTSP
    "short_flow_seconds": 2.0,      # shorter than this = "short" flow
    "short_flow_max_packets": 12,   # at most this many packets = "few" packets
    "aggregate_min_sources": 20,    # this many different sources hitting one device: also emit one event for all of them
    "max_packets": 5000000,         # a capture with more packets is refused (memory)
    "max_flows": 500000,            # a capture with more flows is refused (memory)
}


class FlowEngineError(Exception):
    """Unreadable capture, bad configuration or bad device list."""


class Flow:
    """One connection, oriented from the initiator (src) to the responder (dst)."""
    __slots__ = ("start", "end", "src_ip", "dst_ip", "src_port", "dst_port", "proto",
                 "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
                 "syn", "fin_fwd", "fin_rev", "rst")

    def __init__(self, start, src_ip, dst_ip, src_port, dst_port, proto):
        self.start = self.end = start
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.src_port, self.dst_port, self.proto = src_port, dst_port, proto
        self.pkts_fwd = self.pkts_rev = self.bytes_fwd = self.bytes_rev = 0
        self.syn = self.fin_fwd = self.fin_rev = self.rst = 0

    @property
    def packets(self):
        return self.pkts_fwd + self.pkts_rev

    @property
    def duration(self):
        return max(0.0, self.end - self.start)

    @property
    def closed(self):
        return self.rst > 0 or (self.fin_fwd > 0 and self.fin_rev > 0)


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


def _scapy():
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.utils import PcapReader
    except ImportError as exc:  # pragma: no cover
        raise FlowEngineError(
            "scapy is required for PCAP/live input: pip install scapy (%s)" % exc) from exc
    return IP, TCP, UDP, ICMP, PcapReader


class FlowEngine:
    def __init__(self, devices, config=None):
        """devices: list of profile dicts, each with device_id and ip (Person 1's devices.json)."""
        cfg = copy.deepcopy(DEFAULTS)
        for key, value in (config or {}).items():
            if key not in DEFAULTS:
                raise FlowEngineError("unknown flow_engine setting '%s' (known: %s)" % (key, ", ".join(DEFAULTS)))
            cfg[key] = value
        for key in ("window_seconds", "step_seconds", "idle_timeout_seconds", "short_flow_seconds"):
            if not isinstance(cfg[key], (int, float)) or isinstance(cfg[key], bool) or cfg[key] <= 0:
                raise FlowEngineError("flow_engine.%s must be a number > 0" % key)
        for key in ("aggregate_min_sources", "max_packets", "max_flows", "short_flow_max_packets"):
            if not isinstance(cfg[key], int) or isinstance(cfg[key], bool) or cfg[key] <= 0:
                raise FlowEngineError("flow_engine.%s must be a whole number > 0" % key)
        if cfg["step_seconds"] > cfg["window_seconds"]:
            raise FlowEngineError("flow_engine.step_seconds cannot be larger than window_seconds")
        self.cfg = cfg
        self.auth_ports = set(int(p) for p in cfg["auth_ports"])

        self.device_by_ip = {}
        for d in devices or []:
            if isinstance(d, dict) and d.get("device_id") and d.get("ip"):
                self.device_by_ip[str(d["ip"])] = str(d["device_id"])
        if not self.device_by_ip:
            raise FlowEngineError("no device with device_id and ip: direction cannot be decided")

        self._flows = []          # flows still inside the window
        self._last_tick = None
        self.ignored_flows = 0    # flows that touch none of our devices

    # ------------------------------------------------------------------ packets -> flows
    def _parse(self, pkt, IP, TCP, UDP, ICMP):
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        t = float(pkt.time)
        flags = 0
        if pkt.haslayer(TCP):
            l4 = pkt[TCP]
            proto, sport, dport, flags = "TCP", int(l4.sport), int(l4.dport), int(l4.flags)
        elif pkt.haslayer(UDP):
            l4 = pkt[UDP]
            proto, sport, dport = "UDP", int(l4.sport), int(l4.dport)
        elif pkt.haslayer(ICMP):
            proto, sport, dport = "ICMP", 0, 0
        else:
            proto, sport, dport = PROTO_NAMES.get(int(ip.proto), "IP%d" % int(ip.proto)), 0, 0
        return t, str(ip.src), str(ip.dst), sport, dport, proto, flags, len(pkt)

    def flows_from_packets(self, packets):
        IP, TCP, UDP, ICMP, _ = _scapy()
        active, done = {}, []
        seen_packets = 0
        for pkt in packets:
            seen_packets += 1
            if seen_packets > self.cfg["max_packets"]:
                raise FlowEngineError("the capture has more than %d packets (flow_engine.max_packets)" % self.cfg["max_packets"])
            if len(active) + len(done) > self.cfg["max_flows"]:
                raise FlowEngineError("the capture has more than %d flows (flow_engine.max_flows)" % self.cfg["max_flows"])
            parsed = self._parse(pkt, IP, TCP, UDP, ICMP)
            if parsed is None:
                continue
            t, src, dst, sport, dport, proto, flags, size = parsed
            a, b = (src, sport), (dst, dport)
            key = (proto,) + (min(a, b), max(a, b))
            flow = active.get(key)
            if flow is not None:
                new_conn = proto == "TCP" and (flags & SYN) and not (flags & ACK) and flow.closed
                if t - flow.end > self.cfg["idle_timeout_seconds"] or new_conn:
                    done.append(flow)
                    flow = None
            if flow is None:
                if proto == "TCP" and (flags & SYN) and (flags & ACK):
                    # capture started mid-handshake: the SYN-ACK sender is the server
                    flow = Flow(t, dst, src, dport, sport, proto)
                else:
                    flow = Flow(t, src, dst, sport, dport, proto)
                active[key] = flow
            forward = (src == flow.src_ip and sport == flow.src_port)
            flow.end = max(flow.end, t)
            if forward:
                flow.pkts_fwd += 1
                flow.bytes_fwd += size
                if flags & FIN:
                    flow.fin_fwd += 1
                if (flags & SYN) and not (flags & ACK):
                    flow.syn += 1
            else:
                flow.pkts_rev += 1
                flow.bytes_rev += size
                if flags & FIN:
                    flow.fin_rev += 1
            if flags & RST:
                flow.rst += 1
        done.extend(active.values())
        done.sort(key=lambda f: f.start)
        return done

    def flows_from_pcap(self, path):
        _, _, _, _, PcapReader = _scapy()
        if not os.path.isfile(path):
            raise FlowEngineError("capture file not found: %s" % path)
        try:
            # Open the file ourselves: on Windows, letting scapy reopen a path that a test is
            # about to remove/rename can fail with a sharing violation.
            with open(path, "rb") as fh, PcapReader(fh) as reader:
                return self.flows_from_packets(reader)
        except FlowEngineError:
            raise
        except Exception as exc:     # scapy raises many different errors on corrupt files
            raise FlowEngineError("cannot read %s as a PCAP: %s" % (path, exc)) from exc

    def sniff_chunk(self, iface, seconds):
        """Capture live traffic for `seconds` and return its flows (needs root). Not unit-tested."""
        try:
            from scapy.sendrecv import sniff
        except ImportError as exc:  # pragma: no cover
            raise FlowEngineError("scapy is required for live capture: %s" % exc) from exc
        packets = sniff(iface=iface, timeout=seconds, store=True)
        return self.flows_from_packets(packets)

    def flows_from_records(self, rows):
        """Adapter for exported flow records (NFStream / CICFlowMeter style dicts).
        Needs: start (epoch s), end, src_ip, dst_ip, src_port, dst_port, proto; optional
        pkts_fwd, pkts_rev, bytes_fwd, bytes_rev, syn, rst."""
        flows = []
        for r in rows:
            try:
                f = Flow(float(r["start"]), str(r["src_ip"]), str(r["dst_ip"]),
                         int(r.get("src_port", 0)), int(r.get("dst_port", 0)), str(r["proto"]).upper())
                f.end = float(r.get("end", f.start))
                f.pkts_fwd = int(r.get("pkts_fwd", 1))
                f.pkts_rev = int(r.get("pkts_rev", 0))
                f.bytes_fwd = int(r.get("bytes_fwd", 0))
                f.bytes_rev = int(r.get("bytes_rev", 0))
                f.syn = int(r.get("syn", 0))
                f.rst = int(r.get("rst", 0))
            except (KeyError, TypeError, ValueError):
                continue                      # a bad record never stops the engine
            flows.append(f)
        flows.sort(key=lambda f: f.start)
        return flows

    # ------------------------------------------------------------------ flow helpers
    def is_failed(self, f):
        """Approximation of a failed login (see module docstring)."""
        if f.proto != "TCP" or f.dst_port not in self.auth_ports:
            return False
        if f.pkts_rev == 0:                   # nobody answered (half-open / filtered)
            return True
        short = f.duration < self.cfg["short_flow_seconds"]
        return short and (f.rst > 0 or f.packets <= self.cfg["short_flow_max_packets"])

    def _classify(self, f):
        """Yield (direction, device_id) pairs this flow belongs to."""
        out = []
        if f.dst_ip in self.device_by_ip:
            out.append(("inbound", self.device_by_ip[f.dst_ip]))
        if f.src_ip in self.device_by_ip:
            out.append(("outbound", self.device_by_ip[f.src_ip]))
        return out

    # ------------------------------------------------------------------ sliding window
    def add_flows(self, flows):
        self._flows.extend(flows)

    def tick(self, now):
        """Snapshot of the window (now - window, now]. Returns events only for
        (direction, device, source) groups that had a NEW flow since the previous tick."""
        window, step = self.cfg["window_seconds"], self.cfg["step_seconds"]
        lo = now - window
        self._flows = [f for f in self._flows if f.start > lo]
        prev = self._last_tick if self._last_tick is not None else now - step
        self._last_tick = now

        in_window = [f for f in self._flows if f.start <= now]
        ips_by_src = defaultdict(set)         # every destination a source touched (any device or not)
        for f in in_window:
            ips_by_src[f.src_ip].add(f.dst_ip)

        groups = defaultdict(list)
        for f in in_window:
            members = self._classify(f)
            if not members:
                continue
            for direction, device_id in members:
                groups[(direction, device_id, f.src_ip)].append(f)

        events = []
        for (direction, device_id, src_ip), fl in sorted(groups.items()):
            if not any(f.start > prev for f in fl):
                continue                      # nothing new in this group: stay quiet
            events.append(self._event(direction, device_id, src_ip, fl, ips_by_src[src_ip], now))

        # A flood from many (often spoofed) sources looks harmless per source: every source makes a few
        # connections. One extra event per device sums them up, with a placeholder source address.
        by_device = defaultdict(list)
        for (direction, device_id, _src_ip), fl in groups.items():
            if direction == "inbound":
                by_device[device_id].extend(fl)
        for device_id, fl in sorted(by_device.items()):
            if len({f.src_ip for f in fl}) < self.cfg["aggregate_min_sources"] or not any(f.start > prev for f in fl):
                continue
            events.append(self._event("inbound", device_id, AGGREGATE_SRC, fl, {f.dst_ip for f in fl}, now))
        return events

    def _event(self, direction, device_id, src_ip, flows, src_dst_ips, now):
        ports = Counter(f.dst_port for f in flows)
        dst_port = sorted(ports.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        protos = Counter(f.proto for f in flows)
        protocol = sorted(protos.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        dst_ips = Counter(f.dst_ip for f in flows)
        dst_ip = sorted(dst_ips.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        first = min(f.start for f in flows)
        last = max(f.end for f in flows)
        span = max(1.0, last - first)         # never divide by less than one second
        packets = sum(f.packets for f in flows)
        return {
            "device_id": device_id,
            "timestamp": _iso(now),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "direction": direction,
            "connection_attempts": len(flows),
            "failed_attempts": sum(1 for f in flows if self.is_failed(f)),
            "unique_dst_ports": len({f.dst_port for f in flows if f.dst_port}),
            "unique_dst_ips": len(src_dst_ips),
            "duration": round(last - first, 3),
            "Rate": round(packets / span, 2),
            "syn_count": sum(f.syn for f in flows),
            "SSH": 1 if dst_port == 22 else 0,
            "Telnet": 1 if dst_port == 23 else 0,
            "event_ref": "%d:%s:%s:%s" % (int(now * 1000), direction, device_id, src_ip),
        }

    # ------------------------------------------------------------------ offline helper
    def build_events(self, flows):
        """Replay a whole capture: tick every step_seconds from the first flow to the last."""
        flows = sorted(flows, key=lambda f: f.start)
        if not flows:
            return []
        step = self.cfg["step_seconds"]
        t0, t_end = flows[0].start, flows[-1].start
        self._flows, self._last_tick = [], t0 - 1e-6
        self.add_flows(flows)
        events, k = [], 1
        while True:
            now = t0 + k * step
            events.extend(self.tick(now))
            if now >= t_end:
                break
            k += 1
        self.ignored_flows = sum(1 for f in flows if not self._classify(f))
        return events

    def events_from_pcap(self, path):
        return self.build_events(self.flows_from_pcap(path))
