#!/usr/bin/env python3
"""
ARP IDS – Lightweight ARP Spoofing/Poisoning Detector
- Live sniffing on an interface OR offline analysis of a .pcap
- Detects IP->MAC changes, gateway MAC mismatch, and ARP reply storms
- Logs alerts to CSV and prints to console

Usage:
  Live:   sudo python arp_ids.py --iface eth0 --gateway 192.168.1.1 --gateway-mac aa:bb:cc:dd:ee:ff
  PCAP:   python arp_ids.py --pcap test_arp_spoof.pcap
"""

import argparse
import csv
import os
import time
from collections import defaultdict, deque

try:
    from scapy.all import sniff, ARP, conf, rdpcap
except Exception as e:
    raise SystemExit(
        f"[!] Failed to import Scapy. Install it first:\n"
        f"    pip install scapy\n\nError: {e}"
    )

# -------------------- Defaults --------------------
DEFAULT_LOG = "arp_ids_events.csv"
DEFAULT_STORM_WINDOW = 5        # seconds
DEFAULT_STORM_THRESHOLD = 30    # >30 ARP replies in window -> alert

# -------------------- Helpers --------------------
def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def write_csv(path, record):
    file_exists = os.path.exists(path)
    header = list(record.keys())
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        if not file_exists:
            w.writeheader()
        w.writerow(record)

def console_alert(reason, pkt, extra=None):
    ts = now_str()
    src_ip  = pkt[ARP].psrc
    src_mac = pkt[ARP].hwsrc
    dst_ip  = pkt[ARP].pdst
    dst_mac = pkt[ARP].hwdst
    print(f"[ALERT] {ts} | {reason} | {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac}) | {extra or ''}")

def log_event(log_path, reason, pkt, extra=None):
    ts = now_str()
    rec = {
        "time": ts,
        "reason": reason,
        "src_ip":  pkt[ARP].psrc,
        "src_mac": pkt[ARP].hwsrc,
        "dst_ip":  pkt[ARP].pdst,
        "dst_mac": pkt[ARP].hwdst,
    }
    if extra:
        # flatten extras for readability
        for k, v in extra.items():
            rec[str(k)] = v
    console_alert(reason, pkt, extra)
    write_csv(log_path, rec)

# -------------------- Detector --------------------
class ArpIDS:
    def _init_(self, log_path=DEFAULT_LOG, gateway_ip=None, gateway_mac=None,
                 storm_window=DEFAULT_STORM_WINDOW, storm_threshold=DEFAULT_STORM_THRESHOLD):
        self.log_path = log_path
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.lower() if gateway_mac else None
        self.storm_window = storm_window
        self.storm_threshold = storm_threshold

        self.ip_to_mac = {}  # observed IP -> MAC
        self.reply_buckets = defaultdict(lambda: deque())  # talker key -> timestamps

    def _check_binding(self, pkt):
        src_ip  = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        old = self.ip_to_mac.get(src_ip)
        if old and old.lower() != src_mac.lower():
            self._alert("IP-to-MAC change (possible spoofing)", pkt,
                        {"old_mac": old, "new_mac": src_mac})
        self.ip_to_mac[src_ip] = src_mac

    def _check_gateway(self, pkt):
        if not self.gateway_ip:
            return
        if pkt[ARP].psrc != self.gateway_ip:
            return
        observed = pkt[ARP].hwsrc.lower()
        if self.gateway_mac and observed != self.gateway_mac:
            self._alert("Gateway MAC mismatch", pkt,
                        {"expected": self.gateway_mac, "observed": observed})

    def _check_storm(self, pkt):
        key = (pkt[ARP].hwsrc or "") + "|" + (pkt[ARP].psrc or "")
        q = self.reply_buckets[key]
        t = time.time()
        q.append(t)
        # drop timestamps outside window
        while q and t - q[0] > self.storm_window:
            q.popleft()
        if len(q) > self.storm_threshold:
            self._alert("ARP reply storm", pkt, {"count_in_window": len(q)})

    def _alert(self, reason, pkt, extra=None):
        log_event(self.log_path, reason, pkt, extra)

    def handle(self, pkt):
        if ARP not in pkt:
            return
        if pkt[ARP].op != 2:  # focus on ARP replies (op=2)
            return
        self._check_binding(pkt)
        self._check_gateway(pkt)
        self._check_storm(pkt)

# -------------------- Runners --------------------
def run_live(args):
    iface = args.iface or conf.iface
    print(f"[+] Starting ARP IDS on interface: {iface}")
    if args.gateway:
        print(f"[+] Gateway pin enabled for {args.gateway} "
              f"(expected MAC: {args.gateway_mac or 'discovering'})")

    ids = ArpIDS(
        log_path=args.log,
        gateway_ip=args.gateway,
        gateway_mac=args.gateway_mac,
        storm_window=args.storm_window,
        storm_threshold=args.storm_threshold
    )
    sniff(prn=ids.handle, filter="arp", store=False, iface=iface)

def run_pcap(args):
    print(f"[+] Reading PCAP: {args.pcap}")
    packets = rdpcap(args.pcap)
    ids = ArpIDS(
        log_path=args.log,
        gateway_ip=args.gateway,
        gateway_mac=args.gateway_mac,
        storm_window=args.storm_window,
        storm_threshold=args.storm_threshold
    )
    count = 0
    for p in packets:
        try:
            ids.handle(p)
            count += 1
        except Exception:
            # skip malformed frames gracefully
            pass
    print(f"[+] Processed {count} packets from PCAP.")

# -------------------- CLI --------------------
def parse_args():
    ap = argparse.ArgumentParser(description="Lightweight ARP Spoofing Detector (Python + Scapy)")
    src = ap.add_mutually_exclusive_group(required=False)
    src.add_argument("--iface", help="Network interface for live sniffing (default: scapy's conf.iface)")
    src.add_argument("--pcap", help="Offline analysis from a .pcap file")

    ap.add_argument("--gateway", help="Gateway IP to pin (e.g., 192.168.1.1)")
    ap.add_argument("--gateway-mac", help="Expected gateway MAC to pin (aa:bb:cc:dd:ee:ff)")
    ap.add_argument("--log", default=DEFAULT_LOG, help=f"CSV log path (default: {DEFAULT_LOG})")
    ap.add_argument("--storm-window", type=int, default=DEFAULT_STORM_WINDOW,
                    help=f"Seconds for ARP storm window (default: {DEFAULT_STORM_WINDOW})")
    ap.add_argument("--storm-threshold", type=int, default=DEFAULT_STORM_THRESHOLD,
                    help=f"Max replies in window before alert (default: {DEFAULT_STORM_THRESHOLD})")
    return ap.parse_args()

def main():
    args = parse_args()
    if args.pcap:
        run_pcap(args)
    else:
        run_live(args)

if _name_ == "_main_":
    main()
