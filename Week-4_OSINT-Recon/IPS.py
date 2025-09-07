from scapy.all import sniff, IP, TCP, ICMP, Raw

# Simple state tracking
icmp_count = {}
syn_count = {}

def block(ip):
    print(f"[BLOCK] Traffic from {ip} blocked (simulated)")

def detect(packet):
    if IP in packet:
        src = packet[IP].src

        # --- ICMP Flood Detection ---
        if ICMP in packet:
            icmp_count[src] = icmp_count.get(src, 0) + 1
            if icmp_count[src] > 5:  # threshold
                block(src)

        # --- TCP SYN Flood Detection ---
        if TCP in packet and packet[TCP].flags == "S":  # SYN flag
            syn_count[src] = syn_count.get(src, 0) + 1
            if syn_count[src] > 5:  # threshold
                block(src)

        # --- Simple Payload Filtering ---
        if Raw in packet:
            payload = packet[Raw].load.decode(errors="ignore").lower()
            if "union select" in payload or "drop table" in payload or "' or 1=1" in payload:
                print(f"[ALERT] Suspicious payload from {src}")
                block(src)

print("[*] Starting lightweight IPS (press Ctrl+C to stop)...")
sniff(prn=detect, store
