#!/usr/bin/env python3
from scapy.all import *
import colorama
from colorama import Fore, Style
import subprocess
import os
import json
from datetime import datetime

# Initialize colors
colorama.init()

# Domains to monitor
MONITORED_DOMAINS = ["google.com", "instagram.com", "youtube.com", "snapchat.com"]
ALERT_LOG = "logs/alerts.log"
JSON_LOG = "logs/latest_attack.json"

# Store trusted IPs
trusted_ips = {}

def get_trusted_ip(domain):
    """Query Google DNS to get real IP"""
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "@8.8.8.8"],
            capture_output=True, text=True, timeout=5
        )
        ips = result.stdout.strip().split("\n")
        return [ip for ip in ips if ip]
    except Exception as e:
        print(Fore.LIGHTBLACK_EX + f"[?] Can't verify {domain}: {e}" + Style.RESET_ALL)
        return []

def log_attack(qname, spoofed_ip, expected_ips, ttl, txid):
    """Save attack data in JSON (for web page) and text log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Save structured JSON for web display
    attack_data = {
        "domain": qname,
        "spoofed_ip": spoofed_ip,
        "expected_ips": expected_ips,
        "ttl": ttl,
        "txid": txid,
        "timestamp": timestamp
    }
    with open(JSON_LOG, "w") as f:
        json.dump(attack_data, f)

    # Save to text log
    with open(ALERT_LOG, "a") as f:
        f.write(f"[{timestamp}] {qname} → {spoofed_ip} | Expected: {expected_ips}\n")

def analyze_packet(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 1:  # DNS Response
        try:
            qname = pkt[DNSQR].qname.decode('utf-8').lower()

            # Only monitor target domains
            if not any(qname.endswith(d) or d in qname for d in MONITORED_DOMAINS):
                return

            txid = pkt[IP].id
            ttl = pkt[DNSRR].ttl
            rdata = pkt[DNSRR].rdata
            if isinstance(rdata, bytes):
                resolved_ip = ".".join(map(str, rdata))
            else:
                resolved_ip = str(rdata)

            # Get expected IP from real DNS
            if qname not in trusted_ips:
                trusted_ips[qname] = get_trusted_ip(qname)
            expected_ips = trusted_ips[qname]

            # Detection logic
            suspicious = False
            reasons = []

            if expected_ips and resolved_ip not in expected_ips:
                reasons.append("IP mismatch")
                suspicious = True
            if ttl < 10:
                reasons.append("Low TTL")
                suspicious = True
            if txid < 256:
                reasons.append("Weak TXID")
                suspicious = True

            print(f"\n{'─' * 60}")
            if suspicious:
                print(Fore.RED + "⚠️  [!] SUSPICIOUS DNS RESPONSE DETECTED!" + Style.RESET_ALL)
                print(f"    Domain: {qname}")
                print(f"    Spoofed IP: {resolved_ip} ❌")
                print(f"    Expected IP(s): {expected_ips or ['Unknown']}")
                print(f"    TTL: {ttl}s ⚠️  | TXID: {txid}")
                print(Fore.YELLOW + f"    Reason(s): {', '.join(reasons)}" + Style.RESET_ALL)

                # Save full details for web page
                log_attack(qname, resolved_ip, expected_ips, ttl, txid)
                print(Fore.CYAN + f"    📝 Saved for web display" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "[+] Normal DNS Response:" + Style.RESET_ALL)
                print(f"    Domain: {qname}")
                print(f"    Resolved IP: {resolved_ip} ✅")
                print(f"    TTL: {ttl}s | TXID: {txid}")

        except Exception as e:
            print(Fore.LIGHTBLACK_EX + f"[⚠] Error: {e}" + Style.RESET_ALL)

# Banner
print(Fore.CYAN + "┌───────────────────────────────────────────────────────┐" + Style.RESET_ALL)
print(Fore.CYAN + "│     🔍 DNS SPOOFING DETECTOR (Google, IG, YT, SC)     │" + Style.RESET_ALL)
print(Fore.CYAN + "└───────────────────────────────────────────────────────┘" + Style.RESET_ALL)
print(Fore.YELLOW + f"[+] Monitoring: {', '.join(MONITORED_DOMAINS)}" + Style.RESET_ALL)

# Create logs dir
if not os.path.exists("logs"):
    os.makedirs("logs")

# Start sniffing
try:
    sniff(filter="udp port 53", prn=analyze_packet, store=0)
except KeyboardInterrupt:
    print(f"\n{Fore.RED}[🛑] Detector stopped.{Style.RESET_ALL}")