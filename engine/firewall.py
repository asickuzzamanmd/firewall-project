import os
import sys
import signal
import time
import subprocess
import threading
import queue
import json
import socket as sock
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from collections import defaultdict
import requests
from scapy.all import sniff, IP, TCP, UDP, get_if_list

# ================= কনফিগারেশন =================
LOG_FILE = "firewall_logs.txt"
DASHBOARD_URL = "http://127.0.0.1:3000/api/event"
PYTHON_API_PORT = 5000

PACKET_LIMIT = 20
TIME_WINDOW = 1.0

SCAN_PORT_LIMIT = 4
SCAN_TIME_WINDOW = 3.0

CLEANUP_INTERVAL = 30.0

def get_machine_ip():
    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_machine_ip()
WHITELIST_IPS = {"127.0.0.1", "::1", LOCAL_IP}

# ================= ট্র্যাকিং =================
packet_counts = defaultdict(list)
scanned_ports = defaultdict(set)
port_scan_timers = defaultdict(float)
last_seen = defaultdict(float)

currently_blocked_ips = set()
last_cleanup_time = time.time()
event_queue = queue.Queue(maxsize=1000)

def dashboard_worker():
    session = requests.Session()
    while True:
        event_data = event_queue.get()
        if event_data is None:
            break
        try:
            session.post(DASHBOARD_URL, json=event_data, timeout=0.2)
        except Exception:
            pass
        finally:
            event_queue.task_done()

def dispatch_event(event_type, **kwargs):
    payload = {"type": event_type, "timestamp": datetime.now().strftime("%H:%M:%S"), **kwargs}
    try:
        event_queue.put_nowait(payload)
    except queue.Full:
        pass

def write_to_log(message):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{current_time}] {message}\n")
    except IOError:
        pass

def block_ip_windows(ip, reason):
    if ip in WHITELIST_IPS or ip in currently_blocked_ips:
        return

    try:
        rule_name = f"IDS_BLOCK_{ip.replace(':', '_')}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", 
             f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        currently_blocked_ips.add(ip)
        print(f"\n[!!! SECURITY BLOCK !!!] IP: {ip} | Reason: {reason}")
        write_to_log(f"BLOCKED: {ip} | Reason: {reason}")
        dispatch_event("BLOCK", ip=ip, reason=reason)
    except Exception as e:
        print(f"[-] Block failed for {ip}: {e}")

def unblock_single_ip(ip):
    if ip in currently_blocked_ips:
        try:
            rule_name = f"IDS_BLOCK_{ip.replace(':', '_')}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            currently_blocked_ips.remove(ip)
            packet_counts.pop(ip, None)
            scanned_ports.pop(ip, None)
            port_scan_timers.pop(ip, None)
            print(f"[+] Unblocked IP: {ip}")
            write_to_log(f"UNBLOCKED: {ip}")
            dispatch_event("UNBLOCK", ip=ip)
            return True
        except Exception:
            return False
    return False

def cleanup_memory(current_time):
    global last_cleanup_time
    if current_time - last_cleanup_time < CLEANUP_INTERVAL:
        return

    idle_threshold = 60.0
    stale_ips = [ip for ip, t in last_seen.items() if (current_time - t) > idle_threshold]

    for ip in stale_ips:
        packet_counts.pop(ip, None)
        scanned_ports.pop(ip, None)
        port_scan_timers.pop(ip, None)
        last_seen.pop(ip, None)

    last_cleanup_time = current_time

def unblock_all_ips():
    for ip in list(currently_blocked_ips):
        unblock_single_ip(ip)

class UnblockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/unblock':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            target_ip = data.get('ip')
            success = unblock_single_ip(target_ip)
            
            self.send_response(200 if success else 400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success" if success else "failed"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

def start_unblock_api():
    server = HTTPServer(('127.0.0.1', PYTHON_API_PORT), UnblockHandler)
    server.serve_forever()

def packet_filter(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    current_time = time.time()

    cleanup_memory(current_time)

    if src_ip in currently_blocked_ips or src_ip in WHITELIST_IPS:
        return

    last_seen[src_ip] = current_time

    # DDoS ডিটেকশন
    packet_counts[src_ip].append(current_time)
    packet_counts[src_ip] = [t for t in packet_counts[src_ip] if current_time - t <= TIME_WINDOW]

    if len(packet_counts[src_ip]) > PACKET_LIMIT:
        reason = f"DDoS/Flood: {len(packet_counts[src_ip])} pkts/{TIME_WINDOW}s"
        block_ip_windows(src_ip, reason)
        return

    # পোর্ট স্ক্যান ডিটেকশন
    target_port = None
    proto = "OTHER"
    if packet.haslayer(TCP):
        target_port = packet[TCP].dport
        proto = "TCP"
    elif packet.haslayer(UDP):
        target_port = packet[UDP].dport
        proto = "UDP"

    if target_port is not None:
        if current_time - port_scan_timers[src_ip] > SCAN_TIME_WINDOW:
            scanned_ports[src_ip].clear()
            port_scan_timers[src_ip] = current_time

        scanned_ports[src_ip].add(target_port)

        if len(scanned_ports[src_ip]) > SCAN_PORT_LIMIT:
            reason = f"Port Scan: {len(scanned_ports[src_ip])} unique ports/{SCAN_TIME_WINDOW}s"
            block_ip_windows(src_ip, reason)
            return

    dispatch_event("TRAFFIC", src=src_ip, dst=dst_ip, port=target_port, proto=proto)

def signal_handler(sig, frame):
    unblock_all_ips()
    event_queue.put(None)
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    threading.Thread(target=dashboard_worker, daemon=True).start()
    threading.Thread(target=start_unblock_api, daemon=True).start()

    print("=" * 60)
    print("   CyberGuard Windows IDS Engine Active")
    print(f"   Listening Target IP: {LOCAL_IP}")
    print("=" * 60)

    try:
        sniff(filter="ip", prn=packet_filter, store=0)
    except Exception as e:
        print(f"[-] Engine failed: {e}")
        unblock_all_ips()