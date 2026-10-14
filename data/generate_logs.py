# generate_logs.py - creates a synthetic SOC alert dataset for the project
# Run from the project folder:  python data/generate_logs.py

import json
import random
from datetime import datetime, timedelta

random.seed(42)  # same "random" data every run = repeatable research

INTERNAL_IPS = ["10.0.0.5", "10.0.0.12", "10.0.1.20", "10.0.2.7", "10.0.3.15"]
EXTERNAL_IPS = ["45.33.12.8", "103.21.44.9", "185.220.101.4", "91.240.118.2", "198.51.100.23"]
USERS = ["alice", "bob", "carol", "dave", "admin", "svc_backup"]
NORMAL_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)", "curl/8.4.0"]
ATTACK_AGENTS = ["sqlmap/1.8", "Nmap Scripting Engine", "python-requests/2.31"]

BENIGN_EVENTS = [
    ("login_success", "User logged in successfully", "low"),
    ("file_access", "User opened a shared document", "low"),
    ("dns_query", "Normal DNS lookup to a known domain", "low"),
    ("software_update", "Scheduled software update completed", "low"),
    ("vpn_connect", "User connected to the company VPN", "low"),
]

ATTACK_EVENTS = [
    ("brute_force", "25 failed SSH logins in 2 minutes from one IP", "high"),
    ("port_scan", "Connection attempts to 200 ports in 30 seconds", "medium"),
    ("sql_injection", "Web request contained ' OR 1=1 -- in the login form", "high"),
    ("malware_beacon", "Host contacting a known malicious domain every 60 seconds", "critical"),
]

start = datetime(2026, 10, 1, 0, 0, 0)
logs = []


def make_log(i, label, event, carrier=False):
    event_type, description, severity = event
    if label == "malicious":
        src_ip = random.choice(EXTERNAL_IPS)
        agent = random.choice(ATTACK_AGENTS)
    else:
        src_ip = random.choice(INTERNAL_IPS)
        agent = random.choice(NORMAL_AGENTS)
    return {
        "id": f"LOG-{i:04d}",
        "timestamp": (start + timedelta(minutes=7 * i)).isoformat(),
        "src_ip": src_ip,
        "dst_ip": random.choice(INTERNAL_IPS),
        "user": random.choice(USERS),
        "user_agent": agent,
        "event_type": event_type,
        "description": description,
        "severity": severity,
        "label": label,        # ground truth: benign or malicious
        "carrier": carrier,    # True = attacks will hide payloads in this log later
    }


i = 1
for _ in range(140):  # 70% normal activity
    logs.append(make_log(i, "benign", random.choice(BENIGN_EVENTS))); i += 1
for _ in range(40):   # 20% real attacks
    logs.append(make_log(i, "malicious", random.choice(ATTACK_EVENTS))); i += 1
for _ in range(20):   # 10% real attacks kept clean for payload injection later
    logs.append(make_log(i, "malicious", random.choice(ATTACK_EVENTS), carrier=True)); i += 1

random.shuffle(logs)

with open("data/logs.json", "w") as f:
    json.dump(logs, f, indent=2)

benign = sum(1 for log in logs if log["label"] == "benign")
malicious = len(logs) - benign
carriers = sum(1 for log in logs if log["carrier"])
print(f"Created data/logs.json with {len(logs)} logs")
print(f"  benign: {benign}   malicious: {malicious}   carriers: {carriers}")
print("First log:")
print(json.dumps(logs[0], indent=2))
