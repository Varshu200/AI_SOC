import json, re
from collections import Counter
from pathlib import Path

ATTACK_PATH = Path("data/enterprise-attack.json")
_TECHNIQUES = {}

def load_attack():
    """Load all ATT&CK techniques into a dict keyed by ID (e.g. 'T1110.001')."""
    if _TECHNIQUES:
        return _TECHNIQUES
    data = json.load(open(ATTACK_PATH, encoding="utf-8"))
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = next((r["external_id"] for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        _TECHNIQUES[tid] = {
            "id": tid,
            "name": obj["name"],
            "tactics": tactics,
            "description": obj.get("description", ""),
        }
    return _TECHNIQUES

def is_valid_id(tid):
    return tid in load_attack()

def get_technique(tid):
    return load_attack().get(tid)

# ---- Rule-based mapper ----
TEXT_RULES = [
    (r"\buseradd\b|\badduser\b",        "T1136.001", "Local account created"),
    (r"\bcrontab\b|/var/spool/cron",    "T1053.003", "Cron job modified"),
    (r"/dev/tcp/|\bbash -i\b",          "T1059.004", "Unix shell used for remote command execution"),
    (r"xmrig|stratum\+tcp",             "T1496",     "Cryptocurrency mining activity"),
    (r"/etc/shadow",                    "T1003.008", "Password file read"),
    (r"\b(wget|curl)\b.*https?://", "T1105", "Tool/file downloaded from an external URL"),
    (r"chmod\s+\+x",                "T1222.002", "File made executable"),
    (r":(4444|1337|8888|9001)\b",   "T1571", "Connection on a non-standard port"),
]

def map_logs(logs):
    """logs: list of dict-like rows. Returns {technique_id: {count, why}}."""
    hits = {}
    def hit(tid, why, n=1):
        h = hits.setdefault(tid, {"count": 0, "why": why})
        h["count"] += n

    # Rule 1: many failed logins from one IP -> brute force; then success -> valid account
    failed = Counter(l["src_ip"] for l in logs if l["event_type"] == "login_failed")
    success_ips = {l["src_ip"] for l in logs if l["event_type"] == "login_success"}
    for ip, n in failed.items():
        if n >= 5:
            hit("T1110.001", f"{n} failed logins from {ip}", n)
            if ip in success_ips:
                hit("T1078", f"Successful login from {ip} after {n} failures")

    # Rule 2: text patterns in raw log lines
    for l in logs:
        for pattern, tid, why in TEXT_RULES:
            if re.search(pattern, l["raw"] or "", re.I):
                hit(tid, why)

    # Attach names/tactics and drop any ID that isn't a real ATT&CK technique
    result = {}
    for tid, info in hits.items():
        tech = get_technique(tid)
        if tech:
            result[tid] = {**info, "name": tech["name"], "tactics": tech["tactics"]}
    return result