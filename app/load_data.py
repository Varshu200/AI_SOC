import json
from app.db import get_conn, init_db

init_db()
conn = get_conn()
for l in json.load(open("data/sample_logs/logs.json")):
    conn.execute(
        "INSERT INTO logs (timestamp,host,user,src_ip,dst_ip,event_type,process,raw) VALUES (?,?,?,?,?,?,?,?)",
        (l["timestamp"], l["host"], l["user"], l["src_ip"], l["dst_ip"],
         l["event_type"], l["process"], l["raw"]))
a = json.load(open("data/sample_alerts/alert_001.json"))
conn.execute("INSERT OR REPLACE INTO alerts (alert_id,timestamp,rule_name,host,description,severity_hint) VALUES (?,?,?,?,?,?)",
             (a["alert_id"], a["timestamp"], a["rule_name"], a["host"], a["description"], a["severity_hint"]))
conn.commit()
print("Loaded.")