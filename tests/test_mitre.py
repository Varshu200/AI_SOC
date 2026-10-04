from app.db import get_conn
from app.mitre import load_attack, map_logs

print("Techniques loaded:", len(load_attack()))

conn = get_conn()
logs = [dict(r) for r in conn.execute("SELECT * FROM logs")]
for tid, info in map_logs(logs).items():
    print(tid, "|", info["name"], "|", info["tactics"], "|", info["count"], "|", info["why"])