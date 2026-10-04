from app.db import get_conn
from app.correlator import get_alert, correlate
from app.mitre import map_logs

conn = get_conn()
alert = get_alert(conn, "ALERT-001")
result = correlate(conn, alert)

print("Seed IOCs:", result["seed_iocs"])
print("All IOCs :", result["all_iocs"])
print("Events   :", result["event_count"])
print("\nTimeline:")
for t in result["timeline"]:
    print(f"  {t['start']} -> {t['end']}  x{t['count']:<3} {t['event_type']:<18} user={t['user']:<6} {t['src_ip']} -> {t['dst_ip']}")
    print(f"      e.g. {t['sample']}")

print("\nMITRE techniques from correlated events only:")
for tid, info in map_logs(result["events"]).items():
    print(" ", tid, "|", info["name"], "|", info["why"])