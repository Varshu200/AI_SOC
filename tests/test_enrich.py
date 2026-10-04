from app.db import get_conn
from app.ioc_extractor import extract_iocs
from app.enrichment import enrich

conn = get_conn()
iocs = set()
for row in conn.execute("SELECT raw FROM logs"):
    for ioc_type, values in extract_iocs(row["raw"] or "").items():
        if ioc_type in ("ipv4", "domain"):
            iocs.update((v, ioc_type) for v in values)

for value, ioc_type in sorted(iocs):
    r = enrich(value, ioc_type)
    print(f"{value:28} {ioc_type:7} score={r['reputation_score']:3} {r['verdict']:10} cached={r['cached']}")
    print("   ", r["details"])