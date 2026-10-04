import json, ipaddress
from app.db import get_conn
from app.correlator import get_alert, correlate
from app.enrichment import enrich
from app.mitre import map_logs
from app.llm import build_prompt, ask_llm, validate_techniques


def _ioc_type(v):
    try:
        ipaddress.ip_address(v)
        return "ipv4"
    except ValueError:
        return "domain"


def investigate(alert_id):
    conn = get_conn()
    alert = get_alert(conn, alert_id)
    if not alert:
        conn.close()
        raise ValueError(f"Alert {alert_id} not found")

    corr = correlate(conn, alert)                                    # Step 8
    enriched = [enrich(v, _ioc_type(v)) for v in corr["all_iocs"]]   # Step 7
    candidates = map_logs(corr["events"])                            # Step 6
    prompt = build_prompt(alert, enriched, corr["timeline"], candidates)
    report = ask_llm(prompt)                                         # Step 9
    techniques, rejected = validate_techniques(report)

    out = report.model_dump()
    out.update({"alert_id": alert_id, "mitre_techniques": techniques,
                "rejected_technique_ids": rejected, "iocs": enriched,
                "timeline": corr["timeline"]})

    conn.execute(
        "INSERT INTO investigations (alert_id,verdict,severity,confidence,report_json) VALUES (?,?,?,?,?)",
        (alert_id, out["verdict"], out["severity"], out["confidence"], json.dumps(out)))
    conn.execute("UPDATE alerts SET status='investigated' WHERE alert_id=?", (alert_id,))
    conn.commit()
    conn.close()
    return out