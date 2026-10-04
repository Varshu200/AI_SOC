import json, sqlite3
from collections import Counter
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from app.db import get_conn, init_db
from app.investigator import investigate

app = FastAPI(title="AI SOC Investigation Assistant", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
init_db()


class AlertIn(BaseModel):
    alert_id: str
    timestamp: str                       # format: YYYY-MM-DD HH:MM:SS
    rule_name: str
    host: str
    description: str
    severity_hint: Optional[str] = "medium"

    @field_validator("timestamp")
    @classmethod
    def check_timestamp(cls, v):
        datetime.strptime(v, "%Y-%m-%d %H:%M:%S")    # raises ValueError -> HTTP 422
        return v


def _query(sql, params=()):
    conn = get_conn()
    try:
        return [dict(r) for r in conn.execute(sql, params)]
    finally:
        conn.close()


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"service": "AI SOC Investigation Assistant", "docs": "/docs", "dashboard": "http://localhost:8501"}

@app.post("/alerts", status_code=201)
def create_alert(a: AlertIn):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO alerts (alert_id,timestamp,rule_name,host,description,severity_hint) VALUES (?,?,?,?,?,?)",
            (a.alert_id, a.timestamp, a.rule_name, a.host, a.description, a.severity_hint))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"Alert {a.alert_id} already exists")
    finally:
        conn.close()
    return {"alert_id": a.alert_id, "status": "new"}


@app.get("/alerts")
def list_alerts():
    return _query("SELECT * FROM alerts ORDER BY timestamp DESC")


@app.post("/investigate/{alert_id}")
def run_investigation(alert_id: str):
    try:
        return investigate(alert_id)
    except ValueError as e:                      # unknown alert id
        raise HTTPException(404, str(e))
    except RuntimeError as e:                    # LLM unavailable / invalid output
        raise HTTPException(502, str(e))


@app.get("/investigations")
def list_investigations():
    return _query("""SELECT id, alert_id, verdict, severity, confidence, created_at
                     FROM investigations ORDER BY id DESC""")


@app.get("/investigations/{inv_id}")
def get_investigation(inv_id: int):
    rows = _query("SELECT report_json FROM investigations WHERE id=?", (inv_id,))
    if not rows:
        raise HTTPException(404, "Investigation not found")
    return json.loads(rows[0]["report_json"])


@app.get("/alerts/{alert_id}/investigation")
def latest_investigation(alert_id: str):
    rows = _query("SELECT report_json FROM investigations WHERE alert_id=? ORDER BY id DESC LIMIT 1",
                  (alert_id,))
    if not rows:
        raise HTTPException(404, "No investigation yet for this alert")
    return json.loads(rows[0]["report_json"])


@app.get("/iocs")
def list_iocs():
    rows = _query("SELECT * FROM iocs ORDER BY reputation_score DESC")
    for r in rows:
        r["tags"] = json.loads(r["tags"] or "{}")
    return rows


@app.get("/stats")
def stats():
    inv = _query("SELECT severity, verdict, report_json FROM investigations")
    techniques = Counter()
    for r in inv:
        for t in json.loads(r["report_json"]).get("mitre_techniques", []):
            techniques[f"{t['id']} {t['name']}"] += 1
    return {
        "alerts_total": _query("SELECT COUNT(*) AS n FROM alerts")[0]["n"],
        "alerts_by_status": {r["status"]: r["n"] for r in
                             _query("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")},
        "investigations_total": len(inv),
        "by_severity": dict(Counter(r["severity"] for r in inv)),
        "by_verdict": dict(Counter(r["verdict"] for r in inv)),
        "top_techniques": techniques.most_common(10),
        "malicious_iocs": _query("""SELECT value, type, reputation_score FROM iocs
                                    WHERE reputation_score >= 75 ORDER BY reputation_score DESC"""),
    }