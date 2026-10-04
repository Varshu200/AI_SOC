import time,os, json, requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from app.db import get_conn

load_dotenv()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
CACHE_HOURS = 24
TIMEOUT = 15
VT_PATHS = {"ipv4": "ip_addresses", "domain": "domains", "md5": "files", "sha256": "files"}


def _abuseipdb(ip):
    if not ABUSE_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {"score": d.get("abuseConfidenceScore", 0),
                "reports": d.get("totalReports", 0),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "is_tor": d.get("isTor")}
    except Exception as e:
        return {"error": f"abuseipdb: {e}"}


def _virustotal(value, ioc_type):
    if not VT_KEY or ioc_type not in VT_PATHS:
        return None
    url = f"https://www.virustotal.com/api/v3/{VT_PATHS[ioc_type]}/{value}"
    time.sleep(16)
    try:
        r = requests.get(url, headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "note": "not found in VirusTotal"}
        r.raise_for_status()
        s = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": s.get("malicious", 0),
                "suspicious": s.get("suspicious", 0),
                "harmless": s.get("harmless", 0)}
    except Exception as e:
        return {"error": f"virustotal: {e}"}


def _cached(conn, value):
    row = conn.execute("SELECT * FROM iocs WHERE value=?", (value,)).fetchone()
    if not row:
        return None
    age = datetime.now(timezone.utc) - datetime.fromisoformat(row["last_checked"])
    if age < timedelta(hours=CACHE_HOURS):
        return {"value": row["value"], "type": row["type"],
                "reputation_score": row["reputation_score"],
                "verdict": _verdict(row["reputation_score"], True),
                "details": json.loads(row["tags"]),
                "source": row["source"], "cached": True}
    return None


def _verdict(score, has_data):
    if not has_data:
        return "unknown"
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


def enrich(value, ioc_type):
    conn = get_conn()
    cached = _cached(conn, value)
    if cached:
        conn.close()
        return cached

    abuse = _abuseipdb(value) if ioc_type == "ipv4" else None
    vt = _virustotal(value, ioc_type)

    details, sources, score = {}, [], 0
    if abuse and "error" not in abuse:
        details["abuseipdb"] = abuse
        sources.append("abuseipdb")
        score = max(score, abuse["score"])
    if vt and "error" not in vt:
        details["virustotal"] = vt
        sources.append("virustotal")
        score = max(score, min(100, vt["malicious"] * 10))   # simple heuristic
    errors = [x["error"] for x in (abuse, vt) if x and "error" in x]
    if errors:
        details["errors"] = errors

    result = {"value": value, "type": ioc_type, "reputation_score": score,
              "verdict": _verdict(score, bool(sources)),
              "details": details, "source": ",".join(sources), "cached": False}

    if sources:   # only cache successful lookups
        conn.execute(
            "INSERT OR REPLACE INTO iocs (value,type,reputation_score,tags,source,last_checked) VALUES (?,?,?,?,?,?)",
            (value, ioc_type, score, json.dumps(details), result["source"],
             datetime.now(timezone.utc).isoformat()))
        conn.commit()
    conn.close()
    return result