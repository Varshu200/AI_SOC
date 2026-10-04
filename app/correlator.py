from datetime import datetime, timedelta
from app.ioc_extractor import extract_iocs

FMT = "%Y-%m-%d %H:%M:%S"


def _rows(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params)]


def get_alert(conn, alert_id):
    row = conn.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    return dict(row) if row else None


def _window(ts, minutes):
    t = datetime.strptime(ts, FMT)
    return ((t - timedelta(minutes=minutes)).strftime(FMT),
            (t + timedelta(minutes=minutes)).strftime(FMT))


def logs_for_ioc(conn, ioc, start, end):
    return _rows(conn, """
        SELECT * FROM logs
        WHERE timestamp BETWEEN ? AND ?
          AND (src_ip=? OR dst_ip=? OR raw LIKE ?)
        ORDER BY timestamp""", (start, end, ioc, ioc, f"%{ioc}%"))


def _iocs_in(text):
    found = extract_iocs(text)
    return set(found.get("ipv4", []) + found.get("domain", []))


def build_timeline(events):
    """Collapse consecutive identical events (e.g. 47 failed logins) into one line."""
    timeline = []
    last_key = None
    for e in events:
        key = (e["event_type"], e["host"], e["user"], e["src_ip"], e["dst_ip"],e["process"])
        if key == last_key:
            timeline[-1]["count"] += 1
            timeline[-1]["end"] = e["timestamp"]
        else:
            timeline.append({
                "start": e["timestamp"], "end": e["timestamp"], "count": 1,
                "event_type": e["event_type"], "host": e["host"], "user": e["user"],
                "src_ip": e["src_ip"], "dst_ip": e["dst_ip"], "sample": e["raw"],
            })
            last_key = key
    return timeline


def correlate(conn, alert, window_min=30, max_rounds=3):
    start, end = _window(alert["timestamp"], window_min)
    pending = _iocs_in(alert["description"] or "")
    seed_iocs = set(pending)
    seen = set()
    events = {}          # log id -> row
    pivoted_logins = set()

    for _ in range(max_rounds):
        if not pending:
            break
        # Pivot 1: logs that mention the IOC
        for ioc in pending:
            for row in logs_for_ioc(conn, ioc, start, end):
                events[row["id"]] = row
        seen |= pending

        # Pivot 2: what did the account do after a successful login?
        for row in list(events.values()):
            if row["event_type"] == "login_success" and row["id"] not in pivoted_logins:
                pivoted_logins.add(row["id"])
                for r in _rows(conn, """
                    SELECT * FROM logs
                    WHERE host=? AND user=? AND timestamp>=? AND timestamp<=?
                    ORDER BY timestamp""", (row["host"], row["user"], row["timestamp"], end)):
                    events[r["id"]] = r

        # Discover new IOCs in everything collected so far
        new = set()
        for row in events.values():
            new |= _iocs_in(f"{row['raw']} {row['src_ip']} {row['dst_ip']}")
        pending = new - seen

    ordered = sorted(events.values(), key=lambda e: (e["timestamp"], e["id"]))
    return {
        "alert": alert,
        "window": {"start": start, "end": end},
        "seed_iocs": sorted(seed_iocs),
        "all_iocs": sorted(seen),
        "event_count": len(ordered),
        "events": ordered,
        "timeline": build_timeline(ordered),
    }