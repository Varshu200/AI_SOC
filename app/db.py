import sqlite3
DB_PATH = "soc.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, host TEXT, user TEXT, src_ip TEXT, dst_ip TEXT,
        event_type TEXT, process TEXT, raw TEXT
    );
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        timestamp TEXT, rule_name TEXT, host TEXT, description TEXT,
        severity_hint TEXT, status TEXT DEFAULT 'new'
    );
    CREATE TABLE IF NOT EXISTS iocs (
        value TEXT PRIMARY KEY,
        type TEXT, reputation_score INTEGER, tags TEXT,
        source TEXT, last_checked TEXT
    );
    CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT, verdict TEXT, severity TEXT, confidence REAL,
        report_json TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(src_ip);
    """)
    conn.commit()
    conn.close()