CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_type TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    session TEXT,
    username TEXT,
    password TEXT,
    command TEXT,
    message TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    alert_type TEXT,
    severity TEXT,
    description TEXT,
    src_ip TEXT,
    session TEXT,
    attack_category TEXT,
    mitre_id TEXT,
    mitre_technique TEXT,
    ti_status TEXT,
    reputation TEXT,
    risk_score INTEGER,
    country TEXT,
    isp TEXT,
    abuse_reports INTEGER
);
