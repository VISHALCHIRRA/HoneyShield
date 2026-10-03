import sqlite3
from flask import Flask, jsonify, render_template

app = Flask(
    __name__,
    template_folder="../dashboard/templates",
    static_folder="../dashboard/static"
)

DB_FILE = "database/honeyshield.db"


def get_db_connection():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    connection = get_db_connection()

    total_attacks = connection.execute(
        "SELECT COUNT(*) FROM attacks"
    ).fetchone()[0]

    unique_ips = connection.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM attacks"
    ).fetchone()[0]

    login_attempts = connection.execute(
    "SELECT COUNT(*) FROM alerts WHERE attack_category = 'Authentication'"
).fetchone()[0]
    suspicious_commands = connection.execute(
        "SELECT COUNT(*) FROM alerts WHERE alert_type = 'Suspicious Command'"
    ).fetchone()[0]

    high_severity = connection.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'High'"
    ).fetchone()[0]

    medium_severity = connection.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'Medium'"
    ).fetchone()[0]

    connection.close()

    return jsonify({
        "total_attacks": total_attacks,
        "unique_ips": unique_ips,
        "login_attempts": login_attempts,
        "suspicious_commands": suspicious_commands,
        "high_severity": high_severity,
        "medium_severity": medium_severity
    })


@app.route("/api/alerts")
def alerts():
    connection = get_db_connection()

    rows = connection.execute("""
    SELECT
        id,
        timestamp,
        alert_type,
        attack_category,
        severity,
        description,
        src_ip,
        session,
        mitre_id,
        mitre_technique,
        ti_status,
        reputation,
        risk_score,
        country,
        isp,
        abuse_reports
    FROM alerts
    ORDER BY timestamp DESC
""").fetchall()
    connection.close()

    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
