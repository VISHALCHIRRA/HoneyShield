import json
import sqlite3
from pathlib import Path

DB_FILE = Path("database/honeyshield.db")
PROCESSED_LOGS = Path("logs/processed_logs.json")
ALERTS_FILE = Path("logs/alerts.json")


def insert_attacks():
    if not PROCESSED_LOGS.exists():
        print("Processed logs not found.")
        return

    with PROCESSED_LOGS.open("r", encoding="utf-8") as file:
        events = json.load(file)

    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    # Replace the current processed-log snapshot to avoid duplicate records.
    cursor.execute("DELETE FROM attacks")

    for event in events:
        cursor.execute("""
            INSERT INTO attacks (
                timestamp,
                event_type,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                session,
                username,
                password,
                command,
                message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp"),
            event.get("eventid"),
            event.get("src_ip"),
            event.get("src_port"),
            event.get("dst_ip"),
            event.get("dst_port"),
            event.get("session"),
            event.get("username"),
            event.get("password"),
            event.get("command"),
            event.get("message")
        ))

    connection.commit()
    connection.close()

    print(f"Inserted {len(events)} attack events.")


def insert_alerts():
    if not ALERTS_FILE.exists():
        print("Alerts file not found.")
        return

    with ALERTS_FILE.open("r", encoding="utf-8") as file:
        alerts = json.load(file)

    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    # Replace the current alert snapshot to avoid duplicate records.
    cursor.execute("DELETE FROM alerts")

    for alert in alerts:
        cursor.execute("""
            INSERT INTO alerts (
                timestamp,
                alert_type,
                severity,
                description,
                src_ip,
                session,
                attack_category,
                mitre_id,
                mitre_technique,
                ti_status,
                reputation,
                risk_score,
                country,
                isp,
                abuse_reports
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("timestamp"),
            alert.get("alert_type"),
            alert.get("severity"),
            alert.get("description"),
            alert.get("src_ip"),
            alert.get("session"),
            alert.get("attack_category"),
            alert.get("mitre_id"),
            alert.get("mitre_technique"),
            alert.get("ti_status"),
            alert.get("reputation"),
            alert.get("risk_score"),
            alert.get("country"),
            alert.get("isp"),
            alert.get("abuse_reports")
        ))
    connection.commit()
    connection.close()

    print(f"Inserted {len(alerts)} alerts.")


if __name__ == "__main__":
    insert_attacks()
    insert_alerts()
