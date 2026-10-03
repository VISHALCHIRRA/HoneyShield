import json
from pathlib import Path

from rules import (
    check_suspicious_command,
    check_login_attempt,
    check_brute_force,
    classify_attack,
    map_mitre_technique
)

from threat_intelligence import lookup_ip


INPUT_FILE = Path("logs/processed_logs.json")
OUTPUT_FILE = Path("logs/alerts.json")


def add_threat_intelligence(alert, src_ip):
    ti_data = lookup_ip(src_ip)

    alert.update({
        "ti_status": ti_data.get("ti_status"),
        "reputation": ti_data.get("reputation"),
        "risk_score": ti_data.get("risk_score"),
        "country": ti_data.get("country"),
        "isp": ti_data.get("isp"),
        "abuse_reports": ti_data.get("abuse_reports")
    })

    return alert


def detect_threats():
    alerts = []

    if not INPUT_FILE.exists():
        print("Processed log file not found.")
        return

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        events = json.load(file)

    for event in events:

        # Check login attempts
        login_alert = check_login_attempt(event)

        if login_alert:
            login_alert.update({
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "session": event.get("session"),
                **map_mitre_technique(eventid=event.get("eventid"))
            })

            add_threat_intelligence(
                login_alert,
                event.get("src_ip")
            )

            alerts.append(login_alert)

        # Check suspicious commands
        command = event.get("command")

        command_alert = check_suspicious_command(command)

        if command_alert:
            command_alert.update({
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "session": event.get("session"),
                "attack_category": classify_attack(command),
                **map_mitre_technique(command=command)
            })

            add_threat_intelligence(
                command_alert,
                event.get("src_ip")
            )

            alerts.append(command_alert)

    # Check for brute-force attacks
    brute_force_alerts = check_brute_force(events)

    for alert in brute_force_alerts:
        new_alert = {
            "alert_type": alert.get("alert_type"),
            "severity": alert.get("severity"),
            "description": alert.get("description"),
            "timestamp": None,
            "src_ip": alert.get("src_ip"),
            "session": None,
            "attack_category": "Authentication",
            **map_mitre_technique(eventid="cowrie.login.failed")
        }

        new_alert.update({
            "mitre_id": "T1110",
            "mitre_technique": "Brute Force"
        })

        add_threat_intelligence(
            new_alert,
            alert.get("src_ip")
        )

        alerts.append(new_alert)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"Detected {len(alerts)} alerts")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    detect_threats()
