import json
from pathlib import Path

INPUT_FILE = Path("logs/cowrie.json")
OUTPUT_FILE = Path("logs/processed_logs.json")


def parse_cowrie_log():
    events = []

    if not INPUT_FILE.exists():
        print(f"Error: {INPUT_FILE} not found")
        return

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = {
                "timestamp": data.get("timestamp"),
                "eventid": data.get("eventid"),
                "src_ip": data.get("src_ip"),
                "src_port": data.get("src_port"),
                "dst_ip": data.get("dst_ip"),
                "dst_port": data.get("dst_port"),
                "session": data.get("session"),
                "username": data.get("username"),
                "password": data.get("password"),
                "command": data.get("input"),
                "message": data.get("message")
            }

            events.append(event)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(events, file, indent=4)

    print(f"Parsed {len(events)} events")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    parse_cowrie_log()
