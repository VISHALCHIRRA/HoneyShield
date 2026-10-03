SUSPICIOUS_COMMANDS = [
    "cat /etc/passwd",
    "cat /etc/shadow",
    "whoami",
    "uname -a",
    "ifconfig",
    "ip addr",
    "netstat",
    "ps",
    "wget",
    "curl",
    "chmod",
    "sudo",
]


def check_suspicious_command(command):
    if not command:
        return None

    command = command.lower().strip()

    for suspicious in SUSPICIOUS_COMMANDS:
        if suspicious in command:
            return {
                "alert_type": "Suspicious Command",
                "severity": "Medium",
                "description": f"Suspicious command detected: {command}"
            }

    return None


def check_login_attempt(event):
    eventid = event.get("eventid", "")

    if eventid == "cowrie.login.failed":
        return {
            "alert_type": "Failed SSH Login",
            "severity": "High",
            "attack_category": "Authentication",
            "description": (
                f"Failed SSH login attempt using username: "
                f"{event.get('username')}"
            )
        }

    if eventid == "cowrie.login.success":
        return {
            "alert_type": "Successful Honeypot Login",
            "severity": "High",
            "attack_category": "Authentication",
            "description": (
                f"Successful honeypot login using username: "
                f"{event.get('username')}"
            )
        }

    return None 
def check_brute_force(events, threshold=3):
    """
    Detect multiple failed SSH login attempts
    from the same IP address.
    """

    failed_logins = {}

    for event in events:
        if event.get("eventid") == "cowrie.login.failed":
            src_ip = event.get("src_ip")

            if src_ip:
                failed_logins[src_ip] = failed_logins.get(src_ip, 0) + 1

    alerts = []

    for src_ip, count in failed_logins.items():
        if count >= threshold:
            alerts.append({
                "alert_type": "Possible Brute Force Attack",
                "severity": "High",
                "description": (
                    f"{count} failed SSH login attempts "
                    f"from {src_ip}"
                ),
                "src_ip": src_ip,
                "attempts": count
            })

    return alerts

def classify_attack(command):
    """
    Classify a suspicious command into an attack category.
    """

    if not command:
        return "Unknown"

    command = command.lower().strip()

    if any(item in command for item in [
        "whoami",
        "uname -a",
        "ifconfig",
        "ip addr",
        "netstat",
        "ps"
    ]):
        return "Reconnaissance"

    if any(item in command for item in [
        "cat /etc/passwd",
        "cat /etc/shadow"
    ]):
        return "Credential/File Discovery"

    if any(item in command for item in [
        "wget",
        "curl",
        "chmod",
        "sudo"
    ]):
        return "Command Execution"

    return "Other"


def map_mitre_technique(command=None, eventid=None):
    """
    Map observed HoneyShield activity to a MITRE ATT&CK technique.
    """

    if eventid in [
        "cowrie.login.success",
        "cowrie.login.failed"
    ]:
        return {
            "mitre_id": "T1021.004",
            "mitre_technique": "Remote Services: SSH"
        }

    if eventid == "cowrie.login.failed":
        return {
            "mitre_id": "T1110",
            "mitre_technique": "Brute Force"
        }

    if not command:
        return {
            "mitre_id": None,
            "mitre_technique": None
        }

    command = command.lower().strip()

    mappings = [
        (
            "whoami",
            "T1033",
            "System Owner/User Discovery"
        ),
        (
            "uname -a",
            "T1082",
            "System Information Discovery"
        ),
        (
            "ifconfig",
            "T1016",
            "System Network Configuration Discovery"
        ),
        (
            "ip addr",
            "T1016",
            "System Network Configuration Discovery"
        ),
        (
            "netstat",
            "T1049",
            "System Network Connections Discovery"
        ),
        (
            "ps",
            "T1057",
            "Process Discovery"
        ),
        (
            "cat /etc/passwd",
            "T1087.001",
            "Account Discovery: Local Account"
        ),
        (
            "cat /etc/shadow",
            "T1003.008",
            "/etc/passwd and /etc/shadow"
        ),
        (
            "wget",
            "T1105",
            "Ingress Tool Transfer"
        ),
        (
            "curl",
            "T1105",
            "Ingress Tool Transfer"
        )
    ]

    for pattern, mitre_id, technique in mappings:
        if pattern in command:
            return {
                "mitre_id": mitre_id,
                "mitre_technique": technique
            }

    return {
        "mitre_id": None,
        "mitre_technique": None
    }
