import ipaddress
import os

import requests
from dotenv import load_dotenv


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

load_dotenv()


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup_ip(ip):
    if not ip:
        return {
            "ti_status": "No IP",
            "reputation": None,
            "risk_score": None,
            "country": None,
            "isp": None,
            "abuse_reports": None
        }

    # Never send private lab addresses to a public TI service.
    if is_private_ip(ip):
        return {
            "ti_status": "Private / Lab IP",
            "reputation": "Not available",
            "risk_score": None,
            "country": None,
            "isp": None,
            "abuse_reports": None
        }

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "ti_status": "API key not configured",
            "reputation": None,
            "risk_score": None,
            "country": None,
            "isp": None,
            "abuse_reports": None
        }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key": api_key,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=5
        )

        response.raise_for_status()

        data = response.json().get("data", {})

        abuse_score = data.get("abuseConfidenceScore")

        reputation = (
            "Malicious" if abuse_score is not None and abuse_score >= 75
            else "Suspicious" if abuse_score is not None and abuse_score >= 25
            else "Low Risk" if abuse_score is not None
            else "Unknown"
        )

        return {
            "ti_status": "Lookup successful",
            "reputation": reputation,
            "risk_score": abuse_score,
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "abuse_reports": data.get("totalReports")
        }

    except requests.RequestException as error:
        print(f"Threat intelligence lookup failed for {ip}: {error}")

        return {
            "ti_status": "Lookup failed",
            "reputation": None,
            "risk_score": None,
            "country": None,
            "isp": None,
            "abuse_reports": None
        }
