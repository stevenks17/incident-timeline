import json
from datetime import datetime

def ai_classify_event(event):
    keywords = {
        "critical": ["privilege escalation", "exfiltration", "admin account", "payload executed"],
        "suspicious": ["remote desktop", "scheduled task", "shared drive", "phishing", "malicious"],
        "noise": ["failed login", "scan", "unknown"]
    }

    details = event["details"].lower()

    if any(word in details for word in keywords["critical"]):
        return "critical"
    elif any(word in details for word in keywords["suspicious"]):
        return "suspicious"
    else:
        return "noise"

def load_logs(filepath='data/sample_logs.json'):
    with open(filepath, 'r') as f:
        logs = json.load(f)
    return logs

def normalize_logs(logs):
    normalized = []

    phase_map = {
        "initial_access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege_escalation": "Privilege Escalation",
        "lateral_movement": "Lateral Movement",
        "collection": "Collection",
        "exfiltration": "Exfiltration",
        "response": "Response",
        "remediation": "Remediation",
        "recovery": "Recovery"
    }

    for log in logs:
        timestamp = datetime.fromisoformat(log['timestamp'].replace("Z", "+00:00"))
        event_type = log['event_type']
        group_name = phase_map.get(event_type, event_type.capitalize())

        severity = ai_classify_event(log)

        normalized.append({
            "start_date": {
                "year": timestamp.year,
                "month": timestamp.month,
                "day": timestamp.day,
                "hour": timestamp.hour,
                "minute": timestamp.minute
            },
            "text": {
                "headline": f"{group_name} ({severity.upper()})",
                "text": f"{log['details']}<br>Severity: {severity.capitalize()}"
            },
            "group": group_name,
            "severity": severity
        })

    return normalized
