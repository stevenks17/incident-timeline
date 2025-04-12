import json
import os
import time
from datetime import datetime

DATA_FILE = 'data/sample_logs.json'
LAST_UPDATED_FILE = 'data/last_updated.txt'

INCIDENT_STEPS = [
    ("initial_access", "Phishing email clicked by user j.doe@company.com"),
    ("execution", "Malicious payload executed on workstation WS-324"),
    ("persistence", "Scheduled task created for persistence"),
    ("privilege_escalation", "Admin account 'svc-admin' created"),
    ("lateral_movement", "Remote desktop connection from WS-324 to WS-325"),
    ("collection", "Sensitive documents accessed in shared drive"),
    ("exfiltration", "Data exfiltration to external IP 203.0.113.45"),
    ("response", "SOC triggered account disable for j.doe@company.com"),
    ("remediation", "Firewall rule added to block IP 203.0.113.45"),
    ("recovery", "System restoration initiated for WS-324")
]

def load_existing_events():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return []

def save_events(events):
    with open(DATA_FILE, 'w') as f:
        json.dump(events, f, indent=4)

def save_last_updated():
    with open(LAST_UPDATED_FILE, 'w') as f:
        f.write(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))

def add_next_step():
    events = load_existing_events()

    if len(events) >= len(INCIDENT_STEPS):
        print("🚀 Incident complete! No further steps to add.")
        return

    next_step = INCIDENT_STEPS[len(events)]
    new_event = {
        "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        "event_type": next_step[0],
        "details": next_step[1]
    }

    events.append(new_event)
    save_events(events)
    save_last_updated()
    print(f"✅ Added new step: {next_step[0]} - {next_step[1]}")

if __name__ == "__main__":
    while True:
        add_next_step()
        time.sleep(1800)  
