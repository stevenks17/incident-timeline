import requests
import json
import os
import time
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()



DATA_FILE = 'data/sample_logs.json'

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


def poll_abusepdb():
    try:
      params = {'limit':'10', 'confindenceMinimum': '50'}
      headers = {'Accept': 'application/json', 'key': API_KEY}

      response = requests.get(ABUSE_URL, headers=headers, params=params)


      if response.status_code != 200:
        print(f"Error: {response.status_code}")
        return []
      
      data = response.json()
      events = []

      for report in data.get('data', []):
        event = {
          "timestamp": report["reportedAt"],
          "source_ip": report["ipAddress"],
          "event_type": "abuse_report",
          "details": f"{report['categories']}" | {report['comment']}
        }

        events.append(event)
      return events
    except requests.RequestException as e:
       print(f"Request exception: {e}")
       return None

def load_existing_events():
   if os.path.exists(DATA_FILE):
      with open(DATA_FILE, 'r') as f:
         return json.load(f)
   return []


def deduplicate(existing, new):
   existing_ips = {event['source_ip'] for event in existing}
   return existing + [event for event in new if event['source_ip'] not in existing_ips]


def save_events(events,):
  with open(DATA_FILE, 'w') as f:
    json.dump(events, f, indent=4)
    
def save_last_updated():
   with open(LAST_UPDATED_FILE, 'w') as f:
      f.write(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))


if __name__ == "__main__":
    while True:
        new_events = poll_abusepdb()
        existing_events = load_existing_events()
        if new_events:
            combined_events = deduplicate(existing_events, new_events)
            save_events(combined_events)
            save_last_updated()
            print(f"Saved {len(new_events)} new events! Total: {len(combined_events)}")
        else:
            print("Using cached data. No new events or API Failure")
        time.sleep(3600)