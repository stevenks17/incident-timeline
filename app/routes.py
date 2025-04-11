from flask import Blueprint, render_template, jsonify
from .parser import load_logs, normalize_logs
import os

main = Blueprint('main', __name__)

def get_last_updated():
  try:
    with open('data/last_updated.txt', 'r') as f:
      return f.read()
  except FileNotFoundError:
    return "No updates yet"

@main.route('/')
def index():
  last_updated = get_last_updated
  return render_template('timeline.html', last_updated=last_updated)

@main.route('/data')
def data():
  logs = load_logs()
  normalized_logs = normalize_logs(logs)
  timeline_data = {
    "title":{
      "text":{
        "headline": "Incident Timeline",
        "text": "Live data from AbuseIPDB"
      }
    },
    "events": normalized_logs
  }
  return jsonify(timeline_data)