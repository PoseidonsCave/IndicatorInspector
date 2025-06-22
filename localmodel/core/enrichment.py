import json
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "local_threat_db.json")

def enrich_local(indicator):
    if not os.path.exists(DATA_PATH):
        print(f"[!] Threat database not found at {DATA_PATH}")
        return []

    with open(DATA_PATH, "r") as f:
        db = json.load(f)

    matches = [entry for entry in db if entry.get("indicator") == indicator]
    return matches
