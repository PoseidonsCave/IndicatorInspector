import json
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "threatdb.json")

def enrich_local(indicator):
    if not os.path.exists(DATA_PATH):
        print(f"[!] Threat database not found at {DATA_PATH}")
        return []

    with open(DATA_PATH, "r") as f:
        try:
            db = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Threat database at {DATA_PATH} is corrupted or invalid")
            return []

    matches = [entry for entry in db if entry.get("indicator") == indicator]
    return matches
