import json
import os

# Threat intelligence is stored in `threatdb.json` under the data directory.
# The original path referenced `local_threat_db.json`, which does not exist and
# causes enrichment to always report the database as missing.  Align the path
# with the actual file name so enrichment works correctly.
DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "threatdb.json")

def enrich_local(indicator):
    if not os.path.exists(DATA_PATH):
        print(f"[!] Threat database not found at {DATA_PATH}")
        return []

    with open(DATA_PATH, "r") as f:
        db = json.load(f)

    matches = [entry for entry in db if entry.get("indicator") == indicator]
    return matches
