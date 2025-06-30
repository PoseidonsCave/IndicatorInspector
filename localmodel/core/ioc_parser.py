import os
import re
import json
import csv
try:
    import yaml
except ImportError:
    yaml = None
from core.schema import validate_entry

def detect_type(ioc):
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ioc):
        return "ipv4"
    elif re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "hash"  # MD5
    elif re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "hash"  # SHA1
    elif re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "hash"  # SHA256
    elif re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", ioc):
        return "domain"
    else:
        return None

def extract_iocs_from_text(text):
    ipv4_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    domain_pattern = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"

    matches = set()
    for pattern in [ipv4_pattern, domain_pattern, hash_pattern]:
        matches.update(re.findall(pattern, text))

    return list(matches)

def parse_file(filepath, output_path=None):
    filename = os.path.basename(filepath)
    ioc_list = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            if filepath.endswith(".json"):
                raw = json.load(f)
                text = json.dumps(raw)
            elif filepath.endswith(".yaml") or filepath.endswith(".yml"):
                if yaml is None:
                    # Fall back to plain text if PyYAML is unavailable
                    text = f.read()
                else:
                    raw = yaml.safe_load(f)
                    text = json.dumps(raw)
            elif filepath.endswith(".csv"):
                reader = csv.reader(f)
                lines = [" ".join(row) for row in reader]
                text = "\n".join(lines)
            else:
                text = f.read()
    except Exception as e:
        print(f"[!] Failed to read file: {e}")
        return []

    raw_iocs = extract_iocs_from_text(text)

    for ioc in raw_iocs:
        ioc_type = detect_type(ioc)
        if ioc_type:
            ioc_entry = {
                "indicator": ioc,
                "type": ioc_type,
                "tags": [],
                "confidence": "Moderate",
                "weight": 50,
                "source": f"Parsed from {filename}"
            }
            if not validate_entry(ioc_entry):
                ioc_list.append(ioc_entry)

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as out:
                json.dump(ioc_list, out, indent=2)
                print(f"[+] Parsed IOCs written to: {output_path}")
        except Exception as e:
            print(f"[!] Failed to write output: {e}")

    return ioc_list

# Example usage (direct call):
# parse_file("suspicious.txt", "data/parsed_threats.json")