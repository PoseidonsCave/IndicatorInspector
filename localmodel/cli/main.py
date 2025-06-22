# cli/main.py

import argparse
from core.enrichment import enrich_local
from core.schema import validate_entry
from core.scoring import score_indicator
from core.utils import write_log

def main():
    parser = argparse.ArgumentParser(
        description="Indicator Inspector (Local Model) - Offline IOC Scoring Tool"
    )
    parser.add_argument(
        "indicator", help="IOC to enrich (e.g. IP, domain, or file hash)"
    )
    args = parser.parse_args()

    indicator = args.indicator.strip()
    matches = enrich_local(indicator)

    if not matches:
        print(f"[!] No local intelligence found for: {indicator}")
        write_log("activity.log", f"No data for {indicator}")
        return

    valid_entries = []
    for entry in matches:
        errors = validate_entry(entry)
        if errors:
            print(f"[!] Skipping invalid entry: {errors}")
        else:
            valid_entries.append(entry)

    if not valid_entries:
        print("[!] No valid entries after schema validation.")
        return

    score, tags = score_indicator(valid_entries)

    print("\n=== Indicator Report ===")
    print(f"Indicator: {indicator}")
    print(f"Score: {score}/100")
    print(f"Tags: {', '.join(tags) if tags else 'None'}")

    write_log("activity.log", f"Scored {indicator} => {score}/100 | Tags: {tags}")

if __name__ == "__main__":
    main()
