import argparse
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Updated import path for local enrichment logic
from core.enrichment import enrich_local
from core.schema import validate_entry
from core.scoring import score_indicator
from core.utils import write_log
from core.ioc_parser import parse_file, detect_type

def main():
    parser = argparse.ArgumentParser(
        description="Indicator Inspector (Local Model) - Offline IOC Tool"
    )
    parser.add_argument("indicator", nargs="?", help="IOC to enrich (IP, domain, or hash)")
    parser.add_argument("--extract-iocs", help="Path to .json, .txt, .csv, or .yaml file to parse for IOCs")
    parser.add_argument("--output", help="Where to save parsed IOCs (default: localmodel/data/parsed_threats.json)")
    args = parser.parse_args()

    if args.extract_iocs:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        default_out = os.path.join(base_dir, "data", "parsed_threats.json")
        output_path = args.output or default_out
        parse_file(args.extract_iocs, output_path)
        return

    if not args.indicator:
        print("[!] You must provide an indicator or use --extract-iocs")
        return

    indicator = args.indicator.strip()
    if not detect_type(indicator):
        print(f"[!] Unknown indicator type: {indicator}")
        return

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