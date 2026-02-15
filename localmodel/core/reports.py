import hashlib
import json
import os
from datetime import datetime

def report(ioc_list, output_dir="reports", base_filename="IoC-Report"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    base_name = f"{base_filename}_{timestamp}"
    json_path = os.path.join(output_dir, f"{base_name}.json")
    md_path = os.path.join(output_dir, f"{base_name}.md")

    # Save JSON
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(ioc_list, f, indent=2)
        print(f"[+] JSON report written to {json_path}")
    except Exception as e1:
        print(f"[!] Failed to write JSON: {e1}")

    # Save Markdown
    try:
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# IOC Report\nGenerated: {timestamp} UTC\n\n")
            for entry in ioc_list:
                f.write(f"## {entry.get('indicator')}\n")
                f.write(f"- Type: {entry.get('type')}\n")
                f.write(f"- Tags: {', '.join(entry.get('tags', []))}\n")
                f.write(f"- Confidence: {entry.get('confidence')}\n")
                f.write(f"- Weight: {entry.get('weight')}\n")
                f.write(f"- Source: {entry.get('source')}\n\n")
        print(f"[+] Markdown report written to {md_path}")
    except Exception as e2:
        print(f"[!] Failed to write Markdown: {e2}")

    # Generate SBOM-style hash list
    sbom_log = os.path.join(output_dir, f"{base_name}_SHA256.txt")
    try:
        with open(sbom_log, "w", encoding="utf-8") as f:
            for path in [json_path, md_path]:
                sha = file_hashing(path)
                f.write(f"{os.path.basename(path)}: {sha}\n")
        print(f"[+] SHA256 SBOM written to {sbom_log}")
    except Exception as e3:
        print(f"[!] Failed to write SBOM hash file: {e3}")

    return json_path, md_path, sbom_log

def file_hashing(filepath, block_size=65536):
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(block_size), b""):
                hasher.update(byte_block)
        return hasher.hexdigest()
    except Exception as e:
        print(f"[!] Failed to hash {filepath}: {e}")
        return "ERROR"