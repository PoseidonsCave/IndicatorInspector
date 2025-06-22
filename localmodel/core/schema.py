from core.utils import write_log

def validate_entry(entry):
    errors = []

    if not isinstance(entry.get("indicator"), str):
        errors.append("Missing or invalid 'indicator'")

    if entry.get("type") not in {"ipv4", "domain", "hash"}:
        errors.append("Invalid 'type' value")

    tags = entry.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        errors.append("Invalid or missing 'tags' list")

    if entry.get("confidence") not in {"Low", "Moderate", "High"}:
        errors.append("Invalid 'confidence' level")

    weight = entry.get("weight", 50)
    if not isinstance(weight, int) or not (0 <= weight <= 100):
        errors.append(f"'weight' must be an integer between 0–100 (got {weight})")

    if errors:
        write_log("validation.log", f"Entry: {entry} — Errors: {errors}")

    return errors
