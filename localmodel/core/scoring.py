def score_indicator(entries):
    total_score = 0
    tags = set()

    for entry in entries:
        entry_weight = entry.get("weight", 50)  # default if not present
        tags.update(entry.get("tags", []))

        if "botnet" in entry.get("tags", []):
            total_score += 0.4 * entry_weight  # up to 40 points from this
        if entry.get("confidence", "") == "High":
            total_score += 0.3 * entry_weight
        elif entry.get("confidence", "") == "Moderate":
            total_score += 0.15 * entry_weight

    return min(int(total_score), 100), list(tags)
