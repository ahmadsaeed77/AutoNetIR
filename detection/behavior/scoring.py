def safe_ratio(numerator, denominator):
    if not denominator:
        return 0.0
    return round(numerator / denominator, 4)


def mean(values):
    values = [value for value in values if value is not None]
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)


def median(values):
    values = sorted(value for value in values if value is not None)
    if not values:
        return 0.0

    middle = len(values) // 2
    if len(values) % 2:
        return float(values[middle])
    return round((values[middle - 1] + values[middle]) / 2, 2)


def peer_baseline(rows, field, exclude_src_ip=None):
    values = [
        row[field]
        for row in rows
        if row.get("src_ip") != exclude_src_ip and row.get(field) is not None
    ]
    if not values:
        values = [row[field] for row in rows if row.get(field) is not None]

    return {
        "median": median(values),
        "mean": mean(values),
        "sample_size": len(values),
    }


def behavior_score(observed, baseline_median, minimum_reference=1):
    reference = max(float(baseline_median or 0), minimum_reference)
    # Ratio-based 0-100 score: 1x baseline ~= 30, 2x ~= 60,
    # 3x ~= 90, and 3.33x or higher caps at 100.
    return min(100, round((observed / reference) * 30, 1))
