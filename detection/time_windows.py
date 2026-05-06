from datetime import datetime

DEFAULT_WINDOW_SECONDS = 60
ALL_EVENTS_BUCKET = "all"


def event_timestamp(event):
    value = event.get("timestamp")
    if value is None:
        value = event.get("time")

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        pass

    text = str(value).strip()
    if not text:
        return None

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def window_bucket(event, window_seconds=DEFAULT_WINDOW_SECONDS):
    timestamp = event_timestamp(event)
    if timestamp is None:
        return ALL_EVENTS_BUCKET
    return int(timestamp // window_seconds)


def window_evidence(bucket, window_seconds=DEFAULT_WINDOW_SECONDS):
    if bucket is None or bucket == ALL_EVENTS_BUCKET:
        return {
            "window_seconds": window_seconds,
            "window_start": None,
            "window_end": None,
        }

    window_start = bucket * window_seconds
    return {
        "window_seconds": window_seconds,
        "window_start": window_start,
        "window_end": window_start + window_seconds,
    }
