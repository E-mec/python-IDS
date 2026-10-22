
import re
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# Configuration

LOG_FILE = "advanced_ids_auth.log"
LOG_YEAR = 2026
THRESHOLD = 5
TIME_WINDOW = timedelta(seconds=60)

# Match the syslog timestamp at the beginning of each line.
TIMESTAMP_REGEX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
)

# Match failed SSH password attempts and capture the source IP.
FAIL_REGEX = re.compile(
    r"Failed password for .*? from "
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)

# Store failed-login event timestamps, grouped by source IP.
failed_attempts = defaultdict(list)


# Timestamp Parsing

def parse_timestamp(line):
    """Extract and parse the timestamp from a log line."""
    match = TIMESTAMP_REGEX.search(line)

    if not match:
        return None

    timestamp_text = match.group("timestamp")
    timestamp_with_year = f"{timestamp_text} {LOG_YEAR}"

    try:
        parsed_time = datetime.strptime(
            timestamp_with_year,
            "%b %d %H:%M:%S %Y"
        )

        return parsed_time.replace(tzinfo=timezone.utc)

    except ValueError:
        return None


# Alert Handling

def alert(ip, attempts, event_time):
    """Print an alert when suspicious activity is detected."""
    print(
        f"[!] ALERT: Possible brute-force activity\n"
        f"    Source IP: {ip}\n"
        f"    Failed attempts: {attempts}\n"
        f"    Detection window: {TIME_WINDOW.total_seconds():.0f} seconds\n"
        f"    Event time: {event_time.isoformat()}\n"
    )


# Detection Engine

def check_line(line):
    """Analyze one log line for repeated failed SSH logins."""

    # Step 1: Parse the actual event timestamp.
    event_time = parse_timestamp(line)

    if event_time is None:
        return

    # Step 2: Identify a failed authentication event.
    match = FAIL_REGEX.search(line)

    if not match:
        return

    ip = match.group("ip")

    # Step 3: Remove attempts outside the rolling time window.
    failed_attempts[ip] = [
        timestamp
        for timestamp in failed_attempts[ip]
        if timedelta(0) <= event_time - timestamp < TIME_WINDOW
    ]

    # Step 4: Record the current failed attempt.
    failed_attempts[ip].append(event_time)

    # Step 5: Check the detection threshold.
    if len(failed_attempts[ip]) >= THRESHOLD:
        alert(
            ip,
            len(failed_attempts[ip]),
            event_time
        )

        # Basic alert suppression for this initial version.
        failed_attempts[ip].clear()


# Main Program

def main():
    print(f"[*] Starting IDS log analysis: {LOG_FILE}\n")

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                check_line(line)

        print("[*] Log analysis completed.")

    except FileNotFoundError:
        print(f"[!] Error: Log file '{LOG_FILE}' was not found.")

    except PermissionError:
        print(f"[!] Error: Permission denied when reading '{LOG_FILE}'.")


if __name__ == "__main__":
    main()
