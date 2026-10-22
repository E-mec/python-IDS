
import time
import re
from collections import defaultdict

# Configuration
LOG_FILE = "advanced_ids_auth.log"
FAIL_REGEX = re.compile( r"Failed password for .*? from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
THRESHOLD = 10
TIME_WINDOW = 60

failed_attempts = defaultdict(list)


def alert(ip, attempts):
    print(
        f"[!] ALERT: Possible brute-force activity detected "
        f"from {ip} — {attempts} failed attempts "
        f"within {TIME_WINDOW} seconds."
    )


def simulate_log_read():
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            yield line
            # Optional: slow playback to simulate monitoring.
            # Remove this during faster testing.
            # time.sleep(1)


def check_line(line, current_time):
    match = FAIL_REGEX.search(line)

    if not match:
        return

    ip = match.group("ip")

    # Keep only attempts inside the configured time window.
    failed_attempts[ip] = [
        timestamp
        for timestamp in failed_attempts[ip]
        if current_time - timestamp < TIME_WINDOW
    ]

    # Record the current failed login.
    failed_attempts[ip].append(current_time)

    # Check whether the detection threshold has been reached.
    if len(failed_attempts[ip]) >= THRESHOLD:
        alert(ip, len(failed_attempts[ip]))

        # Clear the counter after alerting to avoid repeated alerts
        # for every subsequent failed login in the same burst.
        failed_attempts[ip].clear()


def main():
    print(f"[*] Monitoring log file: {LOG_FILE}\n")

    for line in simulate_log_read():
        now = time.time()
        check_line(line, now)


if __name__ == "__main__":
    main()
