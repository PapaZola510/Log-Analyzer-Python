import argparse
from collections import defaultdict
from datetime import datetime, timedelta


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Log Analyzer v2.0 - Detect suspicious activity from log files"
    )
    parser.add_argument("logfile", help="Path to the log file")
    parser.add_argument(
        "--fail-threshold",
        type=int,
        default=3,
        help="Number of failed logins before an IP is flagged (default: 3)"
    )
    parser.add_argument(
        "--bruteforce-threshold",
        type=int,
        default=3,
        help="Number of failed logins within time window for brute-force detection (default: 3)"
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=30,
        help="Time window in seconds for brute-force detection (default: 30)"
    )
    parser.add_argument(
        "--activity-threshold",
        type=int,
        default=6,
        help="Number of total events before an IP is flagged for high activity (default: 6)"
    )
    parser.add_argument(
        "--export",
        type=str,
        help="Export report to a text file"
    )
    return parser.parse_args()


def parse_log_file(filename):
    entries = []

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) < 4:
                    print(f"[WARNING] Skipping malformed line {line_number}: {line}")
                    continue

                date_part = parts[0]
                time_part = parts[1]
                ip_address = parts[2]
                event = parts[3]

                try:
                    timestamp = datetime.strptime(
                        f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    print(f"[WARNING] Invalid timestamp on line {line_number}: {line}")
                    continue

                entries.append({
                    "timestamp": timestamp,
                    "ip": ip_address,
                    "event": event
                })

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}")
        return []

    return entries


def detect_failed_logins(entries, threshold):
    failed_counts = defaultdict(int)

    for entry in entries:
        if entry["event"] == "LOGIN_FAILED":
            failed_counts[entry["ip"]] += 1

    flagged = {
        ip: count for ip, count in failed_counts.items()
        if count >= threshold
    }
    return flagged


def detect_bruteforce(entries, threshold, window_seconds):
    failed_times = defaultdict(list)

    for entry in entries:
        if entry["event"] == "LOGIN_FAILED":
            failed_times[entry["ip"]].append(entry["timestamp"])

    flagged = {}
    window = timedelta(seconds=window_seconds)

    for ip, timestamps in failed_times.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            count = 1
            start_time = timestamps[i]

            for j in range(i + 1, len(timestamps)):
                if timestamps[j] - start_time <= window:
                    count += 1
                else:
                    break

            if count >= threshold:
                flagged[ip] = {
                    "attempts": count,
                    "window_seconds": window_seconds
                }
                break

    return flagged


def detect_high_activity(entries, threshold):
    activity_counts = defaultdict(int)

    for entry in entries:
        activity_counts[entry["ip"]] += 1

    flagged = {
        ip: count for ip, count in activity_counts.items()
        if count >= threshold
    }
    return flagged


def generate_report(entries, failed_logins, bruteforce, high_activity):
    unique_ips = len(set(entry["ip"] for entry in entries))
    total_lines = len(entries)

    report_lines = []
    report_lines.append("===== LOG ANALYSIS REPORT =====")
    report_lines.append(f"Total log entries analyzed: {total_lines}")
    report_lines.append(f"Unique IP addresses found: {unique_ips}")
    report_lines.append("")

    report_lines.append("=== Detection Results ===")

    report_lines.append("\n[1] Repeated Failed Login Attempts")
    if failed_logins:
        for ip, count in failed_logins.items():
            report_lines.append(f"- {ip}: {count} failed login attempts")
    else:
        report_lines.append("No suspicious repeated failed logins detected.")

    report_lines.append("\n[2] Brute-Force Detection")
    if bruteforce:
        for ip, data in bruteforce.items():
            report_lines.append(
                f"- {ip}: {data['attempts']} failed attempts within {data['window_seconds']} seconds"
            )
    else:
        report_lines.append("No brute-force behavior detected.")

    report_lines.append("\n[3] High Activity Detection")
    if high_activity:
        for ip, count in high_activity.items():
            report_lines.append(f"- {ip}: {count} total events")
    else:
        report_lines.append("No unusually high activity detected.")

    total_flags = len(set(
        list(failed_logins.keys()) +
        list(bruteforce.keys()) +
        list(high_activity.keys())
    ))

    report_lines.append("")
    report_lines.append("=== Summary ===")
    report_lines.append(f"Total suspicious IPs flagged: {total_flags}")

    return "\n".join(report_lines)


def export_report(report, filename):
    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write(report)
        print(f"\n[INFO] Report exported to: {filename}")
    except OSError as error:
        print(f"[ERROR] Could not export report: {error}")


def main():
    args = parse_arguments()

    print("Analyzing log file...\n")
    entries = parse_log_file(args.logfile)

    if not entries:
        print("No valid log entries found.")
        return

    failed_logins = detect_failed_logins(entries, args.fail_threshold)
    bruteforce = detect_bruteforce(
        entries,
        args.bruteforce_threshold,
        args.window_seconds
    )
    high_activity = detect_high_activity(entries, args.activity_threshold)

    report = generate_report(entries, failed_logins, bruteforce, high_activity)
    print(report)

    if args.export:
        export_report(report, args.export)


if __name__ == "__main__":
    main()