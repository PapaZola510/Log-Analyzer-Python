import sys
from collections import defaultdict

failed_attempts = defaultdict(int)

log_file = sys.argv[1]

with open(log_file, "r") as file:
    for line in file:
        if "LOGIN_FAILED" in line:
            ip = line.split("ip=")[1].strip()
            failed_attempts[ip] += 1

print("Analyzing log file..\n")

found = False

for ip, count in failed_attempts.items():
    if count >= 3:
        print(f"Suspicious activity read from {ip} with {count} failed login attempts")
        found = True

if not found:
    print("No suspicious activity detected.")