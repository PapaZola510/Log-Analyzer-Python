# Python Log Analyzer

A Python project for cybersecurity start, analyzes log files and detects suspicious attempts like repeated failed attempts, brute force behavior, and high IP address activity

Processes it from a txt file that contain the log entries then identifies the potential attack patterns, and generates a report that is extractable as a txt file

# Design

Reads from a log file and identifies the failed log attempts as potential brute force attempts on logging in as it would contain the IP address 

It has limit of 3 attempts before being written as suspicous to give buffer between recalling of password if forgotten or mistyped

# Features

- Analyzes a log file for suspicious activities
- Detects repeated login attempts from the same IP address
- Detects possible brute force attempts within a time window
- Detects suspiciously high activity from a IP address
- Generates a report of findings
- Supports customized thresholds in the command line 
- Exportable report file to a txt file

# To Run

Use on terminal: "py log.analyzer.py *Name of logfile.txt*"
To run with custom threshold: "py log.analyzer.py *Name of logfile.txt* -fail-threshold 3 --window-seconds 15 --activity-threshold 6"
To export: "py log.analyzer.py *Name of logfile.txt* --export report.txt"

# Example

- Log_NoIssue = Log files has no IP address exceeding the limit but still has failed attempts
- Log_Failed = Has 2 IP addresses that have 3 failed log in attempts each
- Auth_Log = Log files made for 2.0 version

PS C:\Users\Local Admin\Desktop\LogAl> py log_analyzer.py Log_NoIssue.txt
Analyzing log file..

No suspicious activity detected.

PS C:\Users\Local Admin\Desktop\LogAl> py log_analyzer.py Log_Failed.txt
Analyzing log file..

Suspicious activity read from 192.168.1.45 with 3 failed login attempts
Suspicious activity read from 192.168.1.99 with 3 failed login attempts

PS C:\Users\Local Admin\Desktop\LogAl> py log_analyzer.py Auth_Log.txt --fail-threshold 3 --window-seconds 15 --activity-threshold 6 --export report.txt     
Analyzing log file...

===== LOG ANALYSIS REPORT =====
Total log entries analyzed: 16
Unique IP addresses found: 4

=== Detection Results ===

[1] Repeated Failed Login Attempts
- 192.168.1.20: 3 failed login attempts

[2] Brute-Force Detection
- 192.168.1.20: 3 failed attempts within 15 seconds

[3] High Activity Detection
- 192.168.1.40: 7 total events

=== Summary ===
Total suspicious IPs flagged: 2

[INFO] Report exported to: report.txt
