# Python Log Analyzer

Simple Python project that analyzes logs for any failed or successful log attempts from an IP address, potentially alerting any suspicous attempts

# Design

Reads from a log file and identifies the failed log attempts as potential brute force attempts on logging in as it would contain the IP address 

It has limit of 3 attempts before being written as suspicous to give buffer between recalling of password if forgotten or mistyped

# Features

- Detects constant log in attempts from an IP
- Identifies them as possible brute forcing
- Reads entries from a log file
- Shows even the IP address to narrow down where

# To Run

Use on terminal "py log.analyzer.py *Name of logfile.txt*

# Exapmle

- Log_NoIssue = Log files has no IP address exceeding the limit but still has failed attempts
- Log_Failed = Has 2 IP addresses that have 3 failed log in attempts each

PS C:\Users\Local Admin\Desktop\LogAl> py log_analyzer.py Log_NoIssue.txt
Analyzing log file..

No suspicious activity detected.

PS C:\Users\Local Admin\Desktop\LogAl> py log_analyzer.py Log_Failed.txt
Analyzing log file..

Suspicious activity read from 192.168.1.45 with 3 failed login attempts
Suspicious activity read from 192.168.1.99 with 3 failed login attempts
