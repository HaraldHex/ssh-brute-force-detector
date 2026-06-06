#!/usr/bin/env python3
"""
brute_force_detector.py

A simple SOC log-analysis tool that scans Linux SSH authentication logs
(/var/log/auth.log style) for brute-force login attempts.

MITRE ATT&CK mapping: T1110 - Brute Force

Detection logic
---------------
  * Counts failed SSH password attempts per source IP.
  * Flags any source IP whose failed-attempt count meets or exceeds a
    configurable threshold (default: 5).
  * Escalates severity to CRITICAL when a SUCCESSFUL login from the same IP
    occurs after those failures - a possible successful brute force /
    account compromise.

Usage
-----
  python brute_force_detector.py sample_auth.log
  python brute_force_detector.py /var/log/auth.log --threshold 10
  python brute_force_detector.py sample_auth.log --json report.json
"""

import argparse
import json
import re
import sys
from collections import OrderedDict

# --- Log line patterns ------------------------------------------------------
# Matches lines such as:
#   Mar 10 13:58:01 host sshd[1421]: Failed password for invalid user admin from 203.0.113.66 port 51000 ssh2
#   Mar 10 13:58:03 host sshd[1421]: Failed password for root from 198.51.100.23 port 40222 ssh2
FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Matches successful logins such as:
#   Mar 10 14:01:55 host sshd[1602]: Accepted password for deploy from 192.0.2.50 port 50122 ssh2
ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?sshd\[\d+\]:\s+"
    r"Accepted \S+ for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


class IPRecord:
    """Tracks authentication activity for a single source IP."""

    def __init__(self, ip):
        self.ip = ip
        self.failed = 0
        self.succeeded = 0
        self.users = set()
        self.first_seen = None
        self.last_seen = None
        # True if a successful login happened after >= threshold failures.
        self.success_after_brute_force = False

    def see(self, ts):
        if self.first_seen is None:
            self.first_seen = ts
        self.last_seen = ts


def analyze(lines, threshold):
    """Walk the log in order and build a per-IP picture of auth activity."""
    records = OrderedDict()
    total_failed = 0
    total_accepted = 0

    for line in lines:
        m = FAILED_RE.search(line)
        if m:
            ip = m.group("ip")
            rec = records.setdefault(ip, IPRecord(ip))
            rec.failed += 1
            rec.users.add(m.group("user"))
            rec.see(m.group("ts"))
            total_failed += 1
            continue

        m = ACCEPTED_RE.search(line)
        if m:
            ip = m.group("ip")
            rec = records.setdefault(ip, IPRecord(ip))
            # If this IP had already crossed the failure threshold before the
            # successful login, treat it as a likely successful brute force.
            if rec.failed >= threshold:
                rec.success_after_brute_force = True
            rec.succeeded += 1
            rec.users.add(m.group("user"))
            rec.see(m.group("ts"))
            total_accepted += 1

    return records, total_failed, total_accepted


def severity(rec, threshold):
    """Return (label, sort_rank) for a flagged record. Higher rank = worse."""
    if rec.success_after_brute_force:
        return "CRITICAL", 2
    if rec.failed >= threshold:
        return "HIGH", 1
    return "OK", 0


def build_findings(records, threshold):
    findings = []
    for rec in records.values():
        label, rank = severity(rec, threshold)
        if rank == 0:
            continue  # below threshold and no compromise - not an alert
        findings.append(
            {
                "ip": rec.ip,
                "severity": label,
                "failed_attempts": rec.failed,
                "successful_logins": rec.succeeded,
                "usernames_targeted": sorted(rec.users),
                "first_seen": rec.first_seen,
                "last_seen": rec.last_seen,
                "_rank": rank,
            }
        )
    # Worst first, then by number of failed attempts.
    findings.sort(key=lambda f: (f["_rank"], f["failed_attempts"]), reverse=True)
    for f in findings:
        del f["_rank"]
    return findings


def print_report(findings, total_lines, total_failed, total_accepted, threshold, source):
    print("=" * 70)
    print("  SSH BRUTE-FORCE DETECTION REPORT")
    print("  MITRE ATT&CK: T1110 (Brute Force)")
    print("=" * 70)
    print(f"  Source file        : {source}")
    print(f"  Lines scanned      : {total_lines}")
    print(f"  Failed logins      : {total_failed}")
    print(f"  Successful logins  : {total_accepted}")
    print(f"  Alert threshold    : {threshold} failed attempts per IP")
    print(f"  Suspicious IPs      : {len(findings)}")
    print("-" * 70)

    if not findings:
        print("  No source IPs crossed the alert threshold. Nothing to report.")
        print("=" * 70)
        return

    for f in findings:
        marker = "[!!] " if f["severity"] == "CRITICAL" else "[ ! ] "
        print(f"{marker}{f['severity']:<8}  {f['ip']}")
        print(f"        Failed attempts   : {f['failed_attempts']}")
        print(f"        Successful logins : {f['successful_logins']}")
        users = ", ".join(f["usernames_targeted"][:8])
        if len(f["usernames_targeted"]) > 8:
            users += f" (+{len(f['usernames_targeted']) - 8} more)"
        print(f"        Usernames targeted: {users}")
        print(f"        First seen        : {f['first_seen']}")
        print(f"        Last seen         : {f['last_seen']}")
        if f["severity"] == "CRITICAL":
            print("        >> Successful login AFTER repeated failures -- "
                  "possible account compromise. Investigate immediately.")
        print("-" * 70)
    print("=" * 70)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force attempts in a Linux auth log."
    )
    parser.add_argument("logfile", help="Path to the auth log (e.g. /var/log/auth.log)")
    parser.add_argument(
        "-t", "--threshold", type=int, default=5,
        help="Failed-attempt threshold per source IP (default: 5)",
    )
    parser.add_argument(
        "--json", metavar="FILE",
        help="Also write the findings to a JSON file",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        print(f"error: log file not found: {args.logfile}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: could not read {args.logfile}: {exc}", file=sys.stderr)
        return 2

    records, total_failed, total_accepted = analyze(lines, args.threshold)
    findings = build_findings(records, args.threshold)

    print_report(findings, len(lines), total_failed, total_accepted,
                 args.threshold, args.logfile)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"  JSON report written to {args.json}")

    # Exit code 1 if anything was flagged - handy for automation / CI pipelines.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
