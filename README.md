# SSH Brute-Force Detector

A small SOC log-analysis tool that scans Linux SSH authentication logs
(`/var/log/auth.log`) for brute-force login attempts and flags suspicious
source IPs.

Built as a lightweight, dependency-free detection script — the kind of
repetitive log-triage task a SOC analyst automates instead of doing by hand.

**MITRE ATT&CK:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)

## What it does

- Parses SSH `Failed password` and `Accepted` events from an auth log.
- Counts failed attempts per source IP and flags any IP that meets or
  exceeds a configurable threshold (default: 5).
- **Escalates to CRITICAL** when a *successful* login follows repeated
  failures from the same IP — a possible successful brute force / account
  compromise that needs immediate investigation.
- Prints a clean, alert-style report and can optionally export findings as
  JSON for ticketing, SIEM ingestion, or further automation.

## Usage

```bash
# Run against the included sample log
python brute_force_detector.py sample_auth.log

# Run against a real log with a stricter threshold
python brute_force_detector.py /var/log/auth.log --threshold 10

# Export findings to JSON as well
python brute_force_detector.py sample_auth.log --json report.json
```

No external dependencies — just Python 3.8+.

The script exits with code `1` when anything is flagged and `0` when the log
is clean, so it can be dropped straight into a cron job or CI pipeline.

## Example output

```
======================================================================
  SSH BRUTE-FORCE DETECTION REPORT
  MITRE ATT&CK: T1110 (Brute Force)
======================================================================
  Source file        : sample_auth.log
  Lines scanned      : 30
  Failed logins      : 24
  Successful logins  : 6
  Alert threshold    : 5 failed attempts per IP
  Suspicious IPs      : 3
----------------------------------------------------------------------
[!!] CRITICAL  198.51.100.23
        Failed attempts   : 6
        Successful logins : 1
        Usernames targeted: root
        First seen        : Mar 10 14:20:40
        Last seen         : Mar 10 14:20:55
        >> Successful login AFTER repeated failures -- possible account compromise. Investigate immediately.
----------------------------------------------------------------------
[ ! ] HIGH      203.0.113.66
        Failed attempts   : 10
        Successful logins : 0
        Usernames targeted: admin, ftpuser, git, oracle, postgres, root, test, ubuntu
...
```

## Detection logic

| Severity   | Condition                                                        |
|------------|------------------------------------------------------------------|
| `CRITICAL` | A successful login from an IP that already had ≥ threshold fails |
| `HIGH`     | Failed attempts ≥ threshold, no successful login                 |
| (ignored)  | Below threshold — e.g. a real user mistyping their password once |

The included `sample_auth.log` mixes benign traffic (normal users, one mistyped
password) with three attacker patterns so you can see the detector separate
real activity from noise. All IPs use the reserved documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` — RFC 5737).

## Limitations & possible next steps

This is intentionally simple. Realistic extensions a SOC analyst might add:

- **Time-window / rate awareness** — flag *X failures in Y seconds* rather than
  a raw count, to catch slow "low-and-slow" attacks differently from fast ones.
- **IP enrichment** — look up flagged IPs against a threat-intel source
  (e.g. AbuseIPDB) before raising the alert.
- **IPv6 support** — the current parser handles IPv4 source addresses.
- **Scheduled automation** — run on a cron or GitHub Actions schedule and post
  findings to Slack / e-mail / a SIEM.
