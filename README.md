# Cross-SIEM Detection Engineering Lab: Password Spray to Valid Login

**Author:** Fahmid Zaman
**Role Target:** SOC Analyst / Cybersecurity Analyst / Junior Detection Engineer
       
**Tech Stack:** Python, Splunk SPL, Microsoft Sentinel KQL, Sigma, Windows Authentication Logs
---

## Project Summary

This project is a detection-as-code lab that simulates a password spraying attack against Windows authentication logs and validates a successful login from the same attacker source IP.

The lab includes Python-generated telemetry, Splunk SPL, Microsoft Sentinel KQL, a Sigma rule, Python validation logic, a SOC incident report, and false-positive tuning documentation.

---

## Quantified Results

| Metric                                |                                             Result |
| ------------------------------------- | -------------------------------------------------: |
| Total authentication events generated |                                            `1,500` |
| Attacker source IP                    |                                     `185.22.44.10` |
| Attack failed-login events            |                                               `25` |
| Attack successful-login events        |                                                `1` |
| Compromised account                   |                                          `ntaylor` |
| Detection threshold                   | `>5 distinct failed usernames from same source IP` |
| Normal successful-login noise         |                                            `1,407` |
| Service-account failure noise         |                                               `30` |
| Slow repeated-failure noise           |                                               `24` |
| Application/server failure noise      |                                                `8` |
| Low-volume failed-then-success noise  |                           `4 failures + 1 success` |
| Python validation result              |                            `1 high-priority alert` |

---

## Attack Scenario

An external source IP performs failed login attempts across multiple usernames. After exceeding the failed-account threshold, the same source IP successfully authenticates as `ntaylor`.

| MITRE ATT&CK Technique | Description       |
| ---------------------- | ----------------- |
| `T1110.003`            | Password Spraying |
| `T1078`                | Valid Accounts    |

| Event ID | Meaning          |
| -------: | ---------------- |
|   `4625` | Failed logon     |
|   `4624` | Successful logon |

---

## Dataset Generation

Generate the dataset:

```bash
python scripts/generate_auth_events.py
```

Output:

```text
data/auth_events.csv
```

CSV schema:

```text
time_stamp, username, source_ip, event_id, action
```

The generator creates exactly:

```text
25 attacker failed logins
1 attacker successful login
4 low-volume failed-login noise events
1 low-volume successful-login noise event
30 service-account-style failures
24 slow repeated failures
8 application/server-style failures
1,407 normal successful logins
```

For reproducibility, the generator uses a fixed seed and hardcoded compromised account:

```python
random.seed(42)
Faker.seed(42)
attacker_username = "ntaylor"
```

---

## Detection Objective

Identify a source IP with:

```text
>5 distinct failed usernames
AND
at least 1 successful login from the same source IP
```

The SPL and KQL queries identify candidate source IPs. The Python validator processes the CSV in timestamp order and alerts when a successful login occurs after the source IP has exceeded the failed-account threshold.

---

## Microsoft Sentinel KQL

For this MVP, the CSV dataset is queried as a Microsoft Sentinel Watchlist named `AuthEvents`. In a production Sentinel deployment, this logic would typically target authentication tables such as `SecurityEvent` or identity sign-in tables instead of using a watchlist.

```kql
let Failedlogins =
_GetWatchlist("AuthEvents")
| where action == "Failed"
| summarize 
    FailedAccountcount = dcount(username),
    FailedAccounts = make_set(username)
    by source_ip
| where FailedAccountcount > 5;

_GetWatchlist("AuthEvents")
| where action == "Success"
| join kind=inner (Failedlogins) on source_ip
```

This identifies source IPs with more than 5 distinct failed usernames and at least one successful login.

---

## Splunk SPL

```spl
source="auth_events.csv" host="WinServer-DC01" sourcetype="csv"
| dedup _raw
| stats 
    dc(eval(if(action == "Failed", username, null()))) as Failedcounts,
    dc(eval(if(action == "Success", username, null()))) as Successcounts
    by source_ip
| where Failedcounts > 5 and Successcounts > 0
```

This identifies the same candidate behavior in Splunk: multiple distinct failed usernames and at least one successful login from the same source IP.

---

## Python Validation

Run the validator:

```bash
python scripts/validate_detections.py
```

The validator tracks failed usernames by source IP using a Python dictionary. When a successful login occurs, it checks whether that source IP already exceeded the failed-account threshold.

Expected output:

```text
[CRITICAL] Potential Account Compromise: IP 185.22.44.10 authenticated as ntaylor following excessive failed attempts.
```

---

## Sigma Rule

A Sigma rule is included at:

```text
detections/password_spray_sigma.yml
```

The Sigma rule captures the vendor-neutral password spray pattern. SPL, KQL, and Python validation demonstrate how the logic can be adapted across platforms.

---

## SOC Documentation

Included documentation:

```text
docs/incident_report.md
docs/false_positive_tuning.md
```

The incident report covers evidence, IoCs, MITRE mapping, containment, recovery, and follow-up investigation.

The false-positive tuning guide covers VPN/NAT gateways, service accounts, vulnerability scanners, password reset noise, and threshold tuning.

Key tuning principle:

```text
Suppress noisy failed-login-only patterns carefully, but do not suppress cases where the same source IP later produces a successful login.
```

---

## Limitations

This is an MVP detection engineering lab, not a production SIEM deployment.

Current limitations:

* dataset is simulated
* SPL and KQL identify candidate source IPs but do not yet enforce a time window
* Python validation handles event-order logic locally
* live Splunk and Sentinel ingestion are optional Phase 2 steps
* MFA, endpoint, VPN, and cloud identity logs are not included yet
* no automated containment action is executed

---

## Future Improvements

Planned improvements:

* add time-windowed SPL and KQL correlation
* add `expected_findings.json`
* add GitHub Actions validation
* add local Splunk screenshots
* ingest the dataset into Microsoft Sentinel Log Analytics
* add MFA and conditional access events
* add additional identity attack scenarios
* build optional Entra ID SOAR response logic

