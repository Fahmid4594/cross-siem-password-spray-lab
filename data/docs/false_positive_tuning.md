# False Positive Tuning & Detection Exclusions

## Overview
While this detection logic is effective for the simulated password-spray scenario, enterprise environments generate massive amounts of authentication noise. Implementing this rule in a production SIEM (such as Microsoft Sentinel or Splunk) without tuning will inevitably result in alert fatigue. 

The following scenarios detail common false positives and the recommended tuning strategies to filter them out before they reach the SOC floor.

### CRITICAL RULE: Never Suppress Success Correlation
Tuning should suppress noisy failed-login-only patterns, but it should **not** suppress cases where the same source IP later produces a successful login to a targeted account. If the full chain (Failures -> Success) is met, the alert must fire regardless of the source IP's categorization.

## Known False Positive Scenarios

### 1. Corporate VPNs and NAT Gateways
*   **The Issue:** Large numbers of remote employees routing through a single corporate VPN egress point or Network Address Translation (NAT) gateway will share a single public IP address. If multiple employees miskey their passwords simultaneously, the source IP will cross the threshold and trigger a password spray alert.
*   **The Fix:** Tag known VPN/NAT egress IPs (e.g., using Microsoft Sentinel Watchlists or Splunk Lookups) and apply separate thresholds or enrichment instead of blindly suppressing all activity. Blindly excluding these IPs can hide real attacks if a compromised internal host or a VPN-authenticated attacker causes the malicious activity.

### 2. Legacy Service Accounts & Automated Scripts
*   **The Issue:** Automated batch jobs, legacy applications, and scheduled tasks often rely on hardcoded credentials. If a service account password expires or is rotated, the automated script will fail to authenticate repeatedly at rapid intervals, mimicking an attacker's brute-force or spray behavior.
*   **The Fix:** Filter or separately route known service accounts such as `svc_`, `app_`, or machine accounts to a lower-severity IT operations dashboard. Do **not** automatically suppress privileged/admin accounts, as these are high-value targets that require strict security scrutiny.

### 3. Authorized Vulnerability Scanners
*   **The Issue:** Internal security teams running authenticated vulnerability scans (e.g., Qualys, Nessus) often attempt to validate default credentials across the network, generating hundreds of `Event ID 4625` (Failed Logon) logs from a single IP.
*   **The Fix:** Implement a strict exclusion for the dedicated IP ranges assigned to the security team's scanning infrastructure. 

### 4. Application Sync & Password Resets
*   **The Issue:** When a user changes their domain password, cached credentials on mobile devices (e.g., email sync clients) will continuously attempt to authenticate using the old password, generating rapid failures.
*   **The Fix:** Correlate `Event ID 4625` failures with recent password change/reset events such as `Event ID 4723` (user attempting to change their own password) or `4724` (attempt to reset another account's password), depending on the environment's identity workflow. If a failure burst immediately follows a password reset for the same user, suppress the alert for 60 minutes.

## Threshold Optimization
The current baseline threshold (`FailedCount > 25` and `DistinctUsers > 10` within a 15-minute window) is calibrated for this simulated dataset. In an enterprise environment, these thresholds must be baselined against a 30-day historical average of failed logons to ensure precision exceeds 80%.