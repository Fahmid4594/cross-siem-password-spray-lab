# SOC Incident Report: Valid Account Compromise via Password Spraying

## 1. Incident Summary
*   **Analyst:** Fahmid Zaman
*   **Date of Investigation:** July 2026
*   **Severity:** **HIGH** *(Pending escalation to CRITICAL if account is privileged or lateral movement is confirmed)*
*   **Incident Type:** Credential Access / Account Compromise

**Executive Overview:**
Routine correlation of authentication logs (Event IDs `4624` and `4625`) identified a systematic password spraying attack originating from an external IP address. The threat actor attempted to authenticate across 14 distinct user accounts, generating 38 failed login events. Eighteen minutes after the failed-login burst, the same source IP successfully authenticated as the user `ntaylor`. Immediate containment and remediation actions are required.

## 2. Indicators of Compromise (IoCs) & Evidence

### Known Indicators
| Indicator Type | Value | Context |
| :--- | :--- | :--- |
| **Attacker Source IP** | `185.22.44.10` | Source of both the failed burst and the successful login. |
| **Compromised Account** | `ntaylor` | Successfully authenticated following the spray attack. |
| **Targeted Accounts** | 14 Distinct Users | Number of unique accounts targeted in the spray attempt. |
| **Total Failures** | 38 Attempts | Number of `Event ID 4625` logs generated prior to success. |

### Evidence Timeline
| Time | Event | Evidence |
| :--- | :--- | :--- |
| **T0 – T+15m** | Password Spray Burst | 38 failed logins (`4625`) across 14 users from `185.22.44.10`. |
| **T+18m** | Successful Login | Successful authentication (`4624`) for `ntaylor` from the same source IP. |
| **T+18m onward** | Investigation Required | Pending review of endpoint, VPN, email, file access, and privilege activity. |

## 3. MITRE ATT&CK Mapping
*   **Tactic:** Credential Access (TA0006)
    *   **Technique:** Brute Force: Password Spraying (`T1110.003`)
*   **Tactic:** Defense Evasion, Persistence, Privilege Escalation, Initial Access (TA0005, TA0003, TA0004, TA0001)
    *   **Technique:** Valid Accounts: Domain Accounts (`T1078.002`)

## 4. Impact Assessment
The successful login from the same source IP indicates likely initial access using the `ntaylor` domain account. Because this is a valid user account, subsequent lateral movement or data exfiltration will blend in with normal business operations unless immediately contained. 

## 5. Remediation & Response Steps

### Immediate Containment
1.  **Revoke Tokens:** Immediately revoke all active session tokens for `ntaylor` across cloud and SSO environments (Azure AD / Entra ID) to sever any active connections.
2.  **Disable Account:** Temporarily lock or disable the `ntaylor` account in Active Directory to prevent re-authentication.
3.  **Block IP & Investigate Infrastructure:** Block the source IP (`185.22.44.10`) at the perimeter firewall as an immediate containment step, while reviewing related source IPs, VPN logs, ASN/geolocation, and any additional authentication attempts against the targeted accounts.

### Eradication & Recovery
4.  **Credential Rotation:** Force a password reset for the `ntaylor` account, ensuring the new password complies with the updated enterprise complexity policy.
5.  **Multi-Factor Authentication (MFA) Verification:** Verify the MFA status for `ntaylor` and investigate if an MFA fatigue attack (push spam) was utilized to bypass the prompt. Reset MFA methods if suspicious.

### Post-Incident Investigation
6.  **Scope Expansion:** Query SIEM logs for any subsequent actions (e.g., internal network connections, file access, privilege escalation attempts) executed by `ntaylor` *after* the successful login timestamp.
7.  **Target Review:** Review the 13 other accounts targeted in the spray attack to ensure no other accounts were compromised via a different IP address or delayed login.