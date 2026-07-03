Markdown
# 🛡️ SIEM Detection Engineering: Splunk SPL to Microsoft Sentinel KQL (Phase 1)

## 📌 Executive Summary
As enterprise security operations migrate from legacy on-premise solutions to cloud-native infrastructure, the ability to translate detection logic across platforms is critical. This project (Phase 1) demonstrates a cross-platform threat hunt, translating a custom Splunk SPL password spray detection query directly into Microsoft Sentinel KQL. 

By engineering synthetic authentication telemetry and executing mathematical aggregations across both platforms, this repository proves parity in detection capabilities while implementing cost-optimized cloud ingestion strategies.

## 🏗️ Architecture & Cloud Cost Optimization
A major challenge in cloud-native SIEM deployments is the compute and storage overhead associated with high-volume telemetry ingestion. 

Instead of deploying full Data Collection Rules (DCRs) or provisioning dedicated Azure Monitor Agents (AMA) for this tactical hunt, I utilized **Microsoft Sentinel Watchlists (`_GetWatchlist`)**. 
* **Impact:** This strategy allowed for the rapid staging of raw CSV telemetry directly into the Azure cloud, entirely bypassing unnecessary infrastructure overhead and significantly reducing the compute costs associated with point-in-time threat hunts.

## 🔬 Detection Logic Translation
The objective of this phase was to identify a threat actor executing a password spray attack. The logic filters for failed authentication events and aggregates the distinct count of targeted accounts grouped by the adversary's source IP.

### Splunk (SPL)
In Splunk, the aggregation relies on `stats dc()` to calculate the distinct count and `values()` to bundle the targeted usernames into a readable array.
spl
index="main" action="Failed"
| stats dc(username) as distinct_accounts, values(username) as targeted_users by source_ip

<img width="958" height="476" alt="Screenshot 2026-07-02 181743" src="https://github.com/user-attachments/assets/34782165-e321-45a3-8a60-75e0adf67c8a" />



Microsoft Sentinel (KQL)
To achieve mathematical and operational parity in Microsoft Sentinel, the logic queries the Watchlist alias and maps the SPL aggregations to KQL native scalar functions (dcount and make_set). Case-insensitive string matching (=~) was applied to ensure robust parsing.

<img width="959" height="476" alt="Screenshot 2026-07-03 040104" src="https://github.com/user-attachments/assets/0ad488c7-3f35-44c3-ad4d-9c1581c30e2d" />

Code snippet
_GetWatchlist("AuthEvents") 
| where action =~ "failed"
| summarize distinct_accounts = dcount(username), targeted_users = make_set(username) by source_ip

📊 Execution & Threat Hunt Results
Both SIEM platforms successfully processed the 1,500 synthetic events, matched the exact mathematical logic, and isolated the identical Indicators of Compromise (IoCs).

Adversary IP: 185.22.44.10

Action: The query successfully generated a distinct array of all targeted employee usernames for immediate incident response and account remediation.

