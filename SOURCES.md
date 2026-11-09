# Alert Sources & Reference Documentation

This document records the standard event logs, security frameworks, and audit trail sources used to construct the 12 labeled alerts in `my_alerts.json`.

---

## 1. Primary Security Log Frameworks

* **Microsoft Windows Security Event Logs**
  * **Event ID 4688 (Process Creation):** Used for process execution scenarios (e.g., command-line logging, suspicious process spawns, system maintenance tasks).
  * **Event ID 4624 / 4625 (Logon Success / Failure):** Used for authentication tracking, privileged account logins, and brute-force simulation.
  * **Reference:** [Microsoft Security Auditing Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)

* **EDR & Endpoint Detection Signals (MITRE ATT&CK)**
  * **T1003.001 (OS Credential Dumping - Mimikatz):** Inspired LSASS memory read detections and execution alerts.
  * **T1059.001 (Command and Scripting Interpreter - PowerShell):** Inspired encoded command execution (`powershell -enc`) detections.
  * **T1071.001 (Application Layer Protocol - C2):** Inspired non-standard port outbound network traffic alerts.
  * **Reference:** [MITRE ATT&CK Matrix for Enterprise](https://attack.mitre.org/)

* **Cloud Audit Logs (AWS CloudTrail & Azure Activity Logs)**
  * **AWS CloudTrail `CreateAccessKey` / `ConsoleLogin`:** Used for cloud privilege escalation and unexpected administrative access patterns.
  * **Reference:** [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/)

---

## 2. Benchmark Case Justifications (Hard Cases)

* **Hard Case 1 (Missed Incident / Stealth Attack):**
  * *Alert Scenario:* Low-frequency lateral movement or legitimate utility abuse (Living off the Land / LotL) that lacks explicit malicious keywords like `mimikatz`.
  * *Justification:* Demonstrates why rule-based keyword matching fails against stealthy attacker techniques.

* **Hard Case 2 (Routine Alert / Noise with Keyword Match):**
  * *Alert Scenario:* Authorized backup or administrative script executing a command containing a keyword (e.g., `root` in a directory path or `powershell` in an IT deployment job).
  * *Justification:* Demonstrates how static keyword detection leads to false positives and analyst alert fatigue.