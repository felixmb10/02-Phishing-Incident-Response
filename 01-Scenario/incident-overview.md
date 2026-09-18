# Incident Overview



## Case Information



| Field | Details |

|---|---|

| Case ID | INC-2026-0027 |

| Organization | Northstar Regional Services |

| Exercise Type | Controlled Phishing Incident Response Lab |

| Incident Type | Simulated Phishing / Suspicious PowerShell Execution |

| Status | Investigation Completed |

| Lab Endpoint | SOC-WINDOWS |

| Endpoint IP | 192.168.121.137 |

| SIEM | Wazuh |

| Endpoint Telemetry | Sysmon |



## Scenario



Northstar Regional Services is a fictional organization used for this controlled SOC investigation.



A simulated Microsoft 365 security email was created as the initial phishing artifact. The message contained suspicious sender information, urgency language, a defanged account-verification URL, and a controlled PowerShell attachment named `Account-Review.ps1`.



The email, domains, IP addresses, URL, and attachment were created or selected specifically for a safe cybersecurity lab. No real user was phished and no real malicious infrastructure was contacted.



The analyst's task was to determine what could be established from the available artifacts and then safely reproduce observable endpoint behavior in a monitored environment.



## Investigation Workflow



The investigation followed this workflow:



1\. Review the simulated phishing email.

2\. Analyze email headers and authentication results.

3\. Extract and validate candidate IOCs.

4\. Analyze the defanged URL safely.

5\. Perform static analysis of the PowerShell attachment.

6\. Execute the controlled attachment in a sandbox.

7\. Verify the attachment hash before endpoint testing.

8\. Execute the attachment on the monitored `SOC-WINDOWS` lab endpoint.

9\. Investigate Sysmon process telemetry.

10\. Correlate the activity in Wazuh.

11\. Preserve relevant evidence.

12\. Remove the controlled endpoint artifacts.

13\. Verify endpoint monitoring and SIEM connectivity.

14\. Develop and test an additional Wazuh detection.

15\. Create and validate a vendor-neutral Sigma detection.



## Investigation Objectives



The investigation was designed to determine:



- Which characteristics made the email suspicious.

- What email addresses, domains, IP addresses, URLs, and file hashes could be extracted.

- Which extracted values represented useful indicators versus context or false positives.

- What behavior the controlled PowerShell attachment contained.

- What behavior occurred during sandbox execution.

- What endpoint telemetry Sysmon generated during controlled execution.

- Whether Wazuh received and detected the activity.

- Which observed behaviors could be mapped to MITRE ATT&CK.

- What evidence should be preserved before eradication.

- Whether a custom detection could identify similar PowerShell behavior.



## Evidence Sources



Evidence collected during the exercise includes:



- Simulated phishing email

- Simulated email headers

- PowerShell-based header and IOC extraction output

- Controlled PowerShell attachment

- SHA-256 file hashes

- Static-analysis output

- Sandbox process and file activity

- Sysmon Event ID 1 telemetry

- Native Sysmon EVTX log

- Wazuh alerts and structured SIEM searches

- Custom Wazuh rule

- Sigma rule and validation output

- Incident-response verification commands

- Screenshots captured during analysis



## Scope



The technical execution phase was limited to the controlled `SOC-WINDOWS` endpoint and the Wazuh lab environment.



The exercise did not simulate or establish actual credential theft, unauthorized account access, persistence, privilege escalation, lateral movement, command-and-control communication, or data exfiltration.



Any conclusions in the investigation are based on observed lab evidence rather than assumptions from the phishing scenario.



## Expected Outcome



The project is intended to demonstrate an evidence-driven SOC workflow from phishing triage through endpoint investigation, SIEM correlation, incident response, and detection engineering.



All potentially malicious behavior is simulated or controlled for educational purposes. No real malware is intentionally deployed and no real users are targeted.



