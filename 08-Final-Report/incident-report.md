# Phishing Incident Response Report



## Executive Summary



A controlled phishing incident was investigated in the Northstar Regional Services lab environment.



The exercise used a simulated Microsoft 365 security email, a defanged account-verification link, and an associated controlled PowerShell attachment.


The attachment, `Account-Review.ps1`, was safely executed on the monitored Windows endpoint `SOC-WINDOWS`.



Sysmon captured the PowerShell execution and subsequent user-discovery activity. Wazuh correlated the endpoint telemetry and generated rule 92029, a level 6 alert for PowerShell executing a script from a suspicious location.



The artifacts were preserved and verified before removal. Recovery checks confirmed that endpoint monitoring remained operational.



A custom Wazuh detection rule was subsequently developed and successfully tested for PowerShell execution using `-ExecutionPolicy Bypass`.



No evidence of credential theft, persistence, privilege escalation, lateral movement, command-and-control communication, or data exfiltration was observed during the controlled exercise.



## Incident Information



- Case ID: INC-2026-0027

- Environment: Northstar Regional Services cybersecurity lab

- Endpoint: SOC-WINDOWS

- Endpoint IP: 192.168.121.137

- User: SOC-WINDOWS\\felix

- SIEM: Wazuh

- Endpoint telemetry: Sysmon

- Incident type: Simulated phishing / suspicious PowerShell execution



## Phishing Analysis



The simulated message impersonated Microsoft 365 security and attempted to create urgency around an alleged unusual sign-in.



Observed indicators included:



- Typosquatted `micros0ft` sender domain

- Sender and URL domain mismatch

- Return-Path inconsistency

- SPF failure

- DMARC failure

- No DKIM authentication

- Urgent account-verification language



The phishing URL was safely defanged during analysis and used the reserved `.example` domain.



## Indicators



Key indicators extracted from the exercise included:



- `security@micros0ft-support.example`

- `account-review@micros0ft-support.example`

- `micros0ft-support.example`

- `login-microsoft365-security.example`

- `mailer-notification.example`

- `203.0.113.77`

- `198.51.100.27`

- `hxxps://login-microsoft365-security.example/account/verify`



The domains and IP addresses were controlled documentation indicators and were not treated as independently confirmed malicious infrastructure.



## Attachment Analysis



Artifact:



`Account-Review.ps1`



SHA-256:



`1087AF513037D27B5277EC6EA36A6E326F012D75D7EF4427CCC9CE37E03E6083`



Static analysis determined that the script performed a small number of controlled actions, including:



- Current-user discovery

- Hostname discovery

- Time retrieval

- Creation of a harmless temporary text file



The script contained no downloader, credential collection, persistence mechanism, or external network connection.



## Sandbox Analysis



The attachment was executed in a controlled sandbox.



Observed behavior included:



- `powershell.exe`

- `whoami.exe`

- `HOSTNAME.EXE`

- Creation of `account-review-lab.txt`

- No HTTP requests associated with the PowerShell process

- No network connections associated with the PowerShell process

- No network threats detected



The sandbox results were consistent with the expected behavior identified during static analysis.



## Endpoint Investigation



The attachment was executed on `SOC-WINDOWS` using:



`powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\Account-Review.ps1`



Sysmon Event ID 1 recorded:



- PowerShell PID: 8288

- User: SOC-WINDOWS\\felix

- Integrity level: Medium

- Full command line

- Parent process information

- Process hashes

- Process GUID

- Child execution of `whoami.exe`



The `whoami.exe` process was directly correlated with PowerShell through its parent process information.



## SIEM Investigation



Wazuh successfully ingested the Sysmon Process Create telemetry.



A structured hunt using:



`data.win.eventdata.commandLine : *Account-Review.ps1*`



returned the corresponding execution.



Wazuh generated:



- Rule ID: 92029

- Level: 6

- Description: Powershell executed script from suspicious location

- MITRE ATT&CK: T1059.001 - PowerShell



Broad free-text searches initially produced misleading results. Structured field searches provided more precise correlation.



## MITRE ATT&CK Mapping



### T1059.001 - PowerShell



Observed evidence:



PowerShell executed the controlled attachment using `-ExecutionPolicy Bypass`.



Tactic:



Execution



### T1033 - System Owner/User Discovery



Observed evidence:



The PowerShell process spawned `whoami.exe`, which identified the current user as `SOC-WINDOWS\\felix`.



Tactic:



Discovery



No additional ATT&CK techniques are claimed without supporting evidence.



## Incident Response



### Identification



The phishing artifact was identified through email, header, URL, attachment, endpoint, and SIEM analysis.



### Investigation



Sysmon and Wazuh telemetry were correlated to establish the process execution chain.



### Evidence Preservation



The original attachment SHA-256 was verified before eradication.



The generated temporary artifact was examined before removal.



### Eradication



The following artifacts were removed:



`C:\\Users\\Public\\Account-Review.ps1`



`C:\\Users\\felix\\AppData\\Local\\Temp\\account-review-lab.txt`



Post-removal verification returned `False` for both paths.



### Recovery



The following monitoring services remained operational:



- Sysmon64: Running / Automatic

- WazuhSvc: Running / Automatic



The Wazuh manager was identified at:



`192.168.121.10`



Connectivity from `SOC-WINDOWS` to TCP port 1514 succeeded.


Post-eradication verification confirmed that both controlled artifacts remained absent, Sysmon64 and WazuhSvc were running with Automatic startup, and `SOC-WINDOWS` (`192.168.121.137`) could reach the Wazuh manager on TCP/1514.

The verification output is preserved in:

`07-Evidence/investigation-output/project02-recovery-verification.txt`



## Detection Engineering



A custom Wazuh rule was developed to identify PowerShell execution containing:



`-ExecutionPolicy Bypass`



Custom detection:



- Rule ID: 100200

- Level: 10

- Description: CUSTOM SOC: PowerShell executed with ExecutionPolicy Bypass

- MITRE ATT&CK: T1059.001



The rule configuration was validated before deployment.



A controlled PowerShell execution was then generated on `SOC-WINDOWS`.



Wazuh successfully triggered custom rule 100200, confirming that the detection worked as intended.



A vendor-neutral Sigma rule was also developed:

`05-Detection/sigma/powershell-execution-policy-bypass.yml`

The rule detects Windows PowerShell process creation containing `ExecutionPolicy Bypass`, including observed command-line variants.

Sigma CLI was used to validate the rule. Validation returned:

- 0 errors
- 0 condition errors
- 0 validation issues

The validation output is preserved in:

`07-Evidence/investigation-output/sigma-rule-validation.txt`

Both detections require appropriate tuning in production because `ExecutionPolicy Bypass` can also be used by legitimate administrative and automation activity.




## Lessons Learned



This exercise demonstrated the importance of correlating multiple evidence sources rather than relying on a single alert.



Sysmon provided detailed process-level evidence, while Wazuh provided centralized detection and investigation capabilities.



Structured SIEM searches proved substantially more useful than broad keyword searches.



The exercise also reinforced the importance of preserving hashes, timestamps, command lines, process relationships, and artifacts before eradication.



Finally, detection engineering extended the investigation beyond alert review by converting an observed suspicious execution characteristic into a tested custom detection.



## Conclusion



The controlled exercise demonstrated an end-to-end SOC investigation:



Phishing Email -> Header Analysis -> URL Analysis -> Attachment Analysis -> Sandbox Analysis -> IOC Analysis -> Endpoint Investigation -> Sysmon -> Wazuh -> Incident Response -> Detection Engineering



The investigation remained evidence-driven throughout the technical execution phase. Observed activity was successfully detected, investigated, eradicated, and followed by recovery validation and custom detection development.



