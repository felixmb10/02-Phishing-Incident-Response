# Incident Response Record



## Case Information



- Case ID: INC-2026-0027

- Endpoint: SOC-WINDOWS

- Endpoint IP: 192.168.121.137

- User: SOC-WINDOWS\\felix

- Incident Type: Simulated phishing / suspicious PowerShell execution

- Status: Contained and recovered



## 1. Identification and Triage



A simulated phishing message was analyzed for suspicious sender information, authentication failures, URL characteristics, and other indicators.



The controlled attachment, `Account-Review.ps1`, was analyzed before execution.



SHA-256:



1087AF513037D27B5277EC6EA36A6E326F012D75D7EF4427CCC9CE37E03E6083



The attachment was then executed on the monitored SOC-WINDOWS endpoint in the controlled lab.



Sysmon Event ID 1 recorded PowerShell execution with the following command:



powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\Account-Review.ps1



Sysmon also recorded `whoami.exe` as a child of the PowerShell process.



## 2. Detection and Investigation



Sysmon recorded the PowerShell process as PID 8288 under the user SOC-WINDOWS\\felix with Medium integrity.



The PowerShell process spawned `whoami.exe`, demonstrating system owner/user discovery.



Wazuh received the Sysmon telemetry and generated:



- Rule ID: 92029

- Rule Level: 6

- Description: Powershell executed script from suspicious location

- MITRE mapping: T1059.001 - PowerShell



A field-specific Wazuh hunt using the command-line field successfully identified the execution of `Account-Review.ps1`.



No evidence was observed during this exercise of credential theft, persistence, privilege escalation, lateral movement, command-and-control communication, or data exfiltration.



## 3. Scope



Observed activity was limited to the controlled SOC-WINDOWS endpoint.



The script:



- Executed through Windows PowerShell

- Queried the current user

- Queried the computer hostname

- Obtained the current time

- Created a harmless temporary text file



The sandbox analysis reported no HTTP requests, network connections, or network threats associated with the PowerShell process.



## 4. Containment and Eradication



Evidence was preserved before removal.



The original PowerShell artifact was verified using SHA-256 before eradication.



The following artifacts were removed:



C:\\Users\\Public\\Account-Review.ps1



C:\\Users\\felix\\AppData\\Local\\Temp\\account-review-lab.txt



`Test-Path` was used after removal and returned `False` for both artifacts.



Because no malicious network communication was observed and this was a controlled lab endpoint, network isolation was not performed.



## 5. Recovery



Endpoint monitoring services were verified after eradication:



- Sysmon64: Running / Automatic

- WazuhSvc: Running / Automatic



SOC-WINDOWS retained:



- IPv4 address: 192.168.121.137

- Default gateway: 192.168.121.2



The current Wazuh manager address was identified as 192.168.121.10.



Connectivity from SOC-WINDOWS to the Wazuh manager on TCP port 1514 was tested successfully.


Post-eradication recovery verification was preserved in:

`07-Evidence/investigation-output/project02-recovery-verification.txt`


The endpoint remained operational and monitored following eradication.



## 6. Detection Improvement

The investigation moved beyond responding to the observed activity by developing additional detection logic.

A custom Wazuh rule, ID `100200`, was created to detect Windows PowerShell processes using the `-ExecutionPolicy Bypass` argument.

The Wazuh configuration passed validation, and a fresh controlled PowerShell test successfully triggered custom rule `100200` at level 10.

The live rule was exported from the Wazuh manager and preserved in:

`05-Detection/wazuh-rules/project02-wazuh-rule-100200.xml`

A vendor-neutral Sigma process-creation rule was also created:

`05-Detection/sigma/powershell-execution-policy-bypass.yml`

Sigma CLI validation returned:

- 0 errors
- 0 condition errors
- 0 validation issues

These detections should be tuned in a production environment because `ExecutionPolicy Bypass` can also occur during legitimate administrative or automation activity.



## 7. Lessons Learned



The exercise demonstrated the importance of correlating endpoint telemetry with SIEM data instead of relying only on broad keyword searches.



Initial free-text searches in Wazuh produced misleading or unrelated results. Querying the structured `data.win.eventdata.commandLine` field provided precise evidence of the PowerShell execution.



The investigation also demonstrated the value of preserving hashes, timestamps, process relationships, command lines, and artifacts before performing eradication.



## Final Assessment



The controlled phishing exercise successfully demonstrated the investigation of a suspicious PowerShell attachment from initial email analysis through endpoint detection, SIEM correlation, eradication, and recovery.



The observed behavior was limited to the intended safe simulation, and no evidence of additional compromise was identified during the exercise.



