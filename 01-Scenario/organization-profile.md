# Northstar Regional Services - Organization Profile

## Organization Overview

Northstar Regional Services is a fictional organization created for the SOC Analyst Hands-On Project.

The organization provides the business context for the phishing incident-response scenario. Technical findings in this project are based on activity performed in the actual isolated lab environment rather than assumed capabilities of the fictional organization.

## Lab Environment

| Component | Details |
|---|---|
| Virtualization | VMware Workstation |
| Endpoint | SOC-WINDOWS |
| Endpoint OS | Windows 11 |
| Endpoint IP | 192.168.121.137 |
| Endpoint Telemetry | Sysmon |
| SIEM Agent | Wazuh Agent |
| SIEM Manager | soc-wazuh-server |
| SIEM Manager IP | 192.168.121.10 |
| Lab Network | 192.168.121.0/24 |
| Environment Type | Isolated virtualized cybersecurity lab |

## Monitored Endpoint

### SOC-WINDOWS

`SOC-WINDOWS` serves as the monitored Windows endpoint for the phishing investigation.

The endpoint is configured with:

- Windows 11
- Sysmon
- Wazuh Agent
- PowerShell
- Access to the isolated lab network

During the controlled exercise, the phishing attachment was reproduced on this endpoint, hash-verified, executed, investigated, and later removed.

Sysmon captured process-creation telemetry and the Wazuh agent forwarded relevant telemetry to the Wazuh manager.

## SIEM Server

### soc-wazuh-server

The Linux-based `soc-wazuh-server` provides centralized security monitoring for the lab.

Observed configuration relevant to this project includes:

- Wazuh Manager
- Wazuh rule processing
- Windows endpoint telemetry ingestion
- Custom detection rules
- Alert investigation through the Wazuh dashboard

The server used IP address:

`192.168.121.10`

Connectivity from `SOC-WINDOWS` to the Wazuh manager on TCP port 1514 was verified during recovery.

## Security Monitoring

The controls directly used and verified during this exercise were:

- Sysmon process telemetry
- Wazuh endpoint agent
- Wazuh SIEM
- Wazuh built-in detection rules
- Custom Wazuh detection rule
- Windows event logging
- PowerShell-based investigation
- Sigma rule validation

Other enterprise security technologies may exist in a real organization, but they are not assumed to have been deployed or tested in this lab.

## Roles

### Simulated Employee

The phishing email represents a message delivered to a fictional Northstar employee.

No real employee was targeted, and the project does not claim that credentials were actually entered or compromised.

### SOC Analyst

The analyst performs the hands-on investigation by:

- Reviewing the phishing artifact
- Analyzing email headers
- Extracting and validating IOC candidates
- Performing static and dynamic attachment analysis
- Investigating Sysmon telemetry
- Hunting activity in Wazuh
- Preserving evidence
- Performing controlled eradication and recovery checks
- Developing additional detection logic

## Network

The lab network used during the investigation was:

```text
192.168.121.0/24

SOC-WINDOWS
192.168.121.137
        |
        | Sysmon + Wazuh Agent
        |
        v
soc-wazuh-server
192.168.121.10
