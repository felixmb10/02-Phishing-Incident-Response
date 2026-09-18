# Incident Timeline



## Case



INC-2026-0027 - Simulated Phishing Investigation



> Times below are based on observed lab evidence. Endpoint-local and UTC timestamps are preserved where available.



| Time | Source | Event |

|---|---|---|

| 21:00:21 | SOC-WINDOWS | Analyst recorded system time immediately before controlled attachment execution. |

| 21:00:26 | Sysmon Event ID 1 | `powershell.exe` executed `C:\\Users\\Public\\Account-Review.ps1` using `-NoProfile -ExecutionPolicy Bypass`. Process ID: 8288. User: `SOC-WINDOWS\\felix`. |

| 21:00:26 / 04:00:26 UTC | Sysmon / Wazuh | PowerShell execution telemetry was recorded. Sysmon tagged the activity as `T1059.001 - PowerShell`. |

| 21:00:30 | Script output | `Account-Review.ps1` reported the user as `SOC-WINDOWS\\felix`, computer as `SOC-WINDOWS`, and creation of the temporary lab artifact. |

| 21:00:30 | Sysmon Event ID 1 | `whoami.exe` executed as a child of PowerShell PID 8288. Sysmon tagged the activity as System Owner/User Discovery. |

| 21:00:30 | File examination | `account-review-lab.txt` was later confirmed to exist with a creation time of 21:00:30 and a size of 72 bytes. |

| Investigation | Wazuh | Structured hunting on `data.win.eventdata.commandLine` located the original `Account-Review.ps1` execution. |

| Investigation | Wazuh | Built-in rule `92029`, level 6, detected PowerShell executing a script from a suspicious location. |

| Response | SOC-WINDOWS | SHA-256 of `Account-Review.ps1` was reverified as `1087AF513037D27B5277EC6EA36A6E326F012D75D7EF4427CCC9CE37E03E6083` before eradication. |

| Eradication | SOC-WINDOWS | `Account-Review.ps1` and `%TEMP%\\account-review-lab.txt` were removed. |

| Verification | SOC-WINDOWS | `Test-Path` returned `False` for both removed artifacts. |

| Recovery | SOC-WINDOWS | Sysmon64 and WazuhSvc were verified Running with Automatic startup. |

| Recovery | Network | Wazuh manager was identified at `192.168.121.10`. Connectivity from `SOC-WINDOWS` (`192.168.121.137`) to TCP/1514 succeeded. |

| Detection Engineering | Wazuh | Custom rule `100200` was created to detect PowerShell using `-ExecutionPolicy Bypass`. |

| Validation | Wazuh | Custom rule configuration passed validation with exit status `0`; Wazuh manager restarted successfully. |

| Detection Test | SOC-WINDOWS / Wazuh | Controlled PowerShell test triggered custom rule `100200` at level 10. |

| Detection Engineering | Sigma | Created vendor-neutral process-creation rule `powershell-execution-policy-bypass.yml` to detect PowerShell launched with ExecutionPolicy Bypass. |

| Validation | Sigma CLI | Sigma rule passed validation with 0 errors, 0 condition errors, and 0 validation issues. |


## Timeline Assessment



The timeline establishes an evidence-backed chain from controlled attachment execution through endpoint telemetry, SIEM detection, investigation, eradication, recovery, and detection engineering.



No observed evidence during the exercise established credential theft, persistence, privilege escalation, lateral movement, command-and-control activity, or data exfiltration.



