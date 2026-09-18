# Initial Phishing Triage



## Case Information



| Field | Details |

|---|---|

| Case ID | INC-2026-0027 |

| Analyst | Felix Wa Muambi |

| Artifact | phishing-email.txt |

| Initial Classification | Suspicious - Possible Credential Phishing |

| Investigation Status | Escalated for Further Analysis |



## Initial Observations



I reviewed the reported email and identified several indicators that made the message suspicious.



### 1. Urgency and Time Pressure



The email tells the recipient that unusual sign-in activity was detected and that the account must be verified within 30 minutes.



The threat of losing access creates urgency and may pressure the recipient into clicking the link without carefully verifying the message.



### 2. Suspicious Sender Domain



The sender is displayed as:



security@micros0ft-support.example



The name `micros0ft` uses the number zero (`0`) instead of the letter `o`. This resembles Microsoft's name and is consistent with a typosquatting technique intended to deceive the recipient.



### 3. Sender and Link Domain Mismatch



The message uses different domains for the sender and the account-verification link.



Sender domain:



micros0ft-support.example



Link destination:



login-microsoft365-security.example



The domains do not match each other, and the message itself does not provide evidence that either domain is legitimately associated with Microsoft.



### 4. Suspicious Sign-In Location Claim



The message claims that an unusual login occurred from Frankfurt, Germany.



This claim increases the sense of urgency, but the location written in the email cannot by itself confirm that an actual authentication attempt occurred. Authentication logs would need to be reviewed to verify the claim.



### 5. Defanged URL



The lab artifact contains the following URL:



hxxps://login-microsoft365-security.example/account/verify



The `hxxps` format was intentionally used in this training environment to prevent accidental navigation to the URL. It is therefore not being treated as a phishing indicator by itself.



## Initial Assessment



Based on the sender-domain impersonation, social-engineering language, inconsistent domains, and suspicious account-verification request, I consider the email sufficiently suspicious to continue the investigation.



At this stage, I have not confirmed credential theft, endpoint compromise, malware execution, or unauthorized account access.



## Next Steps



The next stage of the investigation will include:



- Analyze the full email headers.

- Review sender authentication information.

- Extract and document indicators of compromise.

- Investigate the URL and domain characteristics.

- Determine whether endpoint activity occurred.

- Review available Wazuh and Sysmon telemetry.

- Build an evidence-based incident timeline.



