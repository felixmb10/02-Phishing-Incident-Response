# Indicators of Compromise and Investigative Artifacts

## Case

INC-2026-0027 - Phishing Investigation

## Extracted Indicators

| Type | Indicator | Source | Analyst Notes |
|---|---|---|---|
| Email Address | security@micros0ft-support.example | Email / Header | Simulated sender address impersonating Microsoft |
| Email Address | account-review@micros0ft-support.example | Email / Header | Reply-To address associated with the simulated phishing message |
| Domain | micros0ft-support.example | Email / Header | Typosquatted domain using `0` instead of `o` |
| Domain | login-microsoft365-security.example | Email | Domain used in the account-verification link |
| Domain | mailer-notification.example | Header | Return-Path domain differs from the visible sender domain |
| IPv4 | 203.0.113.77 | Header | Likely simulated originating IP based on the Received chain and X-Originating-IP |
| IPv4 | 198.51.100.27 | Header | Simulated mail server that relayed the message |
| URL | hxxps://login-microsoft365-security.example/account/verify | Email | Defanged simulated phishing URL |
| SHA-256 | 1087AF513037D27B5277EC6EA36A6E326F012D75D7EF4427CCC9CE37E03E6083 | Attachment / Endpoint | SHA-256 of the controlled `Account-Review.ps1` attachment |

## IOC Extraction

Candidate indicators were extracted from the email and header artifacts using PowerShell regular expressions.

The extraction produced both useful indicators and contextual or false-positive values. Candidate values were therefore manually reviewed rather than automatically treating every regex match as malicious.

Examples excluded from the malicious IOC list included:

- `finance.employee@northstar.example` - simulated recipient
- `northstar.example` - simulated internal domain
- `mail.northstar.example` - simulated internal mail infrastructure
- `20260917144308.28471@micros0ft-support.example` - Message-ID value rather than a sender account
- `header.from` - regex false positive
- `smtp.mailfrom` - regex false positive
- `finance.employee` - regex false positive

The raw extraction results are preserved in:

`07-Evidence/investigation-output/email-ioc-extraction.txt`

## Email Authentication Findings

Header analysis identified:

- SPF: fail
- DKIM: none
- DMARC: fail
- Return-Path different from the visible sender address
- Account-verification link hosted on a separate suspicious simulated domain

The two Received timestamps were chronologically consistent after accounting for their timezone offsets and were not treated as evidence of malicious activity.

## Attachment Hash Verification

The controlled PowerShell attachment produced the following SHA-256 hash:

`1087AF513037D27B5277EC6EA36A6E326F012D75D7EF4427CCC9CE37E03E6083`

The hash was verified again on `SOC-WINDOWS` before controlled endpoint execution, confirming that the tested endpoint artifact matched the analyzed attachment.

## Analyst Assessment

The combined indicators support classification of the email as a simulated phishing artifact.

The strongest email-level findings were the typosquatted sender domain, suspicious verification-link domain, failed SPF and DMARC results, absence of DKIM authentication, and differences among the visible sender, Return-Path, and link destination.

The PowerShell attachment was a controlled lab artifact rather than real malware. Static analysis, sandbox execution, Sysmon telemetry, and Wazuh monitoring were used to establish its actual behavior.

The domains ending in `.example` and the IP addresses in the documentation ranges are controlled training values and should not be interpreted as real malicious infrastructure.

No evidence from this exercise established real credential theft, persistence, command-and-control communication, lateral movement, or data exfiltration.
