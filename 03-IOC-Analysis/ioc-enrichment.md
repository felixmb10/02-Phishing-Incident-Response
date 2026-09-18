# IOC Enrichment and Threat Intelligence



## Purpose



This phase demonstrates safe IOC enrichment and threat-intelligence analysis.



The phishing indicators associated with INC-2026-0027 use reserved `.example` domains and documentation IP addresses. Because they do not represent real malicious infrastructure, public reputation results for those indicators would not provide meaningful threat intelligence.



External threat-intelligence examples were therefore analyzed separately and are not attributed to the simulated incident.



## Simulated Incident URL



The phishing artifact contained the following defanged URL:



`hxxps://login-microsoft365-security.example/account/verify`



CyberChef was used to safely refang the value for analysis:



`https://login-microsoft365-security.example/account/verify`



The URL was not visited.



Because `.example` is reserved for documentation and testing, the domain was treated as a controlled lab indicator rather than real attacker infrastructure.



## URLhaus Threat-Intelligence Exercise



A separate historical URLhaus record was reviewed to practice analyzing a real threat-intelligence entry.



Observed host:



`desktop-version.com`



Observed URL:



`https://desktop-version.com/app`



URLhaus reported:



- Date added: 2026-04-23 05:24:23 UTC

- Status: Offline

- Reporter: Anonymous



The `Offline` status was interpreted as the URL no longer being observed as active by the service at the time of review. It was not interpreted as evidence that the URL was safe.



This URL was analyzed only as an external threat-intelligence example. It is not an IOC associated with INC-2026-0027.



## VirusTotal Exercise



VirusTotal was also reviewed as part of the enrichment workflow.



A separate executable SHA-256 value was searched during threat-intelligence practice. The search did not provide useful evidence connecting that hash to the simulated phishing incident.



The hash was therefore excluded from the incident IOC list.



This demonstrates an important investigation principle: an analyst should not associate an external indicator with an incident without supporting evidence.



## Enrichment Assessment



IOC enrichment requires context in addition to reputation data.



During this exercise:



- Simulated incident indicators were kept separate from real-world threat-intelligence examples.

- Reserved lab domains and IP addresses were not presented as real malicious infrastructure.

- An offline URL was not considered safe solely because it was inactive.

- An unrelated executable hash was not attributed to the incident.

- Public threat-intelligence results were treated as supporting context rather than proof of compromise.



The incident conclusions remain based on evidence collected from the controlled phishing artifact, attachment analysis, sandbox execution, Sysmon telemetry, and Wazuh monitoring.



