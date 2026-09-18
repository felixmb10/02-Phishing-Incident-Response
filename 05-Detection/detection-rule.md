# Detection Engineering



## Objective



Create and validate a custom Wazuh detection for suspicious PowerShell execution using the `-ExecutionPolicy Bypass` argument.



The original phishing simulation was already detected by Wazuh rule 92029. A custom rule was developed to provide an additional detection specifically for PowerShell processes launched with ExecutionPolicy Bypass.



## Original Detection



During execution of `Account-Review.ps1`, Sysmon generated Process Create telemetry.



Wazuh correlated the event and generated:



- Rule ID: 92029

- Level: 6

- Description: Powershell executed script from suspicious location

- Endpoint: SOC-WINDOWS

- MITRE ATT&CK: T1059.001 - PowerShell



The observed command line was:



powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\Account-Review.ps1



## Custom Detection Rule



The following rule was added to `/var/ossec/etc/rules/local_rules.xml`:



```xml

<group name="windows,sysmon,powershell,custom_soc,">

 <rule id="100200" level="10">

   <if_group>sysmon_event1</if_group>

   <field name="win.eventdata.image" type="pcre2">(?i)\\\\powershell\\.exe$</field>

   <field name="win.eventdata.commandLine" type="pcre2">(?i)-ExecutionPolicy\\s+Bypass</field>

   <description>CUSTOM SOC: PowerShell executed with ExecutionPolicy Bypass</description>

   <mitre>

     <id>T1059.001</id>

   </mitre>

 </rule>

</group>




