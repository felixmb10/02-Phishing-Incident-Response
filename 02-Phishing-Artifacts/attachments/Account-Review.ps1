# Account-Review.ps1
# SOC Analyst Hands-On Lab - Safe Simulation

Write-Output "Starting account verification..."
Write-Output "SOC-LAB-PHISHING-TEST"

$CurrentUser = whoami
$Computer = hostname
$CurrentTime = Get-Date

Write-Output "User: $CurrentUser"
Write-Output "Computer: $Computer"
Write-Output "Time: $CurrentTime"

# Create a harmless lab artifact in the temporary directory
$Artifact = "$env:TEMP\account-review-lab.txt"

"Northstar SOC phishing simulation" | Out-File $Artifact

Write-Output "Verification complete."
Write-Output "Lab artifact created: $Artifact"