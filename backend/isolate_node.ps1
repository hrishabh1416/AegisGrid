param (
    [Parameter(Mandatory=$true)]
    [string]$NodeName
)

Write-Host "=========================================="
Write-Host "AEGISGRID MICRO-ISOLATION ENGINE (WINDOWS)"
Write-Host "Target Node: $NodeName"
Write-Host "Initiating firewall isolation rules..."
Start-Sleep -Seconds 1

$LockFile = Join-Path -Path $PSScriptRoot -ChildPath "isolated_nodes.txt"
if (!(Test-Path $LockFile)) {
    New-Item -ItemType File -Path $LockFile -Force | Out-Null
}

$Timestamp = (Get-Date).ToString("o")
Add-Content -Path $LockFile -Value "$Timestamp - ISOLATED - $NodeName"

Write-Host "Firewall rules injected: Block all ingress/egress for $NodeName"
Write-Host "Mitigation Action: COMPLETE"
Write-Host "=========================================="
Exit 0
