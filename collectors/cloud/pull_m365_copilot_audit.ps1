<#
.SYNOPSIS
  pull_m365_copilot_audit.ps1 - acquire Microsoft 365 Copilot interaction evidence from the unified audit log
  (CoSAI: prompt_logs, model_output, tool_calls). Read-only.

.DESCRIPTION
  M365 Copilot interactions are recorded in the Purview unified audit log as CopilotInteraction records
  (including the app/agent context, accessed resources, and, where retained, prompt/response references).
  This is the artifact behind EchoLeak-class (CVE-2025-32711) Copilot investigations. Requires the
  Exchange Online Management module and a role with View-Only Audit Logs (e.g., Audit Reader).

.PARAMETER CaseId    Case identifier (required).
.PARAMETER Days      Lookback window in days (default 7).
.PARAMETER OutputDir Case output root (default .\cases).
.PARAMETER UserPrincipalName  Optional: scope to a single user.

.EXAMPLE
  .\pull_m365_copilot_audit.ps1 -CaseId IR-2026-014 -Days 14
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$CaseId,
  [int]$Days = 7,
  [string]$OutputDir = ".\cases",
  [string]$UserPrincipalName
)

$ErrorActionPreference = "Stop"
$dest = Join-Path $OutputDir "$CaseId\cloud\m365-copilot"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$start = (Get-Date).ToUniversalTime().AddDays(-$Days)
$end   = (Get-Date).ToUniversalTime()
Write-Host "[*] M365 Copilot acquisition -> $dest (last $Days d)"

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
  Write-Warning "ExchangeOnlineManagement module not found. Install: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
  exit 1
}
Import-Module ExchangeOnlineManagement
# Interactive/modern-auth connect; use -CertificateThumbprint/-AppId for unattended IR runners.
Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop | Out-Null

# Unified audit log is paginated (5000/return). Loop on SessionId until exhausted.
$all = New-Object System.Collections.Generic.List[object]
$session = "aidfir-copilot-$([guid]::NewGuid().ToString('N'))"
do {
  $params = @{
    StartDate     = $start
    EndDate       = $end
    RecordType    = "CopilotInteraction"
    ResultSize    = 5000
    SessionId     = $session
    SessionCommand = "ReturnLargeSet"
  }
  if ($UserPrincipalName) { $params["UserIds"] = $UserPrincipalName }
  $batch = Search-UnifiedAuditLog @params
  if ($batch) { $batch | ForEach-Object { $all.Add($_) } }
} while ($batch -and $batch.Count -eq 5000)

Write-Host "[*] retrieved $($all.Count) CopilotInteraction records"
$raw = Join-Path $dest "copilot-interactions.json"
$all | ConvertTo-Json -Depth 10 | Out-File -FilePath $raw -Encoding utf8

# Expand the nested AuditData for analysis convenience (kept alongside raw).
$expanded = $all | ForEach-Object { $_.AuditData | ConvertFrom-Json }
$expanded | ConvertTo-Json -Depth 20 | Out-File -FilePath (Join-Path $dest "copilot-interactions-auditdata.json") -Encoding utf8

# Hash outputs for chain of custody.
Get-ChildItem -Path $dest -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
  "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.Name
} | Out-File -FilePath (Join-Path $dest "SHA256SUMS.txt") -Encoding ascii

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Write-Host "[+] Done. Manifest: $dest\SHA256SUMS.txt"
