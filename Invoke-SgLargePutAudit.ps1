<#
.SYNOPSIS
Identifies the tenants, buckets and objects responsible for "S3 PUT object size too large"
alerts in NetApp StorageGRID, filtering out multipart uploads that are not actually in breach.

.DESCRIPTION
The alert fires when a tenant performs a NON-multipart PutObject larger than 5 GiB. Grepping
the audit log for a large CSIZ value (as the NetApp docs and KB articles suggest) also returns
the SPUT message written for every CompleteMultipartUpload, which is why a raw grep over-reports.

This script:
  1. Verifies the /grid/audit clientWrites level is normal or debug (anything else discards SPUT).
  2. Reads /private/audit-destinations to work out whether audit messages live on the Admin Nodes
     (/var/local/audit/export/audit.log) or on each node (/var/local/log/localaudit.log).
  3. Scans a configurable period (default 24h; also 30m, 12h, 3.5d, 2w, forever).
  4. Collects candidate SPUT messages from the nodes over SSH, or from logs you already have.
  5. Classifies every candidate. SPUT messages carrying a ULID field are CompleteMultipartUpload
     records and are excluded unless the assembled object exceeds the 5 TiB multipart limit.
  6. Optionally confirms each suspect against /grid/object-metadata: a single oversized PUT is
     segmented internally at exactly 1 GiB, whereas multipart objects keep client part sizes.
  7. Reports how the NetApp docs regex and the NetApp KB regex scored against the same data.

Nothing in this folder modifies or depends on the existing As-Built scripts.

.PARAMETER Mode
  Ssh            Stream the collector to the Primary Admin Node over ssh (needs an SSH identity
                 that can read the audit logs, normally root with a key).
  GenerateScript Write the collector to disk, print run instructions, and stop. Use this when you
                 only have password access, since StorageGRID's 'admin' account requires an
                 interactive 'su -' that cannot be automated.
  Ingest         Parse collector output you captured earlier (-CollectorOutputPath).
  LocalFiles     Parse audit logs already downloaded to this machine (-LocalAuditPath).

.EXAMPLE
PS> .\Invoke-SgLargePutAudit.ps1 -Target admin.example.com -Period 24h -Mode GenerateScript

.EXAMPLE
PS> .\Invoke-SgLargePutAudit.ps1 -Target admin.example.com -Period 7d -Mode Ssh -SshIdentityFile ~\.ssh\id_ed25519 -VerifyWithObjectMetadata

.EXAMPLE
PS> .\Invoke-SgLargePutAudit.ps1 -Target admin.example.com -Mode Ingest -CollectorOutputPath .\collector-output.tsv -VerifyWithObjectMetadata
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$Target,
    [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential,
    [Parameter(Mandatory = $false)][switch]$ValidateCerts,
    [Parameter(Mandatory = $false)][switch]$UseSystemProxy,

    [Parameter(Mandatory = $false)][string]$Period = '24h',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Ssh', 'GenerateScript', 'Ingest', 'LocalFiles')]
    [string]$Mode = 'GenerateScript',

    [Parameter(Mandatory = $false)][string]$SshUser,
    [Parameter(Mandatory = $false)][string]$SshIdentityFile,
    [Parameter(Mandatory = $false)][string]$SshHost,
    [Parameter(Mandatory = $false)][string]$FanOutSshUser = 'root',
    [Parameter(Mandatory = $false)][switch]$IncludeAllNodes,

    [Parameter(Mandatory = $false)][string]$CollectorOutputPath,
    [Parameter(Mandatory = $false)][string]$LocalAuditPath,

    [Parameter(Mandatory = $false)][switch]$VerifyWithObjectMetadata,
    [Parameter(Mandatory = $false)][int]$MaxMetadataLookups = 250,

    [Parameter(Mandatory = $false)][string]$OutputDir = '.\s3-large-put-audit',
    [Parameter(Mandatory = $false)][switch]$IncludeAllCandidatesInReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Modules\SgPutAudit.Api.psm1') -Force
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Modules\SgPutAudit.Scan.psm1') -Force

$scanPeriod = ConvertTo-SgScanPeriod -Period $Period
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')

if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}
$outputDirResolved = (Resolve-Path -LiteralPath $OutputDir).ProviderPath

# --- Grid connection ------------------------------------------------------------------------
$session = $null
$needsGrid = ($Mode -ne 'LocalFiles') -or $VerifyWithObjectMetadata
if ($needsGrid -or -not [string]::IsNullOrWhiteSpace($Target)) {
    if ([string]::IsNullOrWhiteSpace($Target)) {
        $Target = Read-Host 'Enter the StorageGRID Management API target (for example admin.example.com)'
    }
    if ($null -eq $Credential) {
        $Credential = Get-Credential -Message 'Enter StorageGRID Management API credentials'
    }

    Write-Host "Authenticating to StorageGRID Management API ..."
    $session = Connect-SgGrid -Target $Target -Credential $Credential -ValidateCerts:$ValidateCerts -UseSystemProxy:$UseSystemProxy
}

# --- Step 1: audit level --------------------------------------------------------------------
$auditLevel = $null
$auditDestination = $null
$scanPlan = $null
$tenantMap = @{}

if ($null -ne $session) {
    $auditLevel = Get-SgClientWriteAuditLevel -Session $session
    Write-Host ("Client writes audit level: {0}" -f $auditLevel.ClientWrites)
    if (-not $auditLevel.IsSufficient) {
        Write-Warning "clientWrites is '$($auditLevel.ClientWrites)'. SPUT messages are not retained at this level, so audit-log scanning cannot identify the offending objects."
        Write-Warning "Set Configuration > Monitoring > Audit and syslog server > Client Writes to Normal, or follow the bycast.log procedure in the NetApp troubleshooting article."
    }

    # --- Step 2: audit destinations ---------------------------------------------------------
    $auditDestination = Get-SgAuditDestination -Session $session
    Write-Host ("Audit destination: {0} ({1}/{2})" -f $auditDestination.Scope, $auditDestination.LogDirectory, $auditDestination.LogGlob)
    if ($auditDestination.RemoteSyslogEnabled -and $auditDestination.AuditLogsToSyslog) {
        Write-Host ("Audit logs are also forwarded to external syslog server '{0}'." -f $auditDestination.RemoteSyslogHostname)
    }

    $nodes = Get-SgNodeInventory -Session $session
    Write-Host ("Resolved {0} grid node(s)." -f @($nodes).Count)
    $scanPlan = Get-SgAuditScanPlan -AuditDestination $auditDestination -Nodes $nodes -FallbackHost (([uri]$session.BaseUrl).Host) -IncludeAllNodes:$IncludeAllNodes
    if ($scanPlan.FanOutNodes.Count -gt 0) {
        Write-Host ("Audit messages are kept on local nodes; {0} node(s) will be scanned from the Primary Admin Node." -f $scanPlan.FanOutNodes.Count)
    }
    else {
        Write-Host ("Audit messages are forwarded to the Admin Nodes; only {0} needs to be scanned." -f $scanPlan.EntryNode.Name)
    }

    $tenantMap = Get-SgTenantAccountMap -Session $session
}

Write-Host ("Scan period: {0}" -f $scanPeriod.Text)

# --- Steps 3-5: collect candidate SPUT messages ---------------------------------------------
$collectorLines = @()

if ($Mode -eq 'LocalFiles') {
    if ([string]::IsNullOrWhiteSpace($LocalAuditPath)) {
        throw "-Mode LocalFiles requires -LocalAuditPath pointing at a downloaded audit log file or directory."
    }
    Write-Host "Scanning local audit logs under $LocalAuditPath ..."
    $collectorLines = Read-SgLocalAuditFile -Path $LocalAuditPath
}
elseif ($Mode -eq 'Ingest') {
    if ([string]::IsNullOrWhiteSpace($CollectorOutputPath) -or -not (Test-Path -LiteralPath $CollectorOutputPath -PathType Leaf)) {
        throw "-Mode Ingest requires -CollectorOutputPath pointing at collector output captured from the grid."
    }
    $collectorLines = @(Get-Content -LiteralPath $CollectorOutputPath)
}
else {
    if ($null -eq $scanPlan) { throw "A grid connection is required to build the collector script." }

    $scriptText = New-SgAuditScanScript -ScanPlan $scanPlan -ScanPeriod $scanPeriod -FanOutSshUser $FanOutSshUser
    $scriptPath = Join-Path -Path $outputDirResolved -ChildPath "sg-largeput-collector_$timestamp.sh"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($scriptPath, $scriptText, $utf8NoBom)

    if ($Mode -eq 'GenerateScript') {
        $targetHost = $SshHost
        if ([string]::IsNullOrWhiteSpace($targetHost)) { $targetHost = $scanPlan.EntryNode.GridIp }
        $scriptFileName = [System.IO.Path]::GetFileName($scriptPath)
        $outputName = "collector-output_$timestamp.tsv"
        $remoteScriptPath = "/var/local/tmp/$scriptFileName"

        Write-Host ''
        Write-Host '======================================================================' -ForegroundColor DarkCyan
        Write-Host ' RUN THE COLLECTOR ON THE PRIMARY ADMIN NODE' -ForegroundColor Yellow
        Write-Host '======================================================================' -ForegroundColor DarkCyan
        Write-Host "Collector script: $scriptPath"
        Write-Host ''
        Write-Host '1. Copy the collector to the Primary Admin Node:'
        Write-Host "     scp `"$scriptPath`" admin@${targetHost}:${remoteScriptPath}"
        Write-Host '2. Sign in and elevate:'
        Write-Host "     ssh admin@$targetHost"
        Write-Host '     su -'
        Write-Host '3. Run it and capture the output:'
        Write-Host "     bash $remoteScriptPath > /var/local/tmp/$outputName"
        Write-Host '4. Copy the output back and ingest it:'
        Write-Host "     scp admin@${targetHost}:/var/local/tmp/$outputName `"$outputDirResolved`""
        Write-Host "     .\Invoke-SgLargePutAudit.ps1 -Target $Target -Period $($scanPeriod.Text) -Mode Ingest -CollectorOutputPath `"$(Join-Path $outputDirResolved $outputName)`" -VerifyWithObjectMetadata"
        Write-Host ''
        return
    }

    $sshTarget = $SshHost
    if ([string]::IsNullOrWhiteSpace($sshTarget)) { $sshTarget = $scanPlan.EntryNode.GridIp }
    if ([string]::IsNullOrWhiteSpace($sshTarget)) { $sshTarget = $scanPlan.EntryNode.Name }

    if (-not $PSBoundParameters.ContainsKey('SshUser')) {
        $enteredSshUser = Read-Host 'SSH username [admin]'
        $SshUser = if ([string]::IsNullOrWhiteSpace($enteredSshUser)) { 'admin' } else { $enteredSshUser.Trim() }
    }

    if ([string]::IsNullOrWhiteSpace($SshIdentityFile)) {
        Write-Host "Running the collector on $sshTarget over ssh as $SshUser ..."
        Write-Host 'OpenSSH will prompt for the SSH password without exposing it to PowerShell.'
    }
    else {
        Write-Host "Running the collector on $sshTarget over ssh as $SshUser using the supplied identity ..."
    }
    $collectorLines = Invoke-SgRemoteAuditScan -ScriptText $scriptText -ComputerName $sshTarget -UserName $SshUser -IdentityFile $SshIdentityFile

    $rawOutputPath = Join-Path -Path $outputDirResolved -ChildPath "collector-output_$timestamp.tsv"
    Set-Content -LiteralPath $rawOutputPath -Value $collectorLines -Encoding UTF8
    Write-Host "Raw collector output saved to: $rawOutputPath"
}

# --- Step 5: classify -----------------------------------------------------------------------
$parsed = ConvertFrom-SgCollectorOutput -Lines $collectorLines -TenantNameById $tenantMap -ScanPeriod $scanPeriod
$candidates = @($parsed.Results | Where-Object { -not $_.IsObjectMetadataOperation })
$alerts = @($candidates | Where-Object { $_.TriggersAlert })

Write-Host ''
Write-Host ("SPUT messages scanned : {0}" -f (@($parsed.FileStatistics) | Measure-Object -Property SputMessages -Sum).Sum)
Write-Host ("Candidate lines        : {0}" -f @($candidates).Count)
Write-Host ("Outside scan period    : {0}" -f $parsed.SkippedOutOfPeriod)
Write-Host ("Multipart (excluded)   : {0}" -f @($candidates | Where-Object { $_.Classification -eq 'MultipartComplete' }).Count)
Write-Host ("Alert triggers         : {0}" -f @($alerts).Count) -ForegroundColor Yellow

# --- Step 6/7: object metadata verification -------------------------------------------------
if ($VerifyWithObjectMetadata) {
    if ($null -eq $session) { throw "-VerifyWithObjectMetadata requires a grid connection (-Target/-Credential)." }
    Write-Host "Verifying suspects against /grid/object-metadata ..."
    $toVerify = $alerts
    if ($IncludeAllCandidatesInReport) { $toVerify = $candidates }
    $null = Add-SgObjectMetadataVerification -Session $session -Results $toVerify -MaxLookups $MaxMetadataLookups

    $disagreements = @($alerts | Where-Object { $_.MetadataCheck -eq 'LooksMultipart' })
    if ($disagreements.Count -gt 0) {
        Write-Warning "$($disagreements.Count) suspected single PUT(s) have non-1 GiB segment sizes. Review them before notifying the tenant."
    }
}

# --- Regex comparison ------------------------------------------------------------------------
$regexComparison = Get-SgRegexComparison -Results $candidates
Write-Host ''
Write-Host 'Grep pattern accuracy over the same candidate set:' -ForegroundColor Cyan
Write-Host ("  NetApp docs regex matches : {0} (false positives: {1})" -f $regexComparison.DocsRegexMatches, $regexComparison.DocsRegexFalsePositives)
Write-Host ("  NetApp KB regex matches   : {0} (false positives: {1}, missed >5 GiB: {2})" -f $regexComparison.KbRegexMatches, $regexComparison.KbRegexFalsePositives, $regexComparison.KbRegexMissedOver5GiB)
Write-Host ("  Exact CSIZ > 5 GiB        : {0}" -f $regexComparison.ExactlyOver5GiB)
Write-Host ("  Actual alert triggers     : {0}" -f $regexComparison.ActualAlertTriggers)

# --- Reporting --------------------------------------------------------------------------------
$reportRows = @($alerts)
if ($IncludeAllCandidatesInReport) { $reportRows = $candidates }

$reportColumns = @(
    'AuditTimeUtc', 'TenantName', 'TenantId', 'Bucket', 'Key', 'SizeBytes', 'SizeGiB',
    'ClientIp', 'Node', 'Classification', 'IsMultipart', 'IsObjectMetadataOperation',
    'MetadataCheck', 'SegmentCount', 'SegmentSummary',
    'Uuid', 'VersionId', 'AuditFile'
)

$csvPath = Join-Path -Path $outputDirResolved -ChildPath "s3-large-put_$timestamp.csv"
@($reportRows) | Select-Object -Property $reportColumns | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$jsonPath = Join-Path -Path $outputDirResolved -ChildPath "s3-large-put_$timestamp.json"
[ordered]@{
    generatedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
    target           = $Target
    scanPeriod       = $scanPeriod.Text
    clientWritesLevel = if ($null -ne $auditLevel) { $auditLevel.ClientWrites } else { 'unknown' }
    auditDestination = if ($null -ne $auditDestination) { $auditDestination.Scope } else { 'unknown' }
    fileStatistics   = [object[]]@($parsed.FileStatistics)
    regexComparison  = $regexComparison
    alerts           = [object[]]@($alerts | Select-Object -Property $reportColumns)
    reportCandidates = [object[]]@($reportRows | Select-Object -Property $reportColumns)
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

Write-Host ''
Write-Host "CSV report : $csvPath"
Write-Host "JSON report: $jsonPath"

if (@($alerts).Count -gt 0) {
    Write-Host ''
    Write-Host 'Top offending tenants:' -ForegroundColor Cyan
    @($alerts) |
        Group-Object -Property TenantName |
        Sort-Object -Property Count -Descending |
        Select-Object -First 10 -Property @{ Name = 'Tenant'; Expression = { $_.Name } },
            @{ Name = 'Objects'; Expression = { $_.Count } },
            @{ Name = 'LargestGiB'; Expression = { (@($_.Group | Measure-Object -Property SizeGiB -Maximum).Maximum) } } |
        Format-Table -AutoSize | Out-String | Write-Host
}
