# Audit-log scanning and SPUT classification for the StorageGRID large-PUT audit tool.

Set-StrictMode -Version Latest

# S3 hard limits. A single (non-multipart) PutObject may not exceed 5 GiB; a completed
# multipart object may not exceed 5 TiB.
$script:SgSinglePutLimitBytes = 5368709120L
$script:SgMultipartObjectLimitBytes = 5497558138880L
# StorageGRID chunks an oversized single PUT internally using 1 GiB segments.
$script:SgInternalSegmentBytes = 1073741824L
# Collection threshold used on the nodes. Deliberately looser than 5 GiB so the exact
# 5 GiB comparison, the NetApp docs regex and the NetApp KB regex can all be evaluated
# afterwards against the same superset of lines.
$script:SgCollectionThresholdBytes = 5000000000L

function ConvertTo-SgScanPeriod {
    <#
    .SYNOPSIS
    Converts a scan-period string such as 30m, 3h, 3.5d, 2w or "forever" into a TimeSpan.

    .OUTPUTS
    An object with Text, TimeSpan (null for "forever"), TotalMinutes (null for "forever")
    and StartTimeUtc (null for "forever").
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)][string]$Period = '24h')

    $text = ([string]$Period).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { $text = '24h' }

    if ($text -match '^(?i)(forever|all)$') {
        return [pscustomobject]@{
            Text         = 'forever'
            TimeSpan     = $null
            TotalMinutes = $null
            StartTimeUtc = $null
        }
    }

    $match = [regex]::Match($text, '^(?<value>\d+(\.\d+)?)\s*(?<unit>[mhdw])$', 'IgnoreCase')
    if (-not $match.Success) {
        throw "Invalid scan period '$Period'. Use a value with a unit (for example 30m, 12h, 3.5d, 2w) or 'forever'."
    }

    $value = [double]$match.Groups['value'].Value
    if ($value -le 0) { throw "Scan period '$Period' must be greater than zero." }

    $unit = $match.Groups['unit'].Value.ToLowerInvariant()
    if ($unit -eq 'm') { $span = [TimeSpan]::FromMinutes($value) }
    elseif ($unit -eq 'h') { $span = [TimeSpan]::FromHours($value) }
    elseif ($unit -eq 'd') { $span = [TimeSpan]::FromDays($value) }
    else { $span = [TimeSpan]::FromDays($value * 7) }

    return [pscustomobject]@{
        Text         = $text.ToLowerInvariant()
        TimeSpan     = $span
        TotalMinutes = [int][Math]::Ceiling($span.TotalMinutes)
        StartTimeUtc = (Get-Date).ToUniversalTime().Add(-$span)
    }
}

function Get-SgAuditScanPlan {
    <#
    .SYNOPSIS
    Combines the audit destination configuration and node inventory into a scan plan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$AuditDestination,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Nodes = @(),
        [Parameter(Mandatory = $false)][string]$FallbackHost,
        [Parameter(Mandatory = $false)][switch]$IncludeAllNodes
    )

    # Select-Object rather than [0]: StrictMode throws on indexing an empty filtered array.
    $primaryAdmin = @($Nodes | Where-Object { $_.IsPrimaryAdmin }) | Select-Object -First 1
    if ($null -eq $primaryAdmin) {
        $primaryAdmin = @($Nodes | Where-Object { $_.Type -match '(?i)admin' }) | Select-Object -First 1
    }
    if ($null -eq $primaryAdmin -and -not [string]::IsNullOrWhiteSpace($FallbackHost)) {
        # The Management API host is an Admin Node by definition, so it is a safe entry point.
        Write-Warning "No Admin Node was identified from the node inventory ($(@($Nodes).Count) node(s)); falling back to the Management API host '$FallbackHost' as the SSH entry point."
        $primaryAdmin = [pscustomobject]@{
            NodeId = ''; Name = $FallbackHost; SiteName = ''; Type = 'adminNode'
            IsPrimaryAdmin = $true; Severity = ''; Platform = ''; GridIp = $FallbackHost; AdminIp = ''
        }
    }
    if ($null -eq $primaryAdmin) {
        throw "No Admin Node was found in the node inventory (resolved $(@($Nodes).Count) node(s)) and no fallback host was supplied; cannot determine an SSH entry point."
    }

    if ($AuditDestination.Scope -eq 'AdminNodes') {
        # Every node forwards to the Admin Nodes, so the Primary Admin Node holds the full record.
        $targets = @()
    }
    elseif ($IncludeAllNodes) {
        $targets = @($Nodes | Where-Object { -not $_.IsPrimaryAdmin })
    }
    else {
        # S3 client-write audit messages are emitted by the LDR service on Storage Nodes.
        $targets = @($Nodes | Where-Object { $_.Type -match '(?i)storage' })
    }

    return [pscustomobject]@{
        Scope        = $AuditDestination.Scope
        LogDirectory = $AuditDestination.LogDirectory
        LogGlob      = $AuditDestination.LogGlob
        EntryNode    = $primaryAdmin
        FanOutNodes  = [object[]]@($targets)
    }
}

function New-SgAuditScanScript {
    <#
    .SYNOPSIS
    Generates the self-contained bash collector that runs on the StorageGRID nodes.

    .DESCRIPTION
    The script scans the audit logs on the node it runs on and, when audit messages are kept on
    local nodes, fans out over password-less SSH from the Primary Admin Node to each target node.
    It emits two tab-separated record types on stdout:

      H <TAB> node <TAB> file <TAB> raw-audit-line     a candidate SPUT message
      S <TAB> node <TAB> file <TAB> sputTotal <TAB> emitted   per-file statistics
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$ScanPlan,
        [Parameter(Mandatory = $true)]$ScanPeriod,
        [Parameter(Mandatory = $false)][string]$FanOutSshUser = 'root'
    )

    $sinceMinutes = ''
    if ($null -ne $ScanPeriod.TotalMinutes) { $sinceMinutes = [string]$ScanPeriod.TotalMinutes }

    $nodeList = @(
        $ScanPlan.FanOutNodes | ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace($_.GridIp)) { $_.GridIp } else { $_.Name }
        }
    ) -join ' '

    $template = @'
#!/bin/bash
# StorageGRID large-PUT audit collector (generated -- safe to review before running).
# Read-only: it only reads audit logs and writes to stdout.

AUDIT_DIR='__AUDIT_DIR__'
AUDIT_GLOB='__AUDIT_GLOB__'
SINCE_MINUTES='__SINCE_MINUTES__'
FANOUT_NODES='__FANOUT_NODES__'
FANOUT_USER='__FANOUT_USER__'
MIN_BYTES=__MIN_BYTES__

[ -z "$NODE_NAME" ] && NODE_NAME=$(hostname)

scan_local() {
    local files
    if [ -n "$SINCE_MINUTES" ]; then
        files=$(find "$AUDIT_DIR" -maxdepth 1 -type f \( -name "$AUDIT_GLOB" -o -name '????-??-??*' -o -name '*.txt' -o -name '*.txt.gz' \) -newermt "-${SINCE_MINUTES} minutes" 2>/dev/null)
    else
        files=$(find "$AUDIT_DIR" -maxdepth 1 -type f \( -name "$AUDIT_GLOB" -o -name '????-??-??*' -o -name '*.txt' -o -name '*.txt.gz' \) 2>/dev/null)
    fi

    if [ -z "$files" ]; then
        printf 'S\t%s\t%s\t0\t0\n' "$NODE_NAME" "(no audit files matched)"
        return 0
    fi

    printf '%s\n' "$files" | while IFS= read -r f; do
        case "$f" in
            *.gz)  reader="zcat" ;;
            *.bz2) reader="bzcat" ;;
            *)     reader="cat" ;;
        esac
        $reader "$f" 2>/dev/null | awk -v node="$NODE_NAME" -v file="$f" -v min="$MIN_BYTES" '
            /ATYP\(FC32\):SPUT/ {
                total++
                if (match($0, /CSIZ\(UI64\):[0-9]+/)) {
                    size = substr($0, RSTART + 11, RLENGTH - 11) + 0
                    if (size >= min) {
                        emitted++
                        printf "H\t%s\t%s\t%s\n", node, file, $0
                    }
                }
            }
            END { printf "S\t%s\t%s\t%d\t%d\n", node, file, total, emitted }
        '
    done
}

scan_local

if [ "$SG_LOCAL_ONLY" != "1" ] && [ -n "$FANOUT_NODES" ]; then
    for target in $FANOUT_NODES; do
        if ! ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                "${FANOUT_USER}@${target}" "SG_LOCAL_ONLY=1 NODE_NAME='${target}' bash -s" < "$0"; then
            printf 'S\t%s\t(ssh-failed)\t0\t0\n' "$target" >&2
            echo "WARNING: could not scan ${target}" >&2
        fi
    done
fi
'@

    $script = $template.
        Replace('__AUDIT_DIR__', [string]$ScanPlan.LogDirectory).
        Replace('__AUDIT_GLOB__', [string]$ScanPlan.LogGlob).
        Replace('__SINCE_MINUTES__', $sinceMinutes).
        Replace('__FANOUT_NODES__', $nodeList).
        Replace('__FANOUT_USER__', $FanOutSshUser).
        Replace('__MIN_BYTES__', [string]$script:SgCollectionThresholdBytes)

    # StorageGRID nodes are Linux; keep LF endings so bash does not choke on CR.
    return ($script -replace "`r`n", "`n")
}

function Invoke-SgRemoteAuditScan {
    <#
    .SYNOPSIS
    Streams the generated collector to a StorageGRID node over ssh and returns its stdout lines.

    .DESCRIPTION
    Streams the collector to the requested SSH account, which must be able to read the audit
    logs directly. OpenSSH handles password prompting on the terminal when no identity file is
    supplied; passwords are never passed as PowerShell arguments or sent through the collector
    input stream.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $false)][string]$UserName = 'admin',
        [Parameter(Mandatory = $false)][string]$IdentityFile,
        [Parameter(Mandatory = $false)][string]$SshExecutable = 'ssh'
    )

    $scriptBytes = [System.Text.Encoding]::UTF8.GetBytes($ScriptText)
    $encodedScript = [Convert]::ToBase64String($scriptBytes)

    $sshArgs = @('-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=15')
    if (-not [string]::IsNullOrWhiteSpace($IdentityFile)) { $sshArgs += @('-i', $IdentityFile) }
    $sshArgs += @(
        "$UserName@$ComputerName",
        "printf '%s' '$encodedScript' | base64 -d | bash -s"
    )

    Write-Verbose "Running: $SshExecutable $($sshArgs -join ' ')"
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $SshExecutable @sshArgs 2>&1
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0) {
        throw "ssh to $ComputerName exited with code $LASTEXITCODE. Output: $($output -join '; ')"
    }
    return ,@($output | ForEach-Object { [string]$_ })
}

function ConvertFrom-SgAuditMessage {
    <#
    .SYNOPSIS
    Parses the [CODE(TYPE):value] attribute pairs out of a StorageGRID audit message line.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)

    $fields = @{}
    foreach ($match in [regex]::Matches($Line, '\[(?<code>[A-Z0-9]{4})\((?<type>[A-Z0-9]+)\):(?<val>"(?:[^"\\]|\\.)*"|[^\]]*)\]')) {
        $value = $match.Groups['val'].Value
        if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $fields[$match.Groups['code'].Value] = $value
    }
    return $fields
}

function ConvertFrom-SgSputRecord {
    <#
    .SYNOPSIS
    Turns a collector 'H' record into a structured, classified SPUT result.

    .DESCRIPTION
    Classification rules:
      * ULID is present only on the SPUT written for a CompleteMultipartUpload, so any hit
        carrying ULID is a multipart object and is NOT what the alert reports -- unless the
        assembled object exceeds the 5 TiB multipart object limit.
      * A SPUT without ULID whose CSIZ exceeds 5 GiB is a single PutObject that breaches the
        S3 limit, which is exactly what "S3 PUT object size too large" reports.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$NodeName,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$RawLine,
        [Parameter(Mandatory = $false)][hashtable]$TenantNameById = @{}
    )

    $fields = ConvertFrom-SgAuditMessage -Line $RawLine

    $size = 0L
    if ($fields.ContainsKey('CSIZ')) { [void][long]::TryParse($fields['CSIZ'], [ref]$size) }

    $auditTimeUtc = $null
    if ($fields.ContainsKey('ATIM')) {
        $atim = 0L
        if ([long]::TryParse($fields['ATIM'], [ref]$atim) -and $atim -gt 0) {
            $auditTimeUtc = [DateTimeOffset]::FromUnixTimeMilliseconds([long][Math]::Floor($atim / 1000)).UtcDateTime
        }
    }
    if ($null -eq $auditTimeUtc) {
        $isoMatch = [regex]::Match($RawLine, '(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?)')
        if ($isoMatch.Success) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse($isoMatch.Groups['ts'].Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) {
                $auditTimeUtc = $parsed
            }
        }
    }

    $uploadId = ''
    if ($fields.ContainsKey('ULID')) { $uploadId = [string]$fields['ULID'] }
    $isMultipart = -not [string]::IsNullOrWhiteSpace($uploadId)
    $isObjectMetadataOperation = $fields.ContainsKey('S3SR') -or $fields.ContainsKey('SRCF')

    if ($isObjectMetadataOperation) {
        $classification = 'ObjectMetadataOperation'
        $triggersAlert = $false
    }
    elseif ($isMultipart) {
        if ($size -gt $script:SgMultipartObjectLimitBytes) {
            $classification = 'MultipartOverObjectLimit'
            $triggersAlert = $true
        }
        else {
            $classification = 'MultipartComplete'
            $triggersAlert = $false
        }
    }
    elseif ($size -gt $script:SgSinglePutLimitBytes) {
        $classification = 'SinglePutOverLimit'
        $triggersAlert = $true
    }
    else {
        $classification = 'BelowSinglePutLimit'
        $triggersAlert = $false
    }

    $tenantId = ''
    if ($fields.ContainsKey('S3AI')) { $tenantId = [string]$fields['S3AI'] }
    $tenantName = ''
    if ($fields.ContainsKey('SACC')) { $tenantName = [string]$fields['SACC'] }
    if ([string]::IsNullOrWhiteSpace($tenantName) -and $TenantNameById.ContainsKey($tenantId)) {
        $tenantName = [string]$TenantNameById[$tenantId]
    }
    if ([string]::IsNullOrWhiteSpace($tenantName)) { $tenantName = 'N/A' }

    $getField = {
        param([string]$Code)
        if ($fields.ContainsKey($Code)) { return [string]$fields[$Code] }
        return ''
    }

    return [pscustomobject]@{
        AuditTimeUtc   = $auditTimeUtc
        Node           = $NodeName
        AuditFile      = $FileName
        TenantId       = $tenantId
        TenantName     = $tenantName
        Bucket         = (& $getField 'S3BK')
        Key            = (& $getField 'S3KY')
        SizeBytes      = $size
        SizeGiB        = [math]::Round(($size / 1GB), 3)
        ClientIp       = (& $getField 'SAIP')
        LoadBalancerIp = (& $getField 'TLIP')
        Uuid           = (& $getField 'UUID')
        Cbid           = (& $getField 'CBID')
        VersionId      = (& $getField 'VSID')
        UploadId       = $uploadId
        IsMultipart    = $isMultipart
        IsObjectMetadataOperation = $isObjectMetadataOperation
        Result         = (& $getField 'RSLT')
        Classification = $classification
        TriggersAlert  = $triggersAlert
        ReportCandidate = $triggersAlert -or $isObjectMetadataOperation
        MetadataCheck  = 'NotChecked'
        SegmentCount   = $null
        SegmentSummary = ''
        RawLine        = $RawLine
    }
}

function ConvertFrom-SgCollectorOutput {
    <#
    .SYNOPSIS
    Parses the collector's tab-separated stdout into results plus per-file statistics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines,
        [Parameter(Mandatory = $false)][hashtable]$TenantNameById = @{},
        [Parameter(Mandatory = $false)]$ScanPeriod
    )

    $results = @()
    $stats = @()
    $skippedOutOfPeriod = 0

    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line -split "`t", 4

        if ($parts[0] -eq 'H' -and $parts.Count -eq 4) {
            $record = ConvertFrom-SgSputRecord -NodeName $parts[1] -FileName $parts[2] -RawLine $parts[3] -TenantNameById $TenantNameById

            # Log files are selected by mtime, so an eligible file can still contain older lines.
            if ($null -ne $ScanPeriod -and $null -ne $ScanPeriod.StartTimeUtc -and $null -ne $record.AuditTimeUtc) {
                if ($record.AuditTimeUtc -lt $ScanPeriod.StartTimeUtc) {
                    $skippedOutOfPeriod++
                    continue
                }
            }
            $results += $record
        }
        elseif ($parts[0] -eq 'S') {
            $tail = ($parts[3] -split "`t")
            $total = 0
            $emitted = 0
            if ($tail.Count -ge 1) { [void][int]::TryParse($tail[0], [ref]$total) }
            if ($tail.Count -ge 2) { [void][int]::TryParse($tail[1], [ref]$emitted) }
            $stats += [pscustomobject]@{
                Node          = $parts[1]
                AuditFile     = $parts[2]
                SputMessages  = $total
                Candidates    = $emitted
            }
        }
    }

    return [pscustomobject]@{
        Results            = [object[]]@($results | Sort-Object -Property SizeBytes -Descending)
        FileStatistics     = [object[]]@($stats)
        SkippedOutOfPeriod = $skippedOutOfPeriod
    }
}

function Get-SgRegexComparison {
    <#
    .SYNOPSIS
    Scores the NetApp docs regex, the NetApp KB regex and an exact 5 GiB test against the
    same set of candidate lines so the accuracy difference can be shown, not guessed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Results)

    # Docs: zgrep SPUT * | egrep "CSIZ\(UI64\):([5-9]|[1-9][0-9]+)[0-9]{9}"  -> CSIZ >= 5,000,000,000
    $docsPattern = 'CSIZ\(UI64\):([5-9]|[1-9][0-9]+)[0-9]{9}'
    # KB: grep "CSIZ(UI64):[0-9]*[5-9][0-9]{9}" -> unanchored, so it silently misses any size
    # with no digit 5-9 ten places from the end (for example 10 GiB = 10737418240).
    $kbPattern = 'CSIZ\(UI64\):[0-9]*[5-9][0-9]{9}'

    $docsMatches = @($Results | Where-Object { $_.RawLine -match $docsPattern })
    $kbMatches = @($Results | Where-Object { $_.RawLine -match $kbPattern })
    $exactMatches = @($Results | Where-Object { $_.SizeBytes -gt $script:SgSinglePutLimitBytes })
    $trueAlerts = @($Results | Where-Object { $_.TriggersAlert })

    $kbMissed = @($exactMatches | Where-Object { $_.RawLine -notmatch $kbPattern })
    $docsFalsePositives = @($docsMatches | Where-Object { -not $_.TriggersAlert })
    $kbFalsePositives = @($kbMatches | Where-Object { -not $_.TriggersAlert })

    return [pscustomobject]@{
        CandidateLines            = @($Results).Count
        DocsRegexMatches          = $docsMatches.Count
        KbRegexMatches            = $kbMatches.Count
        ExactlyOver5GiB           = $exactMatches.Count
        ActualAlertTriggers       = $trueAlerts.Count
        DocsRegexFalsePositives   = $docsFalsePositives.Count
        KbRegexFalsePositives     = $kbFalsePositives.Count
        KbRegexMissedOver5GiB     = $kbMissed.Count
        KbRegexMissedExamples     = [object[]]@($kbMissed | Select-Object -First 5 -Property Bucket, Key, SizeBytes)
    }
}

function Add-SgObjectMetadataVerification {
    <#
    .SYNOPSIS
    Confirms each suspected single large PUT against /grid/object-metadata.

    .DESCRIPTION
    A single PUT larger than 5 GiB is chunked internally by StorageGRID into 1 GiB segments, so
    uniform full internal segments with a smaller final segment, covering the exact object size,
    confirm a single PUT. The internal segment size is grid/version dependent; do not assume it
    is exactly 1 GiB. Multipart objects keep the client's part sizes.
    Results are annotated in place; the audit-log ULID field remains the primary discriminator.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Results,
        [Parameter(Mandatory = $false)][int]$MaxLookups = 250
    )

    $lookupCount = 0
    foreach ($result in $Results) {
        if ($lookupCount -ge $MaxLookups) {
            $result.MetadataCheck = 'SkippedLookupLimit'
            continue
        }

        $identifier = ''
        # Prefer bucket/key for version-aware lookups. The SPUT UUID field is not consistently
        # accepted by /grid/object-metadata across grids/releases.
        if (-not [string]::IsNullOrWhiteSpace($result.Bucket) -and -not [string]::IsNullOrWhiteSpace($result.Key)) {
            $identifier = "$($result.Bucket)/$($result.Key)"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($result.Cbid) -and $result.Cbid -notmatch '^0x0+$') {
            $identifier = $result.Cbid.ToUpperInvariant()
        }
        elseif (-not [string]::IsNullOrWhiteSpace($result.Uuid)) {
            $identifier = $result.Uuid.ToUpperInvariant()
        }
        if ([string]::IsNullOrWhiteSpace($identifier)) {
            $result.MetadataCheck = 'NoIdentifier'
            continue
        }

        $lookupCount++
        $metadata = Get-SgObjectMetadata -Session $Session -Identifier $identifier -VersionId $result.VersionId
        if (-not $metadata.Found) {
            $result.MetadataCheck = 'LookupFailed'
            $result.SegmentSummary = $metadata.Message
            continue
        }

        $segmentSizes = @(Find-SgSegmentSizes -Node $metadata.Data)
        $result.SegmentCount = $segmentSizes.Count

        if ($segmentSizes.Count -eq 0) {
            $result.MetadataCheck = 'NoSegments'
            continue
        }

        $leading = @($segmentSizes | Select-Object -First ($segmentSizes.Count - 1))
        $totalSegmentBytes = [int64](($segmentSizes | Measure-Object -Sum).Sum)
        $uniformInternal = ($leading.Count -gt 0) -and
            (@($leading | Sort-Object -Unique).Count -eq 1) -and
            ($totalSegmentBytes -eq [int64]$result.SizeBytes) -and
            ([int64]$segmentSizes[$segmentSizes.Count - 1] -le [int64]$leading[0])
        $result.SegmentSummary = ("{0} segments; distinct sizes: {1}" -f $segmentSizes.Count, (($segmentSizes | Sort-Object -Unique) -join ', '))

        if ($uniformInternal) { $result.MetadataCheck = 'ConfirmedSinglePut' }
        else { $result.MetadataCheck = 'LooksMultipart' }
    }

    return ,@($Results)
}

function Find-SgSegmentSizes {
    <#
    .SYNOPSIS
    Walks an object-metadata response and collects the segment size values it contains.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]$Node,
        [Parameter(Mandatory = $false)][int]$Depth = 0
    )

    $sizes = @()
    if ($null -eq $Node -or $Depth -gt 8) { return @($sizes) }

    if ($Node -is [string] -or $Node -is [valuetype]) { return @($sizes) }

    if ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [System.Collections.IDictionary])) {
        foreach ($item in $Node) { $sizes += @(Find-SgSegmentSizes -Node $item -Depth ($Depth + 1)) }
        return @($sizes)
    }

    $propertyNames = @()
    if ($Node -is [System.Collections.IDictionary]) { $propertyNames = @($Node.Keys) }
    else {
        $propertyNames = @(
            @($Node.PSObject.Properties) |
                ForEach-Object { [string]$_.Name } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }

    foreach ($name in $propertyNames) {
        $value = Get-SgPropertyValue -Object $Node -PropertyName ([string]$name)
        if ([string]$name -match '^(segments|objectSegments)$') {
            foreach ($segment in @(ConvertTo-SgArray -Payload $value)) {
                foreach ($sizeProperty in @('size', 'dataSize', 'segmentSize', 'length', 'bytes')) {
                    $sizeValue = Get-SgPropertyValue -Object $segment -PropertyName $sizeProperty
                    if ($null -ne $sizeValue) {
                        $parsed = 0L
                        if ([long]::TryParse([string]$sizeValue, [ref]$parsed)) { $sizes += $parsed }
                        break
                    }
                }
            }
        }
        else {
            $sizes += @(Find-SgSegmentSizes -Node $value -Depth ($Depth + 1))
        }
    }

    return @($sizes)
}

function Read-SgLocalAuditFile {
    <#
    .SYNOPSIS
    Produces collector-format records from audit logs that were already downloaded locally.

    .PARAMETER Path
    A file or directory. Directories are searched for audit.log*/localaudit.log* including .gz.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Local audit log path not found: $Path"
    }

    if (Test-Path -LiteralPath $Path -PathType Container) {
        $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File | Where-Object { $_.Name -like 'audit.log*' -or $_.Name -like 'localaudit.log*' })
    }
    else {
        $files = @(Get-Item -LiteralPath $Path)
    }

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($file in $files) {
        $total = 0
        $emitted = 0
        $stream = $null
        $reader = $null
        try {
            $stream = [System.IO.File]::OpenRead($file.FullName)
            if ($file.Name -like '*.gz') {
                $stream = New-Object System.IO.Compression.GZipStream($stream, [System.IO.Compression.CompressionMode]::Decompress)
            }
            $reader = New-Object System.IO.StreamReader($stream)
            while ($null -ne ($line = $reader.ReadLine())) {
                if ($line -notmatch 'ATYP\(FC32\):SPUT') { continue }
                $total++
                $sizeMatch = [regex]::Match($line, 'CSIZ\(UI64\):(?<size>[0-9]+)')
                if (-not $sizeMatch.Success) { continue }
                $size = 0L
                if (-not [long]::TryParse($sizeMatch.Groups['size'].Value, [ref]$size)) { continue }
                if ($size -lt $script:SgCollectionThresholdBytes) { continue }
                $emitted++
                $lines.Add(("H`t{0}`t{1}`t{2}" -f 'local', $file.FullName, $line))
            }
        }
        finally {
            if ($null -ne $reader) { $reader.Dispose() }
            elseif ($null -ne $stream) { $stream.Dispose() }
        }
        $lines.Add(("S`tlocal`t{0}`t{1}`t{2}" -f $file.FullName, $total, $emitted))
    }

    return ,@($lines.ToArray())
}

Export-ModuleMember -Function @(
    'ConvertTo-SgScanPeriod',
    'Get-SgAuditScanPlan',
    'New-SgAuditScanScript',
    'Invoke-SgRemoteAuditScan',
    'Read-SgLocalAuditFile',
    'ConvertFrom-SgAuditMessage',
    'ConvertFrom-SgSputRecord',
    'ConvertFrom-SgCollectorOutput',
    'Get-SgRegexComparison',
    'Add-SgObjectMetadataVerification',
    'Find-SgSegmentSizes'
)
