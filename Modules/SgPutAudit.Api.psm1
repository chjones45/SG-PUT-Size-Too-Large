# StorageGRID Management API helpers for the large-PUT audit tool.
# Connection, TLS/proxy and payload-normalization logic is ported from
# Modules\AsBuilt.StorageGrid.psm1 so this tool stays portable and standalone.

Set-StrictMode -Version Latest
$script:SgObjectMetadataShapes = @()

function Set-SgTlsPolicy {
    param([Parameter(Mandatory = $true)][bool]$ValidateCertificates)

    $protocols = [Net.SecurityProtocolType]::Tls12
    try { $protocols = $protocols -bor [Net.SecurityProtocolType]::Tls11 } catch { }
    try { $protocols = $protocols -bor [Net.SecurityProtocolType]::Tls } catch { }

    [Net.ServicePointManager]::SecurityProtocol = $protocols
    [System.Net.ServicePointManager]::Expect100Continue = $false

    if (-not ("SgTrustAllCertsCallback" -as [type])) {
        Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class SgTrustAllCertsCallback
{
    public static readonly RemoteCertificateValidationCallback Callback =
        delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        };
}
"@
    }

    if (-not $ValidateCertificates) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SgTrustAllCertsCallback]::Callback
    }
    else {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    # PowerShell 7+ honours -SkipCertificateCheck per request; 5.1 relies on the callback above.
    return (
        -not $ValidateCertificates -and
        $PSVersionTable.PSVersion.Major -ge 6 -and
        (Get-Command Invoke-RestMethod).Parameters.ContainsKey('SkipCertificateCheck')
    )
}

function Set-SgProxyPolicy {
    param([Parameter(Mandatory = $true)][bool]$UseProxy)

    if (-not $UseProxy) {
        [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy
    }
}

function Get-SgExceptionMessageChain {
    param([Parameter(Mandatory = $true)][System.Exception]$Exception)

    $messages = New-Object System.Collections.Generic.List[string]
    $cursor = $Exception
    while ($null -ne $cursor) {
        if (-not [string]::IsNullOrWhiteSpace($cursor.Message)) { $messages.Add($cursor.Message) }
        $cursor = $cursor.InnerException
    }

    if ($messages.Count -eq 0) { return "Unknown request failure" }
    return ($messages -join " | ")
}

function Get-SgPropertyValue {
    param(
        [Parameter(Mandatory = $false)]$Object,
        [Parameter(Mandatory = $false)][string]$PropertyName
    )

    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($PropertyName)) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($PropertyName)) { return $Object[$PropertyName] }
        return $null
    }

    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function ConvertTo-SgArray {
    <#
    .SYNOPSIS
    Normalizes a payload to a flat sequence of items.

    .NOTES
    Deliberately emits the items rather than using the `,$array` return idiom: that idiom only
    survives direct assignment, and every call site here wraps the result in @(), which would
    otherwise yield a single element containing the whole array.
    #>
    param([Parameter(Mandatory = $false)]$Payload)

    if ($null -eq $Payload) { return @() }
    if ($Payload -is [string] -or $Payload -is [valuetype]) { return @($Payload) }
    if ($Payload -is [System.Collections.IDictionary]) { return @($Payload) }
    return @($Payload)
}

function ConvertTo-SgNormalizedPayload {
    param([Parameter(Mandatory = $false)]$Payload)

    if ($null -eq $Payload) { return $null }

    # StorageGRID API v4 wraps responses in { "data": ..., "apiVersion": ... }.
    $apiVersionProp = $Payload.PSObject.Properties["apiVersion"]
    if ($null -ne $apiVersionProp) {
        $dataProp = $Payload.PSObject.Properties["data"]
        if ($null -ne $dataProp) {
            if ($dataProp.Value -is [array]) { return ,$dataProp.Value }
            return $dataProp.Value
        }
        return $null
    }

    return $Payload
}

function Resolve-SgRecordCollection {
    <#
    .SYNOPSIS
    Extracts a flat array of records from a payload, unwrapping container shapes.

    .DESCRIPTION
    StorageGRID endpoints are not consistent about returning a bare array. The same logical
    collection can arrive as a bare array, as a single object wrapping an array
    (for example { "nodes": [...] }), or as an id-keyed map ({ "<id>": {...} }). This resolves
    all three to a flat array, using IdentifyingProperties to recognise a real record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]$Payload,
        [Parameter(Mandatory = $false)][string[]]$IdentifyingProperties = @('id', 'name'),
        [Parameter(Mandatory = $false)][int]$Depth = 0
    )

    if ($null -eq $Payload -or $Depth -gt 4) { return ,@() }

    $testRecord = {
        param($Candidate)
        if ($null -eq $Candidate -or $Candidate -is [string] -or $Candidate -is [valuetype]) { return $false }
        foreach ($propertyName in $IdentifyingProperties) {
            if ($null -ne (Get-SgPropertyValue -Object $Candidate -PropertyName $propertyName)) { return $true }
        }
        return $false
    }

    $items = @($Payload)
    if ($items.Count -eq 0) { return ,@() }
    if (@($items | Where-Object { & $testRecord $_ }).Count -gt 0) {
        return ,@($items | Where-Object { & $testRecord $_ })
    }

    # Single container object: descend into an array-valued property, or treat it as an id-keyed map.
    if ($items.Count -eq 1) {
        $container = $items[0]
        if ($container -is [string] -or $container -is [valuetype]) { return ,@() }

        $propertyNames = @()
        if ($container -is [System.Collections.IDictionary]) { $propertyNames = @($container.Keys) }
        else { $propertyNames = @($container.PSObject.Properties.Name) }

        foreach ($propertyName in $propertyNames) {
            $value = Get-SgPropertyValue -Object $container -PropertyName ([string]$propertyName)
            if ($value -is [array]) {
                $nested = Resolve-SgRecordCollection -Payload $value -IdentifyingProperties $IdentifyingProperties -Depth ($Depth + 1)
                if (@($nested).Count -gt 0) { return ,@($nested) }
            }
        }

        $mapped = @()
        foreach ($propertyName in $propertyNames) {
            $value = Get-SgPropertyValue -Object $container -PropertyName ([string]$propertyName)
            if ($null -eq $value -or $value -is [string] -or $value -is [valuetype] -or $value -is [array]) { continue }
            if ($null -eq (Get-SgPropertyValue -Object $value -PropertyName 'id')) {
                $value | Add-Member -NotePropertyName 'id' -NotePropertyValue ([string]$propertyName) -Force -ErrorAction SilentlyContinue
            }
            $mapped += $value
        }
        if ($mapped.Count -gt 0) { return ,@($mapped) }
    }

    return ,@()
}

function Resolve-SgBaseUrl {
    param([Parameter(Mandatory = $true)][string]$Target)

    $resolved = $Target.Trim()
    if ($resolved -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $resolved = "https://$resolved" }
    $resolved = $resolved.TrimEnd('/')
    if ($resolved -notmatch '^https?://') {
        throw "StorageGRID Management API target must use HTTP or HTTPS: $resolved"
    }
    if ($resolved -match '^(https?://[^/]+)/api.*$') { $resolved = $Matches[1] }
    return $resolved
}

function Connect-SgGrid {
    <#
    .SYNOPSIS
    Authenticates against the StorageGRID Management API and returns a reusable session object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)][switch]$ValidateCerts,
        [Parameter(Mandatory = $false)][switch]$UseSystemProxy
    )

    $baseUrl = Resolve-SgBaseUrl -Target $Target
    $skipCertCheck = Set-SgTlsPolicy -ValidateCertificates $ValidateCerts.IsPresent
    Set-SgProxyPolicy -UseProxy $UseSystemProxy.IsPresent

    $plainPassword = [System.Net.NetworkCredential]::new("", $Credential.Password).Password
    $body = @{
        username  = $Credential.UserName
        password  = $plainPassword
        cookie    = $false
        csrfToken = $false
    } | ConvertTo-Json

    $invokeParams = @{
        Uri         = "$baseUrl/api/v4/authorize"
        Method      = "POST"
        Body        = $body
        ContentType = "application/json"
        Headers     = @{ Accept = "application/json" }
        ErrorAction = "Stop"
    }
    if ($skipCertCheck) { $invokeParams.SkipCertificateCheck = $true }

    try {
        $response = Invoke-RestMethod @invokeParams
        $token = Get-SgPropertyValue -Object $response -PropertyName "data"
        if ([string]::IsNullOrWhiteSpace([string]$token)) {
            throw "Authorization response did not contain a token in the 'data' field."
        }
    }
    catch {
        throw "StorageGRID authentication failed: " + (Get-SgExceptionMessageChain -Exception $_.Exception)
    }

    return [pscustomobject]@{
        BaseUrl       = $baseUrl
        Token         = [string]$token
        SkipCertCheck = [bool]$skipCertCheck
    }
}

function Invoke-SgApi {
    <#
    .SYNOPSIS
    Issues a StorageGRID Management API request and returns a result envelope instead of throwing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $false)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory = $false)]$Body
    )

    $invokeParams = @{
        Uri         = "$($Session.BaseUrl)/api/v4$Endpoint"
        Method      = $Method
        Headers     = @{
            Accept        = "application/json"
            Authorization = "Bearer $($Session.Token)"
        }
        ErrorAction = "Stop"
    }
    if ($Session.SkipCertCheck) { $invokeParams.SkipCertificateCheck = $true }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $invokeParams.Body = $Body
        $invokeParams.ContentType = "application/json"
    }

    try {
        $response = Invoke-RestMethod @invokeParams
        return [pscustomobject]@{
            Endpoint = $Endpoint
            Failed   = $false
            Status   = 200
            Data     = ConvertTo-SgNormalizedPayload -Payload $response
            Message  = ""
        }
    }
    catch {
        $status = "N/A"
        try {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode
            }
        }
        catch { $status = "N/A" }

        return [pscustomobject]@{
            Endpoint = $Endpoint
            Failed   = $true
            Status   = $status
            Data     = $null
            Message  = Get-SgExceptionMessageChain -Exception $_.Exception
        }
    }
}

function Get-SgClientWriteAuditLevel {
    <#
    .SYNOPSIS
    Reads /grid/audit and reports whether clientWrites retains the SPUT messages this tool needs.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    $response = Invoke-SgApi -Session $Session -Endpoint '/grid/audit'
    if ($response.Failed) {
        throw "Unable to read the grid audit configuration (/grid/audit): $($response.Message)"
    }

    $levels = Get-SgPropertyValue -Object $response.Data -PropertyName 'levels'
    $clientWrites = [string](Get-SgPropertyValue -Object $levels -PropertyName 'clientWrites')
    $loggedHeaders = [object[]]@(ConvertTo-SgArray -Payload (Get-SgPropertyValue -Object $response.Data -PropertyName 'loggedHeaders'))

    return [pscustomobject]@{
        ClientWrites  = $clientWrites
        IsSufficient  = ($clientWrites -in @('normal', 'debug'))
        LoggedHeaders = [object[]]$loggedHeaders
        AllLevels     = $levels
    }
}

function Get-SgAuditDestination {
    <#
    .SYNOPSIS
    Reads /private/audit-destinations and resolves where SPUT audit messages are written.

    .DESCRIPTION
    When adminNodes.enabled is true, every node forwards audit messages to the Admin Nodes and the
    complete record is available from the Primary Admin Node alone. Otherwise each node retains its
    own messages locally and every Storage Node must be scanned.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    $response = Invoke-SgApi -Session $Session -Endpoint '/private/audit-destinations'
    if ($response.Failed) {
        throw "Unable to read the audit destination configuration (/private/audit-destinations): $($response.Message)"
    }

    $defaults = Get-SgPropertyValue -Object $response.Data -PropertyName 'defaults'
    if ($null -eq $defaults) { $defaults = $response.Data }

    $adminNodes = Get-SgPropertyValue -Object $defaults -PropertyName 'adminNodes'
    $localNodes = Get-SgPropertyValue -Object $defaults -PropertyName 'localNodes'
    $remoteSyslog = Get-SgPropertyValue -Object $defaults -PropertyName 'remoteSyslogServerA'
    if ($null -eq $remoteSyslog) {
        $remoteSyslog = Get-SgPropertyValue -Object $defaults -PropertyName 'remoteSyslogServerATest'
    }

    $adminEnabled = [bool](Get-SgPropertyValue -Object $adminNodes -PropertyName 'enabled')
    $localEnabled = $true
    $localEnabledRaw = Get-SgPropertyValue -Object $localNodes -PropertyName 'enabled'
    if ($null -ne $localEnabledRaw) { $localEnabled = [bool]$localEnabledRaw }

    if ($adminEnabled) {
        $scope = 'AdminNodes'
        $logDirectory = '/var/local/audit/export'
        $logGlob = 'audit.log*'
    }
    else {
        $scope = 'LocalNodes'
        $logDirectory = '/var/local/log'
        $logGlob = 'localaudit.log*'
    }

    return [pscustomobject]@{
        Scope                = $scope
        AdminNodesEnabled    = $adminEnabled
        LocalNodesEnabled    = $localEnabled
        RemoteSyslogEnabled  = [bool](Get-SgPropertyValue -Object $remoteSyslog -PropertyName 'enabled')
        RemoteSyslogHostname = [string](Get-SgPropertyValue -Object $remoteSyslog -PropertyName 'hostname')
        AuditLogsToSyslog    = [bool](Get-SgPropertyValue -Object $remoteSyslog -PropertyName 'auditLogsSend')
        LogDirectory         = $logDirectory
        LogGlob              = $logGlob
        Raw                  = $defaults
    }
}

function Get-SgNodeInventory {
    <#
    .SYNOPSIS
    Builds a node inventory (name, site, type, grid/admin IP) from node-health and network-topology.

    .DESCRIPTION
    node-health supplies the site name, node type and primary-admin flag; network-topology supplies
    the hostname and grid/admin IPs used for SSH. Either source alone is enough to produce a usable
    inventory, so records are merged by node ID and topology-only nodes are still returned.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    $healthResponse = Invoke-SgApi -Session $Session -Endpoint '/grid/node-health'
    if ($healthResponse.Failed) {
        throw "Unable to read node health (/grid/node-health): $($healthResponse.Message)"
    }
    $topologyResponse = Invoke-SgApi -Session $Session -Endpoint '/private/network-topology'

    $healthRecords = Resolve-SgRecordCollection -Payload $healthResponse.Data -IdentifyingProperties @('id', 'name', 'type')
    Write-Verbose "[NodeInventory] node-health records: $(@($healthRecords).Count)"

    $configByNodeId = @{}
    $configOrder = @()
    if (-not $topologyResponse.Failed) {
        $gridNodes = Resolve-SgRecordCollection -Payload (Get-SgPropertyValue -Object $topologyResponse.Data -PropertyName 'gridNodes') -IdentifyingProperties @('nodeConfig', 'nodeId', 'hostname')
        foreach ($gridNode in @($gridNodes)) {
            $nodeConfig = Get-SgPropertyValue -Object $gridNode -PropertyName 'nodeConfig'
            if ($null -eq $nodeConfig) { $nodeConfig = $gridNode }
            $configNodeId = [string](Get-SgPropertyValue -Object $nodeConfig -PropertyName 'nodeId')
            if ([string]::IsNullOrWhiteSpace($configNodeId)) { continue }
            $configByNodeId[$configNodeId] = $nodeConfig
            $configOrder += $configNodeId
        }
    }
    Write-Verbose "[NodeInventory] network-topology nodeConfigs: $($configByNodeId.Count)"

    $buildNode = {
        param($HealthNode, $NodeConfig, [string]$NodeId)

        $networking = Get-SgPropertyValue -Object $NodeConfig -PropertyName 'networking'
        $gridCidr = [string](Get-SgPropertyValue -Object (Get-SgPropertyValue -Object $networking -PropertyName 'grid') -PropertyName 'cidr')
        $adminCidr = [string](Get-SgPropertyValue -Object (Get-SgPropertyValue -Object $networking -PropertyName 'admin') -PropertyName 'cidr')

        $name = [string](Get-SgPropertyValue -Object $HealthNode -PropertyName 'name')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = [string](Get-SgPropertyValue -Object $NodeConfig -PropertyName 'hostname') }

        $type = [string](Get-SgPropertyValue -Object $HealthNode -PropertyName 'type')
        if ([string]::IsNullOrWhiteSpace($type)) { $type = [string](Get-SgPropertyValue -Object $NodeConfig -PropertyName 'nodeType') }

        return [pscustomobject]@{
            NodeId         = $NodeId
            Name           = $name
            SiteName       = [string](Get-SgPropertyValue -Object $HealthNode -PropertyName 'siteName')
            Type           = $type
            IsPrimaryAdmin = [bool](Get-SgPropertyValue -Object $HealthNode -PropertyName 'isPrimaryAdmin')
            Severity       = [string](Get-SgPropertyValue -Object $HealthNode -PropertyName 'severity')
            Platform       = [string](Get-SgPropertyValue -Object $NodeConfig -PropertyName 'platform')
            GridIp         = ($gridCidr -split '/')[0]
            AdminIp        = ($adminCidr -split '/')[0]
        }
    }

    $nodes = @()
    $seenNodeIds = @{}
    foreach ($healthNode in @($healthRecords)) {
        $nodeId = [string](Get-SgPropertyValue -Object $healthNode -PropertyName 'id')
        $nodeConfig = $null
        if (-not [string]::IsNullOrWhiteSpace($nodeId) -and $configByNodeId.ContainsKey($nodeId)) {
            $nodeConfig = $configByNodeId[$nodeId]
            $seenNodeIds[$nodeId] = $true
        }
        $nodes += & $buildNode $healthNode $nodeConfig $nodeId
    }

    # Topology-only nodes still give us a hostname and grid IP, which is all the collector needs.
    foreach ($nodeId in @($configOrder | Select-Object -Unique)) {
        if ($seenNodeIds.ContainsKey($nodeId)) { continue }
        $nodes += & $buildNode $null $configByNodeId[$nodeId] $nodeId
    }

    $nodes = @($nodes | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })
    return ,@($nodes | Sort-Object SiteName, Name)
}

function Get-SgTenantAccountMap {
    <#
    .SYNOPSIS
    Returns a hashtable of tenant account ID -> account name for resolving the S3AI audit field.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    $map = @{}
    $response = Invoke-SgApi -Session $Session -Endpoint '/grid/accounts'
    if ($response.Failed) {
        Write-Warning "Unable to read tenant accounts (/grid/accounts): $($response.Message). Tenant names will show as N/A."
        return $map
    }

    foreach ($account in @(Resolve-SgRecordCollection -Payload $response.Data -IdentifyingProperties @('id', 'name'))) {
        $accountId = [string](Get-SgPropertyValue -Object $account -PropertyName 'id')
        if ([string]::IsNullOrWhiteSpace($accountId)) { continue }
        $map[$accountId] = [string](Get-SgPropertyValue -Object $account -PropertyName 'name')
    }
    return $map
}

function Get-SgObjectMetadata {
    <#
    .SYNOPSIS
    Performs an object metadata lookup via /grid/object-metadata.

    .DESCRIPTION
    The Grid Manager "ILM > Object metadata lookup" page posts an identifier (UUID, CBID or
    bucket/key) to /grid/object-metadata. The exact request shape has varied between releases, so
    this function probes the known shapes once and then reuses whichever the grid accepted.

    .PARAMETER Identifier
    A UUID (uppercase), a CBID (uppercase, 0x-prefixed) or an "S3-bucket/object-key" string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$Identifier,
        [Parameter(Mandatory = $false)][string]$VersionId
    )

    if (-not $script:SgObjectMetadataShapes) {
        $script:SgObjectMetadataShapes = @('StringBody', 'IdentifierObject', 'ObjectIdObject')
    }

    $lastMessage = ""
    foreach ($shape in @($script:SgObjectMetadataShapes)) {
        $supportsVersionRetry = $false
        if ($shape -eq 'StringBody') {
            $body = ConvertTo-Json -InputObject $Identifier
        }
        elseif ($shape -eq 'IdentifierObject') {
            $payload = @{ identifier = $Identifier }
            if (-not [string]::IsNullOrWhiteSpace($VersionId)) { $payload.versionId = $VersionId }
            $body = ConvertTo-Json -InputObject $payload -Compress
            $supportsVersionRetry = $true
        }
        else {
            $payload = @{ objectId = $Identifier }
            if (-not [string]::IsNullOrWhiteSpace($VersionId)) { $payload.versionId = $VersionId }
            $body = ConvertTo-Json -InputObject $payload -Compress
            $supportsVersionRetry = $true
        }

        $response = Invoke-SgApi -Session $Session -Endpoint '/grid/object-metadata' -Method POST -Body $body
        if (-not $response.Failed) {
            # Remember the accepted shape so later lookups do not repeat the probe.
            $script:SgObjectMetadataShapes = @($shape)
            return [pscustomobject]@{
                Identifier = $Identifier
                Found      = $true
                Shape      = $shape
                Data       = $response.Data
                Message    = ""
            }
        }

        if ($response.Status -eq 400 -and $supportsVersionRetry -and -not [string]::IsNullOrWhiteSpace($VersionId)) {
            if ($shape -eq 'IdentifierObject') { $retryBody = ConvertTo-Json -InputObject @{ identifier = $Identifier } -Compress }
            else { $retryBody = ConvertTo-Json -InputObject @{ objectId = $Identifier } -Compress }

            $retryResponse = Invoke-SgApi -Session $Session -Endpoint '/grid/object-metadata' -Method POST -Body $retryBody
            if (-not $retryResponse.Failed) {
                $script:SgObjectMetadataShapes = @($shape)
                return [pscustomobject]@{
                    Identifier = $Identifier
                    Found      = $true
                    Shape      = $shape
                    Data       = $retryResponse.Data
                    Message    = ""
                }
            }

            $lastMessage = $retryResponse.Message
            if ($retryResponse.Status -eq 404) { break }
            continue
        }

        $lastMessage = $response.Message
        # A 404/400 on a valid shape means the object is gone, not that the shape is wrong.
        if ($response.Status -eq 404) { break }
    }

    return [pscustomobject]@{
        Identifier = $Identifier
        Found      = $false
        Shape      = ""
        Data       = $null
        Message    = $lastMessage
    }
}

Export-ModuleMember -Function @(
    'Set-SgTlsPolicy',
    'Set-SgProxyPolicy',
    'Get-SgPropertyValue',
    'ConvertTo-SgArray',
    'Resolve-SgRecordCollection',
    'Resolve-SgBaseUrl',
    'Connect-SgGrid',
    'Invoke-SgApi',
    'Get-SgClientWriteAuditLevel',
    'Get-SgAuditDestination',
    'Get-SgNodeInventory',
    'Get-SgTenantAccountMap',
    'Get-SgObjectMetadata'
)
