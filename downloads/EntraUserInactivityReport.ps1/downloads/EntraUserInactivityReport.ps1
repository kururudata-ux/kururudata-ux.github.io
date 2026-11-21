#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$RequiredSignedInAccount,
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,
    [switch]$GenerateSampleData,
    [ValidateRange(100, 100000)]
    [int]$SampleUserCount = 5000,
    [string]$OutputDirectory = (Join-Path (Get-Location).Path ("EntraUserInactivity_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-GraphCollection {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next
        $valueData = Get-PropertyValue -Object $response -Name 'value'
        if ($null -eq $valueData) {
            $errorData = Get-PropertyValue -Object $response -Name 'error'
            if ($null -ne $errorData) {
                $errorCode = [string](Get-PropertyValue -Object $errorData -Name 'code')
                $errorMessage = [string](Get-PropertyValue -Object $errorData -Name 'message')
                throw ("Graph API returned an error. Code: {0} Message: {1}" -f $errorCode, $errorMessage)
            }
            if ($response -is [System.Collections.IDictionary]) {
                $actualProps = @($response.Keys) -join ', '
            }
            else {
                $actualProps = @($response.PSObject.Properties | ForEach-Object { $_.Name }) -join ', '
            }
            throw ("Unexpected Graph response shape. Expected 'value'. Actual properties: {0}" -f $actualProps)
        }

        foreach ($item in @($valueData)) {
            $items.Add($item)
        }
        $nextValue = Get-PropertyValue -Object $response -Name '@odata.nextLink'
        $next = if ($nextValue) { [string]$nextValue } else { $null }
    }
    return $items.ToArray()
}

function Ensure-GraphConnection {
    param(
        [string]$TargetTenantId,
        [string]$AccountCheck
    )

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph PowerShell SDK was not found. Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $connectParams = @{
        Scopes       = @('User.Read.All', 'Directory.Read.All', 'AuditLog.Read.All')
        NoWelcome    = $true
        ContextScope = 'Process'
    }
    if ($TargetTenantId) {
        $connectParams['TenantId'] = $TargetTenantId
    }

    Connect-MgGraph @connectParams | Out-Null
    $ctx = Get-MgContext
    if (-not $ctx) {
        throw 'Microsoft Graph connection failed.'
    }

    if ($AccountCheck) {
        if ([string]::IsNullOrWhiteSpace([string]$ctx.Account)) {
            throw "Signed-in account could not be detected. Expected account: $AccountCheck"
        }
        if ($ctx.Account.ToLowerInvariant() -ne $AccountCheck.ToLowerInvariant()) {
            throw "Signed-in account mismatch. Current: $($ctx.Account) / Expected: $AccountCheck"
        }
    }

    Write-Host ("Connected account : {0}" -f $ctx.Account) -ForegroundColor Green
    Write-Host ("Connected tenant  : {0}" -f $ctx.TenantId) -ForegroundColor Green
}

function New-OutputDirectory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) {
            return $Object[$Name]
        }
        return $null
    }

    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop) {
        return $prop.Value
    }
    return $null
}

function Get-LastSignInDateTime {
    param($UserObject)

    $candidates = @()
    $signInActivity = Get-PropertyValue -Object $UserObject -Name 'signInActivity'
    if ($null -ne $signInActivity) {
        $lastSignInValue = Get-PropertyValue -Object $signInActivity -Name 'lastSignInDateTime'
        if ($lastSignInValue) {
            $candidates += [string]$lastSignInValue
        }
        $lastNonInteractiveValue = Get-PropertyValue -Object $signInActivity -Name 'lastNonInteractiveSignInDateTime'
        if ($lastNonInteractiveValue) {
            $candidates += [string]$lastNonInteractiveValue
        }
    }

    $parsed = New-Object System.Collections.Generic.List[DateTimeOffset]
    foreach ($item in $candidates) {
        $candidateValue = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse([string]$item, [ref]$candidateValue)) {
            $parsed.Add($candidateValue)
        }
    }

    if ($parsed.Count -eq 0) {
        return $null
    }

    return ($parsed.ToArray() | Sort-Object -Descending | Select-Object -First 1)
}

function Get-UserType {
    param($UserObject)

    $value = [string](Get-PropertyValue -Object $UserObject -Name 'userType')
    if ([string]::IsNullOrWhiteSpace($value)) {
        return 'Unknown'
    }
    return $value
}

function Get-InactiveCategory {
    param(
        $LastSignIn,
        [Parameter(Mandatory)][DateTime]$InactiveCutoff,
        [Parameter(Mandatory)][int]$ThresholdDays
    )

    if ($null -eq $LastSignIn) {
        return 'NoSignInRecord'
    }

    if ($LastSignIn.LocalDateTime -lt $InactiveCutoff) {
        return "NoRecentSignIn(>${ThresholdDays}d)"
    }

    return 'Active'
}

function New-HtmlTable {
    param(
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)]$Rows
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<div class="table-wrap"><table>')
    [void]$sb.AppendLine('<thead><tr>')
    foreach ($header in $Headers) {
        [void]$sb.AppendLine(('<th>{0}</th>' -f [System.Net.WebUtility]::HtmlEncode($header)))
    }
    [void]$sb.AppendLine('</tr></thead>')
    [void]$sb.AppendLine('<tbody>')
    foreach ($row in $Rows) {
        [void]$sb.AppendLine('<tr>')
        foreach ($header in $Headers) {
            [void]$sb.AppendLine(('<td>{0}</td>' -f [System.Net.WebUtility]::HtmlEncode([string]$row.$header)))
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody>')
    [void]$sb.AppendLine('</table></div>')
    return $sb.ToString()
}

if (-not $GenerateSampleData) {
    Ensure-GraphConnection -TargetTenantId $TenantId -AccountCheck $RequiredSignedInAccount
}

$resolvedOutputDir = New-OutputDirectory -Path $OutputDirectory

if ($GenerateSampleData) {
    Write-Host ("Generating {0:N0} sample users..." -f $SampleUserCount) -ForegroundColor Cyan
    $users = @(1..$SampleUserCount | ForEach-Object {
            $idx = $_
            $userType = if ($idx % 13 -eq 0) { 'Guest' } elseif ($idx % 29 -eq 0) { 'Unknown' } else { 'Member' }
            $lastSignIn = if ($idx % 17 -eq 0) {
                $null
            }
            elseif ($idx % 11 -eq 0) {
                (Get-Date).AddDays(-1 * ($InactiveDays + 1 + ($idx % 180))).ToString('o')
            }
            else {
                (Get-Date).AddDays(-1 * ($idx % [Math]::Max(2, $InactiveDays - 1))).ToString('o')
            }

            [pscustomobject]@{
                id                = 'sample-user-{0:D6}' -f $idx
                displayName       = 'Sample User {0:D6}' -f $idx
                userPrincipalName = 'sample.user{0:D6}@example.invalid' -f $idx
                mail              = 'sample.user{0:D6}@example.invalid' -f $idx
                accountEnabled    = ($idx % 31 -ne 0)
                userType          = $userType
                createdDateTime   = (Get-Date).AddDays(-1 * ($idx % 2000)).ToString('o')
                signInActivity    = [pscustomobject]@{
                    lastSignInDateTime               = $lastSignIn
                    lastNonInteractiveSignInDateTime = $lastSignIn
                }
            }
        })
}
else {
    Write-Host 'Loading users...' -ForegroundColor Cyan
    $users = Invoke-GraphCollection -Uri "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,signInActivity&`$top=999"
}

$inactiveCutoff = (Get-Date).AddDays(-1 * $InactiveDays)
$allUserRows = New-Object System.Collections.Generic.List[object]
$inactiveUserRows = New-Object System.Collections.Generic.List[object]

foreach ($u in @($users)) {
    $lastSignIn = Get-LastSignInDateTime -UserObject $u
    $inactiveCategory = Get-InactiveCategory -LastSignIn $lastSignIn -InactiveCutoff $inactiveCutoff -ThresholdDays $InactiveDays
    $userType = Get-UserType -UserObject $u
    $inactiveDaysSince = ''
    if ($lastSignIn) {
        $inactiveDaysSince = [string][Math]::Floor(((Get-Date) - $lastSignIn.LocalDateTime).TotalDays)
    }

    $row = [pscustomobject]@{
        UserId                  = [string](Get-PropertyValue -Object $u -Name 'id')
        UserPrincipalName       = [string](Get-PropertyValue -Object $u -Name 'userPrincipalName')
        DisplayName             = [string](Get-PropertyValue -Object $u -Name 'displayName')
        UserType                = [string]$userType
        AccountEnabled          = [string](Get-PropertyValue -Object $u -Name 'accountEnabled')
        LastSignInDateTime      = if ($lastSignIn) { $lastSignIn.ToString('o') } else { '' }
        InactiveCategory        = [string]$inactiveCategory
        InactiveDaysSinceSignIn = [string]$inactiveDaysSince
    }
    $allUserRows.Add($row)
    if ($inactiveCategory -ne 'Active') {
        $inactiveUserRows.Add($row)
    }
}

$userTypeSummaryRows = New-Object System.Collections.Generic.List[object]
$groupedByType = @($allUserRows | Group-Object UserType | Sort-Object Name)
foreach ($group in $groupedByType) {
    $typeRows = @($group.Group)
    $total = $typeRows.Count
    $noSignIn = @($typeRows | Where-Object { $_.InactiveCategory -eq 'NoSignInRecord' }).Count
    $noRecent = @($typeRows | Where-Object { $_.InactiveCategory -like 'NoRecentSignIn*' }).Count
    $unused = $noSignIn + $noRecent
    $rate = if ($total -gt 0) { [Math]::Round(($unused * 100.0) / $total, 2) } else { 0 }

    $userTypeSummaryRows.Add([pscustomobject]@{
            UserType           = [string]$group.Name
            TotalUsers         = [string]$total
            UnusedUsers        = [string]$unused
            NoSignInUsers      = [string]$noSignIn
            NoRecentSignInUsers = [string]$noRecent
            UnusedRatePercent  = ('{0:N2}' -f $rate)
        })
}

$ctx = if ($GenerateSampleData) { $null } else { Get-MgContext }
$summary = [pscustomobject]@{
    DataSource           = if ($GenerateSampleData) { "Generated sample data ($SampleUserCount users)" } else { 'Microsoft Entra ID' }
    GeneratedAt          = (Get-Date).ToString('o')
    TenantId             = if ($GenerateSampleData) { 'sample-tenant' } else { $ctx.TenantId }
    SignedInAccount      = if ($GenerateSampleData) { 'sample-data@example.invalid' } else { $ctx.Account }
    InactiveThresholdDays = $InactiveDays
    TotalUsers           = $allUserRows.Count
    InactiveUsers        = $inactiveUserRows.Count
    NoSignInUsers        = @($inactiveUserRows | Where-Object { $_.InactiveCategory -eq 'NoSignInRecord' }).Count
    NoRecentSignInUsers  = @($inactiveUserRows | Where-Object { $_.InactiveCategory -like 'NoRecentSignIn*' }).Count
    UserTypes            = $groupedByType.Count
}

$paths = [ordered]@{
    SummaryJson          = Join-Path $resolvedOutputDir 'Summary.json'
    AllUsersCsv          = Join-Path $resolvedOutputDir 'Users.csv'
    InactiveUsersCsv     = Join-Path $resolvedOutputDir 'InactiveUsers.csv'
    UserTypeSummaryCsv   = Join-Path $resolvedOutputDir 'UserTypeSummary.csv'
    MarkdownReport       = Join-Path $resolvedOutputDir 'Report.md'
    HtmlReport           = Join-Path $resolvedOutputDir 'Report.html'
}

$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $paths.SummaryJson -Encoding UTF8
$allUserRows | Export-Csv -LiteralPath $paths.AllUsersCsv -NoTypeInformation -Encoding UTF8
$inactiveUserRows | Export-Csv -LiteralPath $paths.InactiveUsersCsv -NoTypeInformation -Encoding UTF8
$userTypeSummaryRows | Export-Csv -LiteralPath $paths.UserTypeSummaryCsv -NoTypeInformation -Encoding UTF8

$reportLines = New-Object System.Collections.Generic.List[string]
$reportLines.Add('# Entra ID User Inactivity Report')
$reportLines.Add('')
$reportLines.Add(('GeneratedAt: {0}' -f $summary.GeneratedAt))
$reportLines.Add(('TenantId: {0}' -f $summary.TenantId))
$reportLines.Add(('SignedInAccount: {0}' -f $summary.SignedInAccount))
$reportLines.Add('')
$reportLines.Add('## Summary')
$reportLines.Add('')
$reportLines.Add(('Total users: {0}' -f $summary.TotalUsers))
$reportLines.Add(('Inactive users: {0}' -f $summary.InactiveUsers))
$reportLines.Add(('No sign-in record: {0}' -f $summary.NoSignInUsers))
$reportLines.Add(('No recent sign-in (>{0} days): {1}' -f $summary.InactiveThresholdDays, $summary.NoRecentSignInUsers))
$reportLines.Add('')
$reportLines.Add('## User type summary')
$reportLines.Add('')
$reportLines.Add('| UserType | TotalUsers | UnusedUsers | NoSignInUsers | NoRecentSignInUsers | UnusedRatePercent |')
$reportLines.Add('| --- | ---: | ---: | ---: | ---: | ---: |')
foreach ($r in $userTypeSummaryRows) {
    $reportLines.Add(('| {0} | {1} | {2} | {3} | {4} | {5}% |' -f $r.UserType, $r.TotalUsers, $r.UnusedUsers, $r.NoSignInUsers, $r.NoRecentSignInUsers, $r.UnusedRatePercent))
}
$reportLines.Add('')
$reportLines.Add('## Output files')
$reportLines.Add('')
foreach ($entry in $paths.GetEnumerator()) {
    $reportLines.Add(('- {0}: {1}' -f $entry.Key, (Split-Path -Leaf $entry.Value)))
}
$reportLines -join [Environment]::NewLine | Set-Content -LiteralPath $paths.MarkdownReport -Encoding UTF8

$summaryHtml = New-HtmlTable -Headers @(
    'DataSource',
    'GeneratedAt',
    'TenantId',
    'SignedInAccount',
    'InactiveThresholdDays',
    'TotalUsers',
    'InactiveUsers',
    'NoSignInUsers',
    'NoRecentSignInUsers',
    'UserTypes'
) -Rows @($summary)

$userTypeSummaryHtml = New-HtmlTable -Headers @(
    'UserType',
    'TotalUsers',
    'UnusedUsers',
    'NoSignInUsers',
    'NoRecentSignInUsers',
    'UnusedRatePercent'
) -Rows $userTypeSummaryRows

$inactivePreview = @($inactiveUserRows | Sort-Object UserType, UserPrincipalName | Select-Object -First 300)
$inactiveUsersHtml = if ($inactivePreview.Count -gt 0) {
    New-HtmlTable -Headers @(
        'UserPrincipalName',
        'DisplayName',
        'UserType',
        'AccountEnabled',
        'LastSignInDateTime',
        'InactiveCategory',
        'InactiveDaysSinceSignIn'
    ) -Rows $inactivePreview
}
else {
    '<p>Inactive users were not detected.</p>'
}

$palette = @('#0078D4', '#107C10', '#8661C5', '#CA5010', '#E81123', '#038387', '#8E562E', '#744DA9', '#986F0B', '#6B69D6')
$pieRows = New-Object System.Collections.Generic.List[object]
$cursor = 0.0
for ($i = 0; $i -lt $groupedByType.Count; $i++) {
    $group = $groupedByType[$i]
    $count = [double]$group.Count
    $ratio = if ($allUserRows.Count -gt 0) { $count / [double]$allUserRows.Count } else { 0 }
    $start = [Math]::Round($cursor * 100, 2)
    $cursor += $ratio
    $end = [Math]::Round($cursor * 100, 2)
    $color = $palette[$i % $palette.Count]
    $pieRows.Add([pscustomobject]@{
            UserType = [string]$group.Name
            Count    = [int]$group.Count
            Share    = ('{0:N2}' -f ([Math]::Round($ratio * 100, 2)))
            Color    = $color
            Start    = $start
            End      = $end
        })
}

$pieSegments = if ($pieRows.Count -gt 0) {
    @($pieRows | ForEach-Object { ('{0} {1}%, {0} {2}%' -f $_.Color, $_.Start, $_.End) }) -join ', '
}
else {
    '#d0d0d0 0%, #d0d0d0 100%'
}

$legendRows = @($pieRows | ForEach-Object {
        [pscustomobject]@{
            UserType = $_.UserType
            Count    = [string]$_.Count
            Share    = ('{0}%' -f $_.Share)
            Color    = $_.Color
        }
    })

$legendHtmlSb = New-Object System.Text.StringBuilder
[void]$legendHtmlSb.AppendLine('<div class="legend">')
foreach ($row in $legendRows) {
    [void]$legendHtmlSb.AppendLine(('<div class="legend-item"><span class="swatch" style="background:{0};"></span><span>{1} ({2} / {3})</span></div>' -f
            [System.Net.WebUtility]::HtmlEncode([string]$row.Color),
            [System.Net.WebUtility]::HtmlEncode([string]$row.UserType),
            [System.Net.WebUtility]::HtmlEncode([string]$row.Count),
            [System.Net.WebUtility]::HtmlEncode([string]$row.Share)))
}
[void]$legendHtmlSb.AppendLine('</div>')
$legendHtml = $legendHtmlSb.ToString()

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Entra ID User Inactivity Report</title>
  <style>
    body { margin: 0; padding: 24px; font-family: "Segoe UI", Arial, sans-serif; background: #f6f8fb; color: #1f2937; }
    .container { max-width: 1400px; margin: 0 auto; }
    .card { background: #fff; border: 1px solid #dce1ea; border-radius: 14px; padding: 20px; margin-bottom: 18px; }
    h1 { margin: 0 0 12px; font-size: 32px; }
    h2 { margin: 0 0 14px; font-size: 22px; }
    .grid { display: grid; grid-template-columns: 420px minmax(0, 1fr); gap: 22px; align-items: start; }
    .kpi-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-top: 14px; }
    .kpi { border: 1px solid #dce1ea; border-radius: 12px; padding: 12px; background: #f8fbff; }
    .kpi .label { font-size: 12px; color: #556070; margin-bottom: 6px; }
    .kpi .value { font-size: 24px; font-weight: 700; color: #0f172a; }
    .pie {
      width: 300px;
      height: 300px;
      border-radius: 50%;
      background: conic-gradient($pieSegments);
      margin: 0 auto;
      border: 1px solid #dce1ea;
      position: relative;
    }
    .pie::after {
      content: "";
      position: absolute;
      inset: 72px;
      border-radius: 50%;
      background: #fff;
      border: 1px solid #dce1ea;
    }
    .legend { display: flex; flex-wrap: wrap; gap: 8px 16px; margin-top: 12px; }
    .legend-item { display: inline-flex; align-items: center; font-size: 13px; color: #1f2937; }
    .swatch { width: 12px; height: 12px; border-radius: 2px; display: inline-block; margin-right: 8px; border: 1px solid #9ca3af; }
    .table-wrap { width: 100%; overflow-x: auto; border: 1px solid #dce1ea; border-radius: 12px; }
    table { border-collapse: collapse; width: 100%; min-width: 720px; font-size: 13px; }
    th, td { border: 1px solid #dce1ea; padding: 8px 10px; text-align: left; vertical-align: top; }
    th { background: #0b3d91; color: #fff; }
    tbody tr:nth-child(even) { background: #f8fbff; }
    .note { color: #5f6b7a; font-size: 12px; margin-top: 8px; }
    @media (max-width: 1024px) {
      .grid { grid-template-columns: 1fr; }
      .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .pie { width: 240px; height: 240px; }
      .pie::after { inset: 55px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>Entra ID User Inactivity Report</h1>
      <p>This report extracts users with no sign-in record and users with no sign-in activity for more than $InactiveDays days.</p>
      $summaryHtml
      <div class="kpi-grid">
        <div class="kpi"><div class="label">Total users</div><div class="value">$($summary.TotalUsers)</div></div>
        <div class="kpi"><div class="label">Inactive users</div><div class="value">$($summary.InactiveUsers)</div></div>
        <div class="kpi"><div class="label">No sign-in record</div><div class="value">$($summary.NoSignInUsers)</div></div>
        <div class="kpi"><div class="label">No sign-in for over $InactiveDays days</div><div class="value">$($summary.NoRecentSignInUsers)</div></div>
      </div>
    </div>

    <div class="card">
      <h2>User type distribution (all users)</h2>
      <div class="grid">
        <div>
          <div class="pie" aria-label="User type distribution"></div>
          $legendHtml
        </div>
        <div>
          <h2>Inactive status by user type</h2>
          $userTypeSummaryHtml
        </div>
      </div>
    </div>

    <div class="card">
      <h2>Inactive users (first 300 rows)</h2>
      $inactiveUsersHtml
      <p class="note">For all rows, see InactiveUsers.csv.</p>
    </div>
  </div>
</body>
</html>
"@

$html | Set-Content -LiteralPath $paths.HtmlReport -Encoding UTF8

Write-Host ''
Write-Host 'Report generation complete. Output files:' -ForegroundColor Green
foreach ($entry in $paths.GetEnumerator()) {
    Write-Host ("- {0}: {1}" -f $entry.Key, $entry.Value)
}
