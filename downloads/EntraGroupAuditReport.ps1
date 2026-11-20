#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$RequiredSignedInAccount,
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,
    [switch]$SkipSignInActivity,
    [switch]$GenerateSampleData,
    [ValidateRange(100, 100000)]
    [int]$SampleGroupCount = 10000,
    [ValidateRange(1, 100000)]
    [int]$DependencyMermaidMaxEdges = 2500,
    [string]$OutputDirectory = (Join-Path (Get-Location).Path ("EntraGroupAudit_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
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
        foreach ($item in @($response.value)) {
            $items.Add($item)
        }
        $next = $response.'@odata.nextLink'
    }
    return $items.ToArray()
}

function Get-MermaidNodeId {
    param([Parameter(Mandatory)][string]$RawId)

    $normalized = $RawId -replace '[^A-Za-z0-9_]', '_'
    if ($normalized -match '^[0-9]') {
        $normalized = "N_$normalized"
    }
    return $normalized
}

function Escape-MermaidLabel {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) {
        return ''
    }
    return ($Value -replace '"', '\"')
}

function Get-LastSignInDateTime {
    param($UserObject)

    $candidates = @()
    if ($null -ne $UserObject.signInActivity) {
        if ($UserObject.signInActivity.lastSignInDateTime) {
            $candidates += [string]$UserObject.signInActivity.lastSignInDateTime
        }
        if ($UserObject.signInActivity.lastNonInteractiveSignInDateTime) {
            $candidates += [string]$UserObject.signInActivity.lastNonInteractiveSignInDateTime
        }
    }

    $parsed = @()
    foreach ($item in $candidates) {
        try {
            $parsed += [DateTimeOffset]::Parse($item)
        }
        catch {
        }
    }

    if ($parsed.Count -eq 0) {
        return $null
    }
    return ($parsed | Sort-Object -Descending | Select-Object -First 1)
}

function Find-GroupCycles {
    param(
        [Parameter(Mandatory)]
        [hashtable]$AdjacencyByGroupId
    )

    $state = @{ Index = 0 }
    $stack = New-Object System.Collections.Generic.List[string]
    $indexByNode = @{}
    $lowLinkByNode = @{}
    $onStack = @{}
    $sccList = New-Object System.Collections.Generic.List[object]

    function Invoke-StrongConnect {
        param([string]$NodeId)

        $indexByNode[$NodeId] = $state.Index
        $lowLinkByNode[$NodeId] = $state.Index
        $state.Index++
        $stack.Add($NodeId)
        $onStack[$NodeId] = $true

        foreach ($neighbor in @($AdjacencyByGroupId[$NodeId])) {
            if (-not $indexByNode.ContainsKey($neighbor)) {
                Invoke-StrongConnect -NodeId $neighbor
                $lowLinkByNode[$NodeId] = [Math]::Min([int]$lowLinkByNode[$NodeId], [int]$lowLinkByNode[$neighbor])
            }
            elseif ($onStack.ContainsKey($neighbor) -and $onStack[$neighbor]) {
                $lowLinkByNode[$NodeId] = [Math]::Min([int]$lowLinkByNode[$NodeId], [int]$indexByNode[$neighbor])
            }
        }

        if ([int]$lowLinkByNode[$NodeId] -eq [int]$indexByNode[$NodeId]) {
            $component = New-Object System.Collections.Generic.List[string]
            while ($true) {
                $w = $stack[$stack.Count - 1]
                $stack.RemoveAt($stack.Count - 1)
                $onStack[$w] = $false
                $component.Add($w)
                if ($w -eq $NodeId) {
                    break
                }
            }
            $sccList.Add($component.ToArray())
        }
    }

    foreach ($node in @($AdjacencyByGroupId.Keys)) {
        if (-not $indexByNode.ContainsKey($node)) {
            Invoke-StrongConnect -NodeId $node
        }
    }

    $cycles = New-Object System.Collections.Generic.List[object]
    foreach ($component in $sccList) {
        if ($component.Count -gt 1) {
            $cycles.Add([pscustomobject]@{ Nodes = @($component) })
            continue
        }

        $single = [string]$component[0]
        if (@($AdjacencyByGroupId[$single]) -contains $single) {
            $cycles.Add([pscustomobject]@{ Nodes = @($component) })
        }
    }
    return $cycles.ToArray()
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

    $scopes = @(
        'Group.Read.All',
        'GroupMember.Read.All',
        'User.Read.All',
        'Directory.Read.All',
        'AuditLog.Read.All'
    )

    $connectParams = @{
        Scopes       = $scopes
        NoWelcome    = $true
        ContextScope = 'Process'
    }
    if ($TargetTenantId) {
        $connectParams['TenantId'] = $TargetTenantId
    }

    Connect-MgGraph @connectParams | Out-Null
    $ctx = Get-MgContext
    if (-not $ctx) {
        throw "Microsoft Graph connection failed."
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

function New-MarkdownTable {
    param(
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)]$Rows
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('| ' + ($Headers -join ' | ') + ' |')
    $lines.Add('| ' + (($Headers | ForEach-Object { '---' }) -join ' | ') + ' |')
    foreach ($row in $Rows) {
        $cells = foreach ($header in $Headers) {
            $value = [string]$row.$header
            ($value -replace '\|', '\|')
        }
        $lines.Add('| ' + ($cells -join ' | ') + ' |')
    }
    return ($lines -join [Environment]::NewLine)
}

function New-HtmlTable {
    param(
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)]$Rows
    )

    $headerLabels = @{
        TotalGroups                   = '総グループ数'
        EmptyGroups                   = '空グループ'
        GroupsWithOneToFiveMembers    = 'メンバー1～5名'
        GroupsWithDirectSubGroups     = '子グループを持つグループ'
        TotalGroupDependencyEdges     = '依存関係数'
        CircularGroupSets             = '循環セット数'
        UsersReferencedInGroups       = 'グループ内ユーザー数'
        PotentiallyUnusedUsersInGroup = '未使用ユーザー候補'
        InactiveThresholdDays         = '未使用判定日数'
        SignInActivityChecked         = 'サインイン確認'
        FileKey                       = '出力種別'
        File                          = 'ファイル'
        CycleId                       = '循環ID'
        GroupCount                    = 'グループ数'
        GroupDisplayNames             = 'グループ名'
        GroupId                       = 'グループID'
        GroupName                     = 'グループ名'
        DirectUsers                   = '直接ユーザー'
        DirectSubGroups               = '直接子グループ'
        DirectOthers                  = 'その他メンバー'
        DirectMembers                 = '直接メンバー合計'
        UserPrincipalName             = 'ユーザープリンシパル名'
        DisplayName                   = '表示名'
        AccountEnabled                = 'アカウント有効'
        LastSignInDateTime            = '最終サインイン'
        Reasons                       = '検出理由'
        MemberOfGroupCount            = '所属グループ数'
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<div class="table-wrap"><table>')
    [void]$sb.AppendLine('<thead><tr>')
    foreach ($header in $Headers) {
        $jaLabel = if ($headerLabels.ContainsKey($header)) { $headerLabels[$header] } else { $header }
        [void]$sb.AppendLine(('<th data-ja="{0}" data-en="{1}">{0}</th>' -f
                [System.Net.WebUtility]::HtmlEncode($jaLabel),
                [System.Net.WebUtility]::HtmlEncode($header)))
    }
    [void]$sb.AppendLine('</tr></thead>')
    [void]$sb.AppendLine('<tbody>')
    foreach ($row in $Rows) {
        $rowClass = ''
        if ($row.PSObject.Properties.Name -contains 'CycleId') {
            $rowClass = 'risk-critical'
        }
        elseif ($row.PSObject.Properties.Name -contains 'Reasons') {
            $reasonText = [string]$row.Reasons
            $rowClass = if ($reasonText -match 'AccountDisabled|UserObjectNotFound') { 'risk-critical' } else { 'risk-warning' }
        }
        elseif ($row.PSObject.Properties.Name -contains 'DirectMembers') {
            $rowClass = 'risk-review'
        }
        [void]$sb.AppendLine(('<tr class="{0}">' -f $rowClass))
        foreach ($header in $Headers) {
            $value = [string]$row.$header
            [void]$sb.AppendLine(('<td>{0}</td>' -f [System.Net.WebUtility]::HtmlEncode($value)))
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
    Write-Host ("Generating {0:N0} sample groups..." -f $SampleGroupCount) -ForegroundColor Cyan
    $groups = @(1..$SampleGroupCount | ForEach-Object {
            $indexValue = $_
            [pscustomobject]@{
                id                            = 'sample-group-{0:D5}' -f $indexValue
                displayName                   = 'Sample Group {0:D5}' -f $indexValue
                description                   = 'Generated sample data for Entra ID group audit validation.'
                mailEnabled                   = ($indexValue % 7 -eq 0)
                securityEnabled               = $true
                groupTypes                    = if ($indexValue % 25 -eq 0) { @('DynamicMembership') } else { @() }
                membershipRule                = if ($indexValue % 25 -eq 0) { '(user.department -eq "Sample")' } else { $null }
                membershipRuleProcessingState = if ($indexValue % 25 -eq 0) { 'On' } else { $null }
                createdDateTime               = (Get-Date).AddDays(-1 * ($indexValue % 1500)).ToString('o')
                onPremisesSyncEnabled         = ($indexValue % 9 -eq 0)
                SampleIndex                   = $indexValue
            }
        })
}
else {
    Write-Host 'Loading Entra groups...' -ForegroundColor Cyan
    $groups = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,description,mailEnabled,securityEnabled,groupTypes,membershipRule,membershipRuleProcessingState,createdDateTime,onPremisesSyncEnabled&`$top=999"
}

$groupById = @{}
$groupNameById = @{}
$adjacency = @{}
$memberCountRows = New-Object System.Collections.Generic.List[object]
$dependencyRows = New-Object System.Collections.Generic.List[object]
$userGroupMembership = @{}
$usersReferenced = New-Object 'System.Collections.Generic.HashSet[string]'
$userById = @{}

foreach ($g in @($groups)) {
    $groupById[[string]$g.id] = $g
    $groupNameById[[string]$g.id] = [string]$g.displayName
    $adjacency[[string]$g.id] = @()
}

Write-Host ('Processing group members ({0:N0} groups)...' -f $groups.Count) -ForegroundColor Cyan
foreach ($g in @($groups)) {
    $groupId = [string]$g.id

    if ($GenerateSampleData) {
        $sampleIndex = [int]$g.SampleIndex
        $userCount = if ($sampleIndex % 10 -eq 0) {
            0
        }
        elseif ($sampleIndex % 4 -eq 0) {
            ($sampleIndex % 5) + 1
        }
        else {
            6 + ($sampleIndex % 20)
        }

        $childIndexes = New-Object System.Collections.Generic.List[int]
        if ($sampleIndex % 20 -eq 0 -and $sampleIndex -lt $SampleGroupCount) {
            $childIndexes.Add($sampleIndex + 1)
        }
        if ($sampleIndex -eq 1) { $childIndexes.Add(2) }
        if ($sampleIndex -eq 2) { $childIndexes.Add(3) }
        if ($sampleIndex -eq 3) { $childIndexes.Add(1) }
        if ($sampleIndex -eq 101 -and $SampleGroupCount -ge 103) { $childIndexes.Add(102) }
        if ($sampleIndex -eq 102 -and $SampleGroupCount -ge 103) { $childIndexes.Add(103) }
        if ($sampleIndex -eq 103 -and $SampleGroupCount -ge 103) { $childIndexes.Add(101) }

        foreach ($childIndex in @($childIndexes | Select-Object -Unique)) {
            $childId = 'sample-group-{0:D5}' -f $childIndex
            $adjacency[$groupId] = @($adjacency[$groupId] + $childId | Select-Object -Unique)
            $dependencyRows.Add([pscustomobject]@{
                    ParentGroupId   = $groupId
                    ParentGroupName = [string]$g.displayName
                    ChildGroupId    = $childId
                    ChildGroupName  = [string]$groupNameById[$childId]
                })
        }

        for ($memberIndex = 1; $memberIndex -le $userCount; $memberIndex++) {
            $userNumber = (($sampleIndex * 17 + $memberIndex) % 25000) + 1
            $memberId = 'sample-user-{0:D5}' -f $userNumber
            [void]$usersReferenced.Add($memberId)
            if (-not $userGroupMembership.ContainsKey($memberId)) {
                $userGroupMembership[$memberId] = New-Object System.Collections.Generic.List[string]
            }
            $userGroupMembership[$memberId].Add($groupId)

            if (-not $userById.ContainsKey($memberId)) {
                $lastSignIn = if ($userNumber % 23 -eq 0) {
                    $null
                }
                elseif ($userNumber % 17 -eq 0) {
                    (Get-Date).AddDays(-1 * ($InactiveDays + 30 + ($userNumber % 180))).ToString('o')
                }
                else {
                    (Get-Date).AddDays(-1 * ($userNumber % [Math]::Max(2, $InactiveDays - 1))).ToString('o')
                }
                $userById[$memberId] = [pscustomobject]@{
                    id                = $memberId
                    displayName       = 'Sample User {0:D5}' -f $userNumber
                    userPrincipalName = 'sample.user{0:D5}@example.invalid' -f $userNumber
                    mail              = 'sample.user{0:D5}@example.invalid' -f $userNumber
                    accountEnabled    = ($userNumber % 37 -ne 0)
                    userType          = if ($userNumber % 19 -eq 0) { 'Guest' } else { 'Member' }
                    createdDateTime   = (Get-Date).AddDays(-1 * ($userNumber % 1200)).ToString('o')
                    signInActivity    = [pscustomobject]@{
                        lastSignInDateTime               = $lastSignIn
                        lastNonInteractiveSignInDateTime = $lastSignIn
                    }
                }
            }
        }

        $otherCount = if ($sampleIndex % 97 -eq 0) { 1 } else { 0 }
        $groupCount = @($childIndexes | Select-Object -Unique).Count
        $memberCountRows.Add([pscustomobject]@{
                GroupId         = $groupId
                GroupName       = [string]$g.displayName
                DirectUsers     = $userCount
                DirectSubGroups = $groupCount
                DirectOthers    = $otherCount
                DirectMembers   = $userCount + $groupCount + $otherCount
            })
        continue
    }

    $members = Invoke-GraphCollection -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/members?`$select=id,displayName,userPrincipalName,mail,accountEnabled&`$top=999" -f $groupId)

    $userCount = 0
    $groupCount = 0
    $otherCount = 0

    foreach ($member in @($members)) {
        $memberType = [string]$member.'@odata.type'
        $memberId = [string]$member.id

        switch -Regex ($memberType) {
            '#microsoft\.graph\.group$' {
                $groupCount++
                $adjacency[$groupId] = @($adjacency[$groupId] + $memberId | Select-Object -Unique)
                $dependencyRows.Add([pscustomobject]@{
                        ParentGroupId   = $groupId
                        ParentGroupName = [string]$g.displayName
                        ChildGroupId    = $memberId
                        ChildGroupName  = if ($groupNameById.ContainsKey($memberId)) { [string]$groupNameById[$memberId] } else { [string]$member.displayName }
                    })
                break
            }
            '#microsoft\.graph\.user$' {
                $userCount++
                [void]$usersReferenced.Add($memberId)
                if (-not $userGroupMembership.ContainsKey($memberId)) {
                    $userGroupMembership[$memberId] = New-Object System.Collections.Generic.List[string]
                }
                $userGroupMembership[$memberId].Add($groupId)
                break
            }
            default {
                $otherCount++
            }
        }
    }

    $memberCountRows.Add([pscustomobject]@{
            GroupId         = $groupId
            GroupName       = [string]$g.displayName
            DirectUsers     = $userCount
            DirectSubGroups = $groupCount
            DirectOthers    = $otherCount
            DirectMembers   = $members.Count
        })
}

Write-Host 'Analyzing group cycles...' -ForegroundColor Cyan
$cycles = Find-GroupCycles -AdjacencyByGroupId $adjacency
$cycleRows = New-Object System.Collections.Generic.List[object]
$cycleNodeSet = New-Object 'System.Collections.Generic.HashSet[string]'
$cycleIndex = 1
foreach ($cycle in @($cycles)) {
    $cycleNodes = @($cycle.Nodes)
    foreach ($id in $cycleNodes) {
        [void]$cycleNodeSet.Add([string]$id)
    }
    $names = @($cycleNodes | ForEach-Object {
            if ($groupNameById.ContainsKey($_)) { $groupNameById[$_] } else { $_ }
        })
    $cycleRows.Add([pscustomobject]@{
            CycleId         = "C$cycleIndex"
            GroupCount      = $cycleNodes.Count
            GroupIds        = ($cycleNodes -join '; ')
            GroupDisplayNames = ($names -join ' -> ')
        })
    $cycleIndex++
}

if (-not $GenerateSampleData) {
    Write-Host 'Loading users for inactivity checks...' -ForegroundColor Cyan
    $userSelect = if ($SkipSignInActivity) {
        'id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime'
    }
    else {
        'id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,signInActivity'
    }

    $userUri = if ($SkipSignInActivity) {
        "https://graph.microsoft.com/v1.0/users?`$select=$userSelect&`$top=999"
    }
    else {
        "https://graph.microsoft.com/beta/users?`$select=$userSelect&`$top=999"
    }

    $allUsers = Invoke-GraphCollection -Uri $userUri
    foreach ($u in @($allUsers)) {
        $userById[[string]$u.id] = $u
    }
}

$inactiveCutoff = (Get-Date).AddDays(-1 * $InactiveDays)
$unusedUserRows = New-Object System.Collections.Generic.List[object]

foreach ($userId in @($usersReferenced)) {
    if (-not $userById.ContainsKey($userId)) {
        $unusedUserRows.Add([pscustomobject]@{
                UserId              = $userId
                UserPrincipalName   = '(not found)'
                DisplayName         = '(not found)'
                AccountEnabled      = ''
                LastSignInDateTime  = ''
                Reasons             = 'UserObjectNotFound'
                MemberOfGroupCount  = @($userGroupMembership[$userId]).Count
                MemberOfGroups      = (@($userGroupMembership[$userId] | ForEach-Object {
                            if ($groupNameById.ContainsKey($_)) { $groupNameById[$_] } else { $_ }
                        }) -join '; ')
            })
        continue
    }

    $u = $userById[$userId]
    $reasons = New-Object System.Collections.Generic.List[string]

    if ($null -ne $u.accountEnabled -and -not [bool]$u.accountEnabled) {
        $reasons.Add('AccountDisabled')
    }

    $lastSignIn = $null
    if (-not $SkipSignInActivity) {
        $lastSignIn = Get-LastSignInDateTime -UserObject $u
        if ($null -eq $lastSignIn) {
            $reasons.Add('NoSignInRecord')
        }
        elseif ($lastSignIn.LocalDateTime -lt $inactiveCutoff) {
            $reasons.Add("NoRecentSignIn(>${InactiveDays}d)")
        }
    }

    if ($reasons.Count -gt 0) {
        $unusedUserRows.Add([pscustomobject]@{
                UserId              = [string]$u.id
                UserPrincipalName   = [string]$u.userPrincipalName
                DisplayName         = [string]$u.displayName
                AccountEnabled      = [string]$u.accountEnabled
                LastSignInDateTime  = if ($null -ne $lastSignIn) { $lastSignIn.ToString('o') } else { '' }
                Reasons             = ($reasons -join '; ')
                MemberOfGroupCount  = @($userGroupMembership[$userId]).Count
                MemberOfGroups      = (@($userGroupMembership[$userId] | ForEach-Object {
                            if ($groupNameById.ContainsKey($_)) { $groupNameById[$_] } else { $_ }
                        }) -join '; ')
            })
    }
}

$groupRows = @($groups | ForEach-Object {
        [pscustomobject]@{
            GroupId                        = [string]$_.id
            GroupName                      = [string]$_.displayName
            Description                    = [string]$_.description
            SecurityEnabled                = [string]$_.securityEnabled
            MailEnabled                    = [string]$_.mailEnabled
            GroupTypes                     = (@($_.groupTypes) -join '; ')
            DynamicMembershipRule          = [string]$_.membershipRule
            MembershipRuleProcessingState  = [string]$_.membershipRuleProcessingState
            OnPremisesSyncEnabled          = [string]$_.onPremisesSyncEnabled
            CreatedDateTime                = [string]$_.createdDateTime
        }
    })

$emptyGroupRows = @($memberCountRows | Where-Object { $_.DirectMembers -eq 0 })
$smallGroupRows = @($memberCountRows | Where-Object { $_.DirectMembers -ge 1 -and $_.DirectMembers -le 5 })
$context = if ($GenerateSampleData) { $null } else { Get-MgContext }
$summary = [pscustomobject]@{
    DataSource                    = if ($GenerateSampleData) { "Generated sample data ($SampleGroupCount groups)" } else { 'Microsoft Entra ID' }
    GeneratedAt                   = (Get-Date).ToString('o')
    TenantId                      = if ($GenerateSampleData) { 'sample-tenant' } else { $context.TenantId }
    SignedInAccount               = if ($GenerateSampleData) { 'sample-data@example.invalid' } else { $context.Account }
    TotalGroups                   = $groups.Count
    EmptyGroups                   = $emptyGroupRows.Count
    GroupsWithOneToFiveMembers    = $smallGroupRows.Count
    GroupsWithDirectSubGroups     = (@($memberCountRows | Where-Object { $_.DirectSubGroups -gt 0 })).Count
    TotalGroupDependencyEdges     = $dependencyRows.Count
    CircularGroupSets             = $cycleRows.Count
    UsersReferencedInGroups       = $usersReferenced.Count
    PotentiallyUnusedUsersInGroup = $unusedUserRows.Count
    InactiveThresholdDays         = $InactiveDays
    SignInActivityChecked         = (-not $SkipSignInActivity)
}

Write-Host 'Generating Mermaid diagrams...' -ForegroundColor Cyan
$depMermaid = New-Object System.Collections.Generic.List[string]
$depMermaid.Add('flowchart TD')

$edgeCount = 0
foreach ($edge in $dependencyRows) {
    if ($edgeCount -ge $DependencyMermaidMaxEdges) {
        break
    }
    $p = Get-MermaidNodeId -RawId ([string]$edge.ParentGroupId)
    $c = Get-MermaidNodeId -RawId ([string]$edge.ChildGroupId)
    $pLabel = Escape-MermaidLabel -Value ("{0}`n{1}" -f $edge.ParentGroupName, $edge.ParentGroupId)
    $cLabel = Escape-MermaidLabel -Value ("{0}`n{1}" -f $edge.ChildGroupName, $edge.ChildGroupId)
    $depMermaid.Add(("    {0}[`"{1}`"] --> {2}[`"{3}`"]" -f $p, $pLabel, $c, $cLabel))
    $edgeCount++
}

if ($dependencyRows.Count -gt $DependencyMermaidMaxEdges) {
    $depMermaid.Add(("    %% Truncated: showing first {0} edges out of {1}" -f $DependencyMermaidMaxEdges, $dependencyRows.Count))
}

$cycleMermaid = New-Object System.Collections.Generic.List[string]
$cycleMermaid.Add('flowchart TD')
$cycleMermaid.Add('    classDef cycle fill:#ffe5e5,stroke:#d60000,stroke-width:2px;')

$cycleEdges = @($dependencyRows | Where-Object {
        $cycleNodeSet.Contains([string]$_.ParentGroupId) -and $cycleNodeSet.Contains([string]$_.ChildGroupId)
    })

foreach ($edge in @($cycleEdges)) {
    $p = Get-MermaidNodeId -RawId ([string]$edge.ParentGroupId)
    $c = Get-MermaidNodeId -RawId ([string]$edge.ChildGroupId)
    $pLabel = Escape-MermaidLabel -Value ("{0}`n{1}" -f $edge.ParentGroupName, $edge.ParentGroupId)
    $cLabel = Escape-MermaidLabel -Value ("{0}`n{1}" -f $edge.ChildGroupName, $edge.ChildGroupId)
    $cycleMermaid.Add(("    {0}[`"{1}`"] --> {2}[`"{3}`"]" -f $p, $pLabel, $c, $cLabel))
}

if ($cycleNodeSet.Count -gt 0) {
    $cycleClassTargets = @($cycleNodeSet | ForEach-Object { Get-MermaidNodeId -RawId $_ })
    $cycleMermaid.Add(("    class {0} cycle;" -f ($cycleClassTargets -join ',')))
}
else {
    $cycleMermaid.Add('    %% No circular group dependencies detected.')
}

$paths = [ordered]@{
    SummaryJson          = Join-Path $resolvedOutputDir 'Summary.json'
    GroupsCsv            = Join-Path $resolvedOutputDir 'Groups.csv'
    GroupMembersCsv      = Join-Path $resolvedOutputDir 'GroupMemberSummary.csv'
    GroupDependenciesCsv = Join-Path $resolvedOutputDir 'GroupDependencies.csv'
    GroupCyclesCsv       = Join-Path $resolvedOutputDir 'GroupCycles.csv'
    UnusedUsersCsv       = Join-Path $resolvedOutputDir 'PotentiallyUnusedUsers.csv'
    EmptyGroupsCsv       = Join-Path $resolvedOutputDir 'EmptyGroups.csv'
    SmallGroupsCsv       = Join-Path $resolvedOutputDir 'GroupsWithOneToFiveMembers.csv'
    MermaidDependency    = Join-Path $resolvedOutputDir 'GroupDependencies.mmd'
    MermaidCycles        = Join-Path $resolvedOutputDir 'GroupCycles.mmd'
    MarkdownReport       = Join-Path $resolvedOutputDir 'Report.md'
    HtmlReport           = Join-Path $resolvedOutputDir 'Report.html'
}

$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $paths.SummaryJson -Encoding UTF8
$groupRows | Export-Csv -LiteralPath $paths.GroupsCsv -NoTypeInformation -Encoding UTF8
$memberCountRows | Export-Csv -LiteralPath $paths.GroupMembersCsv -NoTypeInformation -Encoding UTF8
$dependencyRows | Export-Csv -LiteralPath $paths.GroupDependenciesCsv -NoTypeInformation -Encoding UTF8
$cycleRows | Export-Csv -LiteralPath $paths.GroupCyclesCsv -NoTypeInformation -Encoding UTF8
$unusedUserRows | Export-Csv -LiteralPath $paths.UnusedUsersCsv -NoTypeInformation -Encoding UTF8
$emptyGroupRows | Export-Csv -LiteralPath $paths.EmptyGroupsCsv -NoTypeInformation -Encoding UTF8
$smallGroupRows | Export-Csv -LiteralPath $paths.SmallGroupsCsv -NoTypeInformation -Encoding UTF8
$depMermaid -join [Environment]::NewLine | Set-Content -LiteralPath $paths.MermaidDependency -Encoding UTF8
$cycleMermaid -join [Environment]::NewLine | Set-Content -LiteralPath $paths.MermaidCycles -Encoding UTF8

$reportLines = New-Object System.Collections.Generic.List[string]
$reportLines.Add('# Entra ID Group Audit Report')
$reportLines.Add('')
$reportLines.Add(('GeneratedAt: {0}' -f $summary.GeneratedAt))
$reportLines.Add(('TenantId: {0}' -f $summary.TenantId))
$reportLines.Add(('SignedInAccount: {0}' -f $summary.SignedInAccount))
$reportLines.Add('')
$reportLines.Add('## Summary')
$reportLines.Add('')
$summaryRows = @([pscustomobject]@{
        TotalGroups                   = [string]$summary.TotalGroups
        EmptyGroups                   = [string]$summary.EmptyGroups
        GroupsWithOneToFiveMembers    = [string]$summary.GroupsWithOneToFiveMembers
        GroupsWithDirectSubGroups     = [string]$summary.GroupsWithDirectSubGroups
        TotalGroupDependencyEdges     = [string]$summary.TotalGroupDependencyEdges
        CircularGroupSets             = [string]$summary.CircularGroupSets
        UsersReferencedInGroups       = [string]$summary.UsersReferencedInGroups
        PotentiallyUnusedUsersInGroup = [string]$summary.PotentiallyUnusedUsersInGroup
        InactiveThresholdDays         = [string]$summary.InactiveThresholdDays
        SignInActivityChecked         = [string]$summary.SignInActivityChecked
    })
$reportLines.Add((New-MarkdownTable -Headers @(
            'TotalGroups',
            'EmptyGroups',
            'GroupsWithOneToFiveMembers',
            'GroupsWithDirectSubGroups',
            'TotalGroupDependencyEdges',
            'CircularGroupSets',
            'UsersReferencedInGroups',
            'PotentiallyUnusedUsersInGroup',
            'InactiveThresholdDays',
            'SignInActivityChecked'
        ) -Rows $summaryRows))
$reportLines.Add('')
$reportLines.Add('## Output files')
$reportLines.Add('')
$outputRows = @($paths.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{
            FileKey = $_.Key
            File    = Split-Path -Leaf $_.Value
        }
    })
$reportLines.Add((New-MarkdownTable -Headers @('FileKey', 'File') -Rows $outputRows))
$reportLines.Add('')
$reportLines.Add('## Circular dependencies')
$reportLines.Add('')
if ($cycleRows.Count -gt 0) {
    $reportLines.Add((New-MarkdownTable -Headers @('CycleId', 'GroupCount', 'GroupDisplayNames') -Rows $cycleRows))
}
else {
    $reportLines.Add('No circular group dependency was detected.')
}
$reportLines.Add('')
$reportLines.Add('## Empty groups')
$reportLines.Add('')
$reportLines.Add(('Detected: {0}' -f $emptyGroupRows.Count))
$reportLines.Add('')
$reportLines.Add((New-MarkdownTable -Headers @('GroupId', 'GroupName', 'DirectMembers') -Rows @($emptyGroupRows | Select-Object -First 100)))
$reportLines.Add('')
$reportLines.Add('## Groups with 1-5 direct members')
$reportLines.Add('')
$reportLines.Add(('Detected: {0}' -f $smallGroupRows.Count))
$reportLines.Add('')
$reportLines.Add((New-MarkdownTable -Headers @('GroupId', 'GroupName', 'DirectUsers', 'DirectSubGroups', 'DirectOthers', 'DirectMembers') -Rows @($smallGroupRows | Select-Object -First 100)))
$reportLines.Add('')
$reportLines.Add('## Mermaid (circular dependencies)')
$reportLines.Add('')
$reportLines.Add('```mermaid')
$reportLines.Add(($cycleMermaid -join [Environment]::NewLine))
$reportLines.Add('```')
$reportLines.Add('')
$reportLines.Add('## Mermaid (group dependencies)')
$reportLines.Add('')
$reportLines.Add('```mermaid')
$reportLines.Add(($depMermaid -join [Environment]::NewLine))
$reportLines.Add('```')

$reportLines -join [Environment]::NewLine | Set-Content -LiteralPath $paths.MarkdownReport -Encoding UTF8

$summaryTableRows = @([pscustomobject]@{
        TotalGroups                   = [string]$summary.TotalGroups
        EmptyGroups                   = [string]$summary.EmptyGroups
        GroupsWithOneToFiveMembers    = [string]$summary.GroupsWithOneToFiveMembers
        GroupsWithDirectSubGroups     = [string]$summary.GroupsWithDirectSubGroups
        TotalGroupDependencyEdges     = [string]$summary.TotalGroupDependencyEdges
        CircularGroupSets             = [string]$summary.CircularGroupSets
        UsersReferencedInGroups       = [string]$summary.UsersReferencedInGroups
        PotentiallyUnusedUsersInGroup = [string]$summary.PotentiallyUnusedUsersInGroup
        InactiveThresholdDays         = [string]$summary.InactiveThresholdDays
        SignInActivityChecked         = [string]$summary.SignInActivityChecked
    })
$summaryHtmlTable = New-HtmlTable -Headers @(
    'TotalGroups',
    'EmptyGroups',
    'GroupsWithOneToFiveMembers',
    'GroupsWithDirectSubGroups',
    'TotalGroupDependencyEdges',
    'CircularGroupSets',
    'UsersReferencedInGroups',
    'PotentiallyUnusedUsersInGroup',
    'InactiveThresholdDays',
    'SignInActivityChecked'
) -Rows $summaryTableRows

$outputHtmlTable = New-HtmlTable -Headers @('FileKey', 'File') -Rows $outputRows
$cycleHtmlTable = if ($cycleRows.Count -gt 0) {
    New-HtmlTable -Headers @('CycleId', 'GroupCount', 'GroupDisplayNames') -Rows $cycleRows
}
else {
    '<p data-ja="循環するグループ依存関係は検出されませんでした。" data-en="No circular group dependency was detected.">循環するグループ依存関係は検出されませんでした。</p>'
}

$emptyPreview = @($emptyGroupRows | Select-Object -First 200)
$emptyHtmlTable = New-HtmlTable -Headers @(
    'GroupId',
    'GroupName',
    'DirectMembers'
) -Rows $emptyPreview
$emptyNotice = if ($emptyGroupRows.Count -gt 200) {
    '<p data-ja="先頭200件を表示しています。全件は EmptyGroups.csv を参照してください。" data-en="Showing the first 200 rows. See EmptyGroups.csv for the full dataset.">先頭200件を表示しています。全件は EmptyGroups.csv を参照してください。</p>'
}
else {
    ''
}

$smallPreview = @($smallGroupRows | Select-Object -First 200)
$smallHtmlTable = New-HtmlTable -Headers @(
    'GroupId',
    'GroupName',
    'DirectUsers',
    'DirectSubGroups',
    'DirectOthers',
    'DirectMembers'
) -Rows $smallPreview
$smallNotice = if ($smallGroupRows.Count -gt 200) {
    '<p data-ja="先頭200件を表示しています。全件は GroupsWithOneToFiveMembers.csv を参照してください。" data-en="Showing the first 200 rows. See GroupsWithOneToFiveMembers.csv for the full dataset.">先頭200件を表示しています。全件は GroupsWithOneToFiveMembers.csv を参照してください。</p>'
}
else {
    ''
}

$unusedPreview = @($unusedUserRows | Select-Object -First 200)
$unusedHtmlTable = if ($unusedPreview.Count -gt 0) {
    New-HtmlTable -Headers @(
        'UserPrincipalName',
        'DisplayName',
        'AccountEnabled',
        'LastSignInDateTime',
        'Reasons',
        'MemberOfGroupCount'
    ) -Rows $unusedPreview
}
else {
    '<p data-ja="未使用ユーザー候補は検出されませんでした。" data-en="No potentially unused users were detected.">未使用ユーザー候補は検出されませんでした。</p>'
}

$unusedNotice = if ($unusedUserRows.Count -gt 200) {
    '<p data-ja="先頭200件を表示しています。全件は PotentiallyUnusedUsers.csv を参照してください。" data-en="Showing the first 200 rows. See PotentiallyUnusedUsers.csv for the full dataset.">先頭200件を表示しています。全件は PotentiallyUnusedUsers.csv を参照してください。</p>'
}
else {
    ''
}

$html = @"
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" href="data:," />
  <title>Entra ID Group Audit Report</title>
  <script>
    (() => {
      const param = new URLSearchParams(window.location.search).get("scoutTheme");
      const theme =
        param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      document.documentElement.setAttribute("data-theme", theme);
    })();
  </script>
  <style>
    :root {
      color-scheme: light;
      --cp-bg: #f7f4ef;
      --cp-bg-elevated: #fcfbf8;
      --cp-surface: #ffffff;
      --cp-surface-soft: #f5f5f5;
      --cp-border: #dedede;
      --cp-border-strong: #919191;
      --cp-text: #242424;
      --cp-text-muted: #5c5c5c;
      --cp-text-soft: #6f6f6f;
      --cp-accent: #b11f4b;
      --cp-accent-hover: #9a1a41;
      --cp-accent-soft: rgba(177, 31, 75, 0.08);
      --cp-accent-fg: #ffffff;
      --cp-success: #16a34a;
      --cp-danger: #dc2626;
      --cp-warning: #f59e0b;
      --cp-link: #0078d4;
      --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.12);
      --cp-overlay: rgba(255, 255, 255, 0.8);
      --cp-panel: rgba(255, 255, 255, 0.86);
      --cp-panel-strong: rgba(255, 255, 255, 0.96);
      --cp-sheen: rgba(255, 255, 255, 0.55);
      --cp-highlight: rgba(177, 31, 75, 0.12);
      --cp-table-header: #0b3d2e;
      --cp-table-header-alt: #146b4f;
      --cp-table-header-fg: #ffffff;
      --cp-gradient-end: #e2eee7;
      --cp-gradient-deep: #062d22;
      --cp-gradient-mid: #0f5942;
      --cp-gradient-soft: #d7e9df;
      --cp-critical-bg: #fde7e9;
      --cp-warning-bg: #fff4ce;
      --cp-review-bg: #e1efe8;
    }
    html[data-theme="dark"] {
      color-scheme: dark;
      --cp-bg: #3d3b3a;
      --cp-bg-elevated: #343231;
      --cp-surface: #292929;
      --cp-surface-soft: #2e2e2e;
      --cp-border: #474747;
      --cp-border-strong: #5f5f5f;
      --cp-text: #dedede;
      --cp-text-muted: #919191;
      --cp-text-soft: #b0b0b0;
      --cp-accent: #fd8ea1;
      --cp-accent-hover: #fb7b91;
      --cp-accent-soft: rgba(253, 142, 161, 0.14);
      --cp-accent-fg: #1a1a1a;
      --cp-success: #4ade80;
      --cp-danger: #f87171;
      --cp-warning: #fbbf24;
      --cp-link: #4da6ff;
      --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.32);
      --cp-overlay: rgba(41, 41, 41, 0.88);
      --cp-panel: rgba(41, 41, 41, 0.72);
      --cp-panel-strong: rgba(41, 41, 41, 0.96);
      --cp-sheen: rgba(255, 255, 255, 0.04);
      --cp-highlight: rgba(253, 142, 161, 0.12);
      --cp-table-header: #08291f;
      --cp-table-header-alt: #11543f;
      --cp-table-header-fg: #ffffff;
      --cp-gradient-end: #172d25;
      --cp-gradient-deep: #041d16;
      --cp-gradient-mid: #0b4936;
      --cp-gradient-soft: #173a2e;
      --cp-critical-bg: #522126;
      --cp-warning-bg: #493b18;
      --cp-review-bg: #173a2e;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: linear-gradient(145deg, var(--cp-bg), var(--cp-gradient-end));
      color: var(--cp-text);
      font-family: "Segoe UI", Aptos, Calibri, -apple-system, BlinkMacSystemFont, sans-serif;
      line-height: 1.5;
    }
    .layout { display: grid; grid-template-columns: 280px minmax(0, 1fr); min-height: 100vh; }
    .sidebar {
      position: sticky;
      top: 0;
      height: 100vh;
      overflow-y: auto;
      padding: 24px 16px;
      background: linear-gradient(180deg, var(--cp-panel-strong), var(--cp-gradient-soft));
      border-right: 1px solid var(--cp-border);
    }
    .brand { font-size: 18px; font-weight: 700; margin: 0 0 4px; }
    .sidebar-subtitle { color: var(--cp-text-muted); font-size: 12px; margin: 0 0 20px; }
    .language-button {
      width: 100%;
      border: 1px solid var(--cp-table-header);
      border-radius: 0.625rem;
      padding: 9px 12px;
      margin-bottom: 20px;
      background: linear-gradient(135deg, var(--cp-gradient-deep), var(--cp-gradient-mid));
      color: var(--cp-table-header-fg);
      cursor: pointer;
      font: inherit;
      font-weight: 600;
    }
    .language-button:hover { background: linear-gradient(135deg, var(--cp-gradient-mid), var(--cp-table-header-alt)); }
    .nav-title { color: var(--cp-text-muted); font-size: 11px; font-weight: 700; letter-spacing: .08em; margin: 12px 8px 6px; text-transform: uppercase; }
    .nav-list { list-style: none; margin: 0; padding: 0; }
    .nav-list a {
      display: block;
      padding: 8px 10px;
      margin: 2px 0;
      border-left: 3px solid transparent;
      border-radius: 0.625rem;
      color: var(--cp-text);
      text-decoration: none;
      font-size: 13px;
    }
    .nav-list a:hover, .nav-list a.active {
      background: var(--cp-review-bg);
      border-left-color: var(--cp-table-header);
    }
    main { min-width: 0; padding: 32px clamp(20px, 4vw, 56px) 64px; }
    .page-header, section {
      max-width: 1500px;
      margin: 0 auto 24px;
      padding: 24px;
      background: var(--cp-surface);
      border: 1px solid var(--cp-border);
      border-radius: 16px;
      box-shadow: var(--cp-shadow);
      scroll-margin-top: 16px;
    }
    .page-header {
      border-top: 6px solid var(--cp-table-header);
      background: linear-gradient(135deg, var(--cp-surface), var(--cp-gradient-soft));
    }
    h1 { margin: 0 0 12px; font-size: clamp(28px, 4vw, 44px); line-height: 1.12; }
    h2 { margin: 0 0 16px; font-size: 24px; }
    .meta { margin: 3px 0; color: var(--cp-text-muted); font-size: 13px; }
    .status-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
    .status-card { padding: 16px; border: 1px solid var(--cp-border); border-left-width: 5px; border-radius: 0.625rem; }
    .status-card strong { display: block; font-size: 13px; margin-bottom: 6px; }
    .status-card .count { font-size: 30px; font-weight: 700; }
    .critical { border-left-color: var(--cp-danger); background: var(--cp-critical-bg); }
    .warning { border-left-color: var(--cp-warning); background: var(--cp-warning-bg); }
    .review { border-left-color: var(--cp-link); background: var(--cp-review-bg); }
    .table-wrap { width: 100%; overflow-x: auto; border: 1px solid var(--cp-border); border-radius: 0.625rem; }
    table { border-collapse: collapse; width: 100%; min-width: 760px; font-size: 13px; }
    th, td { border: 1px solid var(--cp-border); padding: 8px 10px; text-align: left; vertical-align: top; }
    th { position: sticky; top: 0; background: linear-gradient(135deg, var(--cp-gradient-deep), var(--cp-gradient-mid)); color: var(--cp-table-header-fg); z-index: 1; }
    tbody tr:nth-child(even) { background: var(--cp-surface-soft); }
    tr.risk-critical { background: var(--cp-critical-bg); }
    tr.risk-warning { background: var(--cp-warning-bg); }
    tr.risk-review { background: var(--cp-review-bg); }
    .section-count { display: inline-block; padding: 3px 9px; margin-bottom: 12px; border-radius: 0.625rem; background: var(--cp-review-bg); font-weight: 700; }
    .mermaid { overflow: auto; padding: 16px; border: 1px solid var(--cp-border); border-radius: 0.625rem; background: var(--cp-surface); }
    .muted { color: var(--cp-text-muted); font-size: 12px; }
    .legend { display: flex; flex-wrap: wrap; gap: 12px; margin: 12px 0 0; font-size: 12px; }
    .legend span { padding: 5px 9px; border-radius: 0.625rem; }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      .sidebar { position: sticky; z-index: 20; height: auto; padding: 12px 16px; border-right: 0; border-bottom: 1px solid var(--cp-border); }
      .sidebar-subtitle, .nav-title { display: none; }
      .language-button { width: auto; margin: 0 0 8px; }
      .nav-list { display: flex; overflow-x: auto; gap: 4px; }
      .nav-list a { white-space: nowrap; }
      main { padding: 20px 12px 48px; }
      .status-grid { grid-template-columns: 1fr; }
      .page-header, section { padding: 18px; }
    }
  </style>
  <script type="module">
    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
    mermaid.initialize({ startOnLoad: true, securityLevel: 'loose', maxTextSize: 1000000 });
  </script>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <p class="brand">Entra ID Audit</p>
      <p class="sidebar-subtitle" data-ja="グループ構造・利用状況レポート" data-en="Group structure and usage report">グループ構造・利用状況レポート</p>
      <button id="languageToggle" class="language-button" type="button">English</button>
      <p class="nav-title" data-ja="レポート項目" data-en="Report index">レポート項目</p>
      <nav aria-label="Report index">
        <ul class="nav-list">
          <li><a href="#overview" data-ja="概要" data-en="Overview">概要</a></li>
          <li><a href="#priority" data-ja="優先対応" data-en="Priority actions">優先対応</a></li>
          <li><a href="#outputs" data-ja="出力ファイル" data-en="Output files">出力ファイル</a></li>
          <li><a href="#cycles" data-ja="循環依存" data-en="Circular dependencies">循環依存</a></li>
          <li><a href="#empty-groups" data-ja="空グループ" data-en="Empty groups">空グループ</a></li>
          <li><a href="#small-groups" data-ja="5名以下グループ" data-en="Groups with 1-5 members">5名以下グループ</a></li>
          <li><a href="#unused-users" data-ja="未使用ユーザー候補" data-en="Potentially unused users">未使用ユーザー候補</a></li>
          <li><a href="#cycle-map" data-ja="循環関係図" data-en="Cycle map">循環関係図</a></li>
          <li><a href="#dependency-map" data-ja="依存関係図" data-en="Dependency map">依存関係図</a></li>
        </ul>
      </nav>
    </aside>
    <main>
      <header class="page-header" id="overview">
        <h1 data-ja="Entra ID グループ監査レポート" data-en="Entra ID Group Audit Report">Entra ID グループ監査レポート</h1>
        <p class="meta"><strong data-ja="データソース" data-en="Data source">データソース</strong>: $([System.Net.WebUtility]::HtmlEncode([string]$summary.DataSource))</p>
        <p class="meta"><strong data-ja="生成日時" data-en="Generated at">生成日時</strong>: $([System.Net.WebUtility]::HtmlEncode($summary.GeneratedAt))</p>
        <p class="meta"><strong data-ja="テナントID" data-en="Tenant ID">テナントID</strong>: $([System.Net.WebUtility]::HtmlEncode([string]$summary.TenantId))</p>
        <p class="meta"><strong data-ja="実行アカウント" data-en="Signed-in account">実行アカウント</strong>: $([System.Net.WebUtility]::HtmlEncode([string]$summary.SignedInAccount))</p>
        <h2 data-ja="概要" data-en="Summary">概要</h2>
        $summaryHtmlTable
      </header>

      <section id="priority">
        <h2 data-ja="優先対応" data-en="Priority actions">優先対応</h2>
        <div class="status-grid">
          <article class="status-card critical">
            <strong data-ja="緊急: 循環依存" data-en="Urgent: Circular dependencies">緊急: 循環依存</strong>
            <div class="count">$($cycleRows.Count)</div>
            <span data-ja="権限評価やメンバー展開が複雑化するため、早急な構造見直しが必要です。" data-en="Review the structure immediately because cycles complicate permission evaluation and membership expansion.">権限評価やメンバー展開が複雑化するため、早急な構造見直しが必要です。</span>
          </article>
          <article class="status-card warning">
            <strong data-ja="要対応: 未使用ユーザー候補" data-en="Action required: Potentially unused users">要対応: 未使用ユーザー候補</strong>
            <div class="count">$($unusedUserRows.Count)</div>
            <span data-ja="無効アカウントや長期未使用ユーザーの所属継続要否を確認してください。" data-en="Confirm whether disabled or inactive accounts should remain in their groups.">無効アカウントや長期未使用ユーザーの所属継続要否を確認してください。</span>
          </article>
          <article class="status-card review">
            <strong data-ja="要確認: 空・少人数グループ" data-en="Review: Empty or small groups">要確認: 空・少人数グループ</strong>
            <div class="count">$($emptyGroupRows.Count + $smallGroupRows.Count)</div>
            <span data-ja="利用目的・所有者・廃止可否を確認してください。" data-en="Validate purpose, ownership, and whether these groups can be retired.">利用目的・所有者・廃止可否を確認してください。</span>
          </article>
        </div>
        <div class="legend">
          <span class="critical" data-ja="赤: 緊急対応" data-en="Red: Urgent">赤: 緊急対応</span>
          <span class="warning" data-ja="黄: 要対応" data-en="Yellow: Action required">黄: 要対応</span>
          <span class="review" data-ja="青: 要確認" data-en="Blue: Review">青: 要確認</span>
        </div>
      </section>

      <section id="outputs">
        <h2 data-ja="出力ファイル" data-en="Output files">出力ファイル</h2>
        $outputHtmlTable
      </section>

      <section id="cycles">
        <h2 data-ja="循環依存" data-en="Circular dependencies">循環依存</h2>
        <span class="section-count">$($cycleRows.Count)</span>
        $cycleHtmlTable
      </section>

      <section id="empty-groups">
        <h2 data-ja="空グループ" data-en="Empty groups">空グループ</h2>
        <span class="section-count">$($emptyGroupRows.Count)</span>
        $emptyNotice
        $emptyHtmlTable
      </section>

      <section id="small-groups">
        <h2 data-ja="直接メンバーが1～5名のグループ" data-en="Groups with 1-5 direct members">直接メンバーが1～5名のグループ</h2>
        <span class="section-count">$($smallGroupRows.Count)</span>
        $smallNotice
        $smallHtmlTable
      </section>

      <section id="unused-users">
        <h2 data-ja="未使用ユーザー候補" data-en="Potentially unused users">未使用ユーザー候補</h2>
        <span class="section-count">$($unusedUserRows.Count)</span>
        $unusedNotice
        $unusedHtmlTable
      </section>

      <section id="cycle-map">
        <h2 data-ja="循環依存 Mermaid 図" data-en="Circular dependency Mermaid map">循環依存 Mermaid 図</h2>
        <div class="mermaid">
$([string]::Join([Environment]::NewLine, $cycleMermaid))
        </div>
      </section>

      <section id="dependency-map">
        <h2 data-ja="グループ依存関係 Mermaid 図" data-en="Group dependency Mermaid map">グループ依存関係 Mermaid 図</h2>
        <p class="muted" data-ja="大規模テナントでは -DependencyMermaidMaxEdges の指定値で図を省略する場合があります。" data-en="For large tenants, the graph may be truncated according to -DependencyMermaidMaxEdges.">大規模テナントでは -DependencyMermaidMaxEdges の指定値で図を省略する場合があります。</p>
        <div class="mermaid">
$([string]::Join([Environment]::NewLine, $depMermaid))
        </div>
      </section>
    </main>
  </div>
  <script>
    (() => {
      let currentLanguage = "ja";
      const toggle = document.getElementById("languageToggle");
      const applyLanguage = (language) => {
        currentLanguage = language;
        document.documentElement.lang = language;
        document.querySelectorAll("[data-ja][data-en]").forEach((element) => {
          element.textContent = language === "ja" ? element.dataset.ja : element.dataset.en;
        });
        toggle.textContent = language === "ja" ? "English" : "日本語";
        toggle.setAttribute("aria-label", language === "ja" ? "Switch to English" : "日本語に切り替え");
      };
      toggle.addEventListener("click", () => applyLanguage(currentLanguage === "ja" ? "en" : "ja"));
      applyLanguage("ja");

      const links = Array.from(document.querySelectorAll(".nav-list a"));
      const sections = links
        .map((link) => document.querySelector(link.getAttribute("href")))
        .filter(Boolean);
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          links.forEach((link) => {
            link.classList.toggle("active", link.getAttribute("href") === "#" + entry.target.id);
          });
        });
      }, { rootMargin: "-15% 0px -70% 0px" });
      sections.forEach((section) => observer.observe(section));
    })();
  </script>
</body>
</html>
"@

$html | Set-Content -LiteralPath $paths.HtmlReport -Encoding UTF8

Write-Host ''
Write-Host 'Audit complete. Output files:' -ForegroundColor Green
foreach ($entry in $paths.GetEnumerator()) {
    Write-Host ("- {0}: {1}" -f $entry.Key, $entry.Value)
}
