#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Interactive configuration manager for Advanced Sender Based Routing Agent (Console/Core mode).

.DESCRIPTION
    Provides an interactive text-based menu to manage:
    - Feature settings (Send-As-Alias, Sender-Based Routing, etc.)
    - Advanced routing rules with sender AND recipient conditions
    - Wildcard support (* and ?) in rules
    - Rule testing/validation
    - Local domains management
    - Send Connector creation
    - Configuration backup and restore

.PARAMETER ConfigPath
    Path to routing-config.xml. Auto-detected if not specified.

.EXAMPLE
    .\configure.ps1
    Opens interactive configuration menu.

.EXAMPLE
    .\configure.ps1 -ConfigPath "C:\CustomPath\routing-config.xml"
    Opens configuration for specified config file.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"

# Global variables
$Script:ConfigFile = $null
$Script:Config = $null

#region Helper Functions

function Write-Header {
    param([string]$Text)
    Clear-Host
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-MenuOption {
    param([string]$Key, [string]$Text)
    Write-Host "  [$Key] " -ForegroundColor Yellow -NoNewline
    Write-Host $Text -ForegroundColor White
}

function Write-Success { param([string]$Text); Write-Host "[OK] $Text" -ForegroundColor Green }
function Write-Info { param([string]$Text); Write-Host "[*] $Text" -ForegroundColor Cyan }
function Write-Warn { param([string]$Text); Write-Host "[!] $Text" -ForegroundColor Yellow }
function Write-Err { param([string]$Text); Write-Host "[X] $Text" -ForegroundColor Red }

function Pause-Menu {
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-ExchangeInstallPath {
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup",
        "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup"
    )
    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $installPath = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).MsiInstallPath
            if ($installPath) { return $installPath.TrimEnd('\') }
        }
    }
    return "C:\Program Files\Microsoft\Exchange Server\V15"
}

function Find-ConfigFile {
    $locations = @(
        $PSScriptRoot,
        (Join-Path (Get-ExchangeInstallPath) "TransportRoles\agents\AdvancedSenderRouting")
    )
    foreach ($loc in $locations) {
        $path = Join-Path $loc "routing-config.xml"
        if (Test-Path $path) { return $path }
    }
    return $null
}

#endregion

#region Wildcard Matching

function Test-WildcardMatch {
    param([string]$InputString, [string]$Pattern)

    if ([string]::IsNullOrEmpty($Pattern)) { return [string]::IsNullOrEmpty($InputString) }

    $regexPattern = "^"
    foreach ($c in $Pattern.ToCharArray()) {
        switch ($c) {
            '*' { $regexPattern += ".*" }
            '?' { $regexPattern += "." }
            '.' { $regexPattern += "\." }
            '+' { $regexPattern += "\+" }
            '^' { $regexPattern += "\^" }
            '$' { $regexPattern += "\$" }
            '(' { $regexPattern += "\(" }
            ')' { $regexPattern += "\)" }
            '[' { $regexPattern += "\[" }
            ']' { $regexPattern += "\]" }
            '{' { $regexPattern += "\{" }
            '}' { $regexPattern += "\}" }
            '|' { $regexPattern += "\|" }
            '\' { $regexPattern += "\\" }
            default { $regexPattern += $c }
        }
    }
    $regexPattern += "$"

    return $InputString -match $regexPattern
}

function Test-SenderMatch {
    param($Rule, [string]$SenderAddress)

    if ([string]::IsNullOrEmpty($SenderAddress)) { return $false }
    $SenderAddress = $SenderAddress.ToLower()

    if ($Rule.SenderAddress) {
        return Test-WildcardMatch -InputString $SenderAddress -Pattern $Rule.SenderAddress.ToLower()
    }

    if ($Rule.SenderDomain) {
        $pattern = $Rule.SenderDomain.ToLower()
        if ($pattern.Contains("*") -or $pattern.Contains("?")) {
            if (-not $pattern.StartsWith("*")) { $pattern = "*@" + $pattern.TrimStart('@') }
            return Test-WildcardMatch -InputString $SenderAddress -Pattern $pattern
        }
        $domain = if ($pattern.StartsWith("@")) { $pattern } else { "@" + $pattern }
        return $SenderAddress.EndsWith($domain)
    }
    return $false
}

function Test-RecipientMatch {
    param($Rule, [string]$RecipientAddress)

    if ([string]::IsNullOrEmpty($Rule.RecipientDomain) -and [string]::IsNullOrEmpty($Rule.RecipientAddress)) {
        return $true  # No recipient condition = match all
    }

    if ([string]::IsNullOrEmpty($RecipientAddress)) { return $false }
    $RecipientAddress = $RecipientAddress.ToLower()

    if ($Rule.RecipientAddress) {
        return Test-WildcardMatch -InputString $RecipientAddress -Pattern $Rule.RecipientAddress.ToLower()
    }

    if ($Rule.RecipientDomain) {
        $pattern = $Rule.RecipientDomain.ToLower()
        if ($pattern.Contains("*") -or $pattern.Contains("?")) {
            if (-not $pattern.StartsWith("*")) { $pattern = "*@" + $pattern.TrimStart('@') }
            return Test-WildcardMatch -InputString $RecipientAddress -Pattern $pattern
        }
        $domain = if ($pattern.StartsWith("@")) { $pattern } else { "@" + $pattern }
        return $RecipientAddress.EndsWith($domain)
    }
    return $false
}

#endregion

#region Configuration Management

function Load-Configuration {
    if (-not (Test-Path $Script:ConfigFile)) {
        # Create default config
        $defaultConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <settings>
    <enableSendAsAlias>true</enableSendAsAlias>
    <enableSenderBasedRouting>true</enableSenderBasedRouting>
    <bypassLocalRecipients>true</bypassLocalRecipients>
    <routeByHeaderFrom>false</routeByHeaderFrom>
    <validateProxyAddresses>true</validateProxyAddresses>
    <blockIfNoAlias>false</blockIfNoAlias>
  </settings>
  <localDomains>
  </localDomains>
  <routingRules>
  </routingRules>
</configuration>
"@
        $defaultConfig | Out-File -FilePath $Script:ConfigFile -Encoding UTF8
        Write-Info "Created new configuration file"
    }

    try {
        [xml]$Script:Config = Get-Content $Script:ConfigFile -Raw
        Update-ConfigurationSchema
        return $true
    }
    catch {
        Write-Err "Failed to load configuration: $_"
        return $false
    }
}

function Update-ConfigurationSchema {
    $updated = $false
    $settings = $Script:Config.configuration.settings

    if (-not $settings) {
        $settings = $Script:Config.CreateElement("settings")
        $Script:Config.configuration.PrependChild($settings) | Out-Null
        $updated = $true
    }

    $requiredSettings = @{
        "enableSendAsAlias" = "true"
        "enableSenderBasedRouting" = "true"
        "bypassLocalRecipients" = "true"
        "routeByHeaderFrom" = "false"
        "validateProxyAddresses" = "true"
        "blockIfNoAlias" = "false"
    }

    foreach ($settingName in $requiredSettings.Keys) {
        $element = $settings.SelectSingleNode($settingName)
        if (-not $element) {
            $element = $Script:Config.CreateElement($settingName)
            $element.InnerText = $requiredSettings[$settingName]
            $settings.AppendChild($element) | Out-Null
            $updated = $true
        }
    }

    if (-not $Script:Config.configuration.SelectSingleNode("localDomains")) {
        $localDomains = $Script:Config.CreateElement("localDomains")
        $Script:Config.configuration.AppendChild($localDomains) | Out-Null
        $updated = $true
    }

    if (-not $Script:Config.configuration.SelectSingleNode("routingRules")) {
        $routingRules = $Script:Config.CreateElement("routingRules")
        $Script:Config.configuration.AppendChild($routingRules) | Out-Null
        $updated = $true
    }

    if ($updated) { Save-Configuration | Out-Null }
}

function Save-Configuration {
    try {
        $Script:Config.Save($Script:ConfigFile)
        return $true
    }
    catch {
        Write-Err "Failed to save: $_"
        return $false
    }
}

function Get-FeatureStatus {
    param([string]$FeatureName)
    $settings = $Script:Config.configuration.settings
    if ($settings) {
        $element = $settings.SelectSingleNode($FeatureName)
        if ($element) { return $element.InnerText -eq "true" }
    }
    return $true
}

function Set-FeatureStatus {
    param([string]$FeatureName, [bool]$Enabled)
    $settings = $Script:Config.configuration.settings
    if (-not $settings) {
        $settings = $Script:Config.CreateElement("settings")
        $Script:Config.configuration.PrependChild($settings) | Out-Null
    }
    $element = $settings.SelectSingleNode($FeatureName)
    if (-not $element) {
        $element = $Script:Config.CreateElement($FeatureName)
        $settings.AppendChild($element) | Out-Null
    }
    $element.InnerText = $Enabled.ToString().ToLower()
}

function Get-RoutingRules {
    $rules = @()
    $rulesNode = $Script:Config.configuration.routingRules
    if ($rulesNode) {
        $index = 1
        foreach ($rule in $rulesNode.SelectNodes("rule")) {
            $enabledAttr = $rule.GetAttribute("enabled")
            $rules += [PSCustomObject]@{
                Index = $index
                Name = $rule.GetAttribute("name")
                Enabled = if ($enabledAttr -eq "false") { $false } else { $true }
                SenderDomain = $rule.GetAttribute("senderDomain")
                SenderAddress = $rule.GetAttribute("senderAddress")
                RecipientDomain = $rule.GetAttribute("recipientDomain")
                RecipientAddress = $rule.GetAttribute("recipientAddress")
                AddressSpace = $rule.GetAttribute("addressSpace")
                SendAsAlias = $rule.GetAttribute("sendAsAlias")
            }
            $index++
        }
    }
    return $rules
}

function Get-LocalDomains {
    $domains = @()
    $localDomainsNode = $Script:Config.configuration.SelectSingleNode("localDomains")
    if ($localDomainsNode) {
        foreach ($node in $localDomainsNode.SelectNodes("domain")) {
            $domains += $node.InnerText
        }
    }
    return $domains
}

function New-RoutingConnector {
    param([string]$SmartHost, [string]$AddressSpace, [int]$Port = 25)

    $connectorName = "SRA-Route-$($SmartHost -replace '\.', '-')"

    $existing = Get-SendConnector -Identity $connectorName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Connector '$connectorName' already exists"
        return $connectorName
    }

    Write-Info "Creating: $connectorName (Port: $Port)"

    try {
        New-SendConnector -Name $connectorName `
            -AddressSpaces "SMTP:$AddressSpace;1" `
            -SmartHosts $SmartHost `
            -Port $Port `
            -SmartHostAuthMechanism None `
            -Usage Custom `
            -DNSRoutingEnabled $false `
            -ErrorAction Stop | Out-Null

        Write-Success "Connector created"
        return $connectorName
    }
    catch {
        Write-Err "Failed: $_"
        return $null
    }
}

function Add-RoutingRuleToConfig {
    param(
        [string]$Name,
        [bool]$Enabled = $true,
        [string]$SenderDomain,
        [string]$SenderAddress,
        [string]$RecipientDomain,
        [string]$RecipientAddress,
        [string]$AddressSpace,
        [string]$SendAsAlias
    )

    $rulesNode = $Script:Config.configuration.routingRules
    $newRule = $Script:Config.CreateElement("rule")

    if ($Name) { $newRule.SetAttribute("name", $Name) }
    if (-not $Enabled) { $newRule.SetAttribute("enabled", "false") }
    if ($SenderDomain) { $newRule.SetAttribute("senderDomain", $SenderDomain) }
    if ($SenderAddress) { $newRule.SetAttribute("senderAddress", $SenderAddress) }
    if ($RecipientDomain) { $newRule.SetAttribute("recipientDomain", $RecipientDomain) }
    if ($RecipientAddress) { $newRule.SetAttribute("recipientAddress", $RecipientAddress) }
    if ($AddressSpace) { $newRule.SetAttribute("addressSpace", $AddressSpace) }
    if ($SendAsAlias) { $newRule.SetAttribute("sendAsAlias", $SendAsAlias) }

    $rulesNode.AppendChild($newRule) | Out-Null
}

function Remove-RoutingRuleFromConfig {
    param([int]$Index)
    $rulesNode = $Script:Config.configuration.routingRules
    if ($rulesNode) {
        $rules = $rulesNode.SelectNodes("rule")
        if ($Index -ge 1 -and $Index -le $rules.Count) {
            $rulesNode.RemoveChild($rules[$Index - 1]) | Out-Null
            return $true
        }
    }
    return $false
}

function Move-RoutingRule {
    param([int]$Index, [string]$Direction)
    $rulesNode = $Script:Config.configuration.routingRules
    $rules = @($rulesNode.SelectNodes("rule"))

    if ($Direction -eq "up" -and $Index -gt 1) {
        $rule = $rules[$Index - 1]
        $prevRule = $rules[$Index - 2]
        $rulesNode.RemoveChild($rule) | Out-Null
        $rulesNode.InsertBefore($rule, $prevRule) | Out-Null
        return $true
    }
    elseif ($Direction -eq "down" -and $Index -lt $rules.Count) {
        $rule = $rules[$Index - 1]
        $nextRule = $rules[$Index]
        $rulesNode.RemoveChild($rule) | Out-Null
        $rulesNode.InsertAfter($rule, $nextRule) | Out-Null
        return $true
    }
    return $false
}

function Set-RuleEnabled {
    param([int]$Index, [bool]$Enabled)
    $rulesNode = $Script:Config.configuration.routingRules
    $rules = $rulesNode.SelectNodes("rule")
    if ($Index -ge 1 -and $Index -le $rules.Count) {
        $rule = $rules[$Index - 1]
        if ($Enabled) {
            $rule.RemoveAttribute("enabled")
        } else {
            $rule.SetAttribute("enabled", "false")
        }
        return $true
    }
    return $false
}

#endregion

#region Menu Functions

function Select-ConfigFile {
    Write-Header "Select Configuration File"

    $defaultPath = Find-ConfigFile
    $localPath = Join-Path $PSScriptRoot "routing-config.xml"

    Write-Host "  Available options:" -ForegroundColor Gray
    Write-Host ""

    if ($defaultPath) {
        Write-MenuOption "1" "Active config (installed agent)"
        Write-Host "     $defaultPath" -ForegroundColor DarkGray
    } else {
        Write-Host "  [1] Active config (not found)" -ForegroundColor DarkGray
    }

    Write-MenuOption "2" "Local config (current folder)"
    Write-Host "     $localPath" -ForegroundColor DarkGray

    Write-MenuOption "3" "Enter custom path"
    Write-MenuOption "4" "Create new config file"

    Write-Host ""
    $choice = Read-Host "Select option"

    switch ($choice) {
        "1" { if ($defaultPath) { return $defaultPath } else { Write-Warn "Not found"; return $null } }
        "2" { return $localPath }
        "3" {
            $custom = Read-Host "Enter full path to config file"
            if ($custom) { return $custom }
            return $null
        }
        "4" {
            $newPath = Read-Host "Enter path for new config file"
            if ($newPath) { return $newPath }
            return $null
        }
        default { return $defaultPath }
    }
}

function Show-MainMenu {
    while ($true) {
        Write-Header "Advanced Sender Based Routing - Configuration"

        Write-Host "  Config: $Script:ConfigFile" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuOption "1" "Manage Routing Rules"
        Write-MenuOption "2" "Test Rules"
        Write-MenuOption "3" "Settings"
        Write-MenuOption "4" "Local Domains"
        Write-MenuOption "5" "Manage Connectors"
        Write-MenuOption "6" "View Configuration (XML)"
        Write-MenuOption "7" "Backup/Restore"
        Write-MenuOption "8" "Restart Transport Service"
        Write-MenuOption "H" "Help"
        Write-MenuOption "Q" "Quit"

        Write-Host ""
        $choice = Read-Host "Select"

        switch ($choice.ToUpper()) {
            "1" { Show-RulesMenu }
            "2" { Show-TestRulesMenu }
            "3" { Show-SettingsMenu }
            "4" { Show-LocalDomainsMenu }
            "5" { Show-ConnectorsMenu }
            "6" { Show-CurrentConfig }
            "7" { Show-BackupMenu }
            "8" { Restart-TransportService }
            "H" { Show-Help }
            "Q" { return }
        }
    }
}

function Show-RulesMenu {
    while ($true) {
        Write-Header "Routing Rules"

        $rules = Get-RoutingRules

        if ($rules.Count -eq 0) {
            Write-Host "  No rules configured." -ForegroundColor DarkGray
        } else {
            Write-Host "  # | Ena | Name            | Sender              | Recipient           | Route              | Alias" -ForegroundColor DarkGray
            Write-Host "  --|-----|-----------------|---------------------|---------------------|--------------------|---------" -ForegroundColor DarkGray

            foreach ($r in $rules) {
                $ena = if ($r.Enabled) { "[X]" } else { "[ ]" }
                $enaColor = if ($r.Enabled) { "White" } else { "DarkGray" }
                $name = if ($r.Name) { $r.Name.PadRight(15).Substring(0,15) } else { "".PadRight(15) }
                $sender = if ($r.SenderDomain) { $r.SenderDomain } elseif ($r.SenderAddress) { $r.SenderAddress } else { "" }
                $sender = $sender.PadRight(19).Substring(0,19)
                $recip = if ($r.RecipientDomain) { $r.RecipientDomain } elseif ($r.RecipientAddress) { $r.RecipientAddress } else { "(any)" }
                $recip = $recip.PadRight(19).Substring(0,19)
                $route = if ($r.AddressSpace) { $r.AddressSpace.PadRight(18).Substring(0,18) } else { "".PadRight(18) }
                $alias = if ($r.SendAsAlias) { $r.SendAsAlias } else { "" }

                Write-Host "  $($r.Index.ToString().PadLeft(2)) | " -NoNewline -ForegroundColor $enaColor
                Write-Host "$ena | $name | $sender | $recip | $route | $alias" -ForegroundColor $enaColor
            }
        }

        Write-Host ""
        Write-Host "  Rules are evaluated top-to-bottom. First match wins." -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuOption "A" "Add Rule"
        Write-MenuOption "E" "Edit Rule"
        Write-MenuOption "D" "Delete Rule"
        Write-MenuOption "T" "Toggle Enable/Disable"
        Write-MenuOption "U" "Move Up"
        Write-MenuOption "N" "Move Down"
        Write-MenuOption "C" "Duplicate Rule"
        Write-MenuOption "B" "Back"

        Write-Host ""
        $choice = Read-Host "Select"

        switch ($choice.ToUpper()) {
            "A" { Add-NewRule }
            "E" { Edit-Rule }
            "D" { Remove-Rule }
            "T" { Toggle-Rule }
            "U" { Move-RuleUp }
            "N" { Move-RuleDown }
            "C" { Duplicate-Rule }
            "B" { return }
        }
    }
}

function Add-NewRule {
    Write-Header "Add New Rule"

    Write-Host "  Wildcards: * = any characters, ? = single character" -ForegroundColor DarkGray
    Write-Host ""

    $name = Read-Host "Rule name (optional)"

    Write-Host ""
    Write-Host "  SENDER (at least one required):" -ForegroundColor Cyan
    $senderDomain = Read-Host "Sender Domain (e.g., @domain.com, *.domain.com)"
    $senderAddress = Read-Host "OR Sender Address (e.g., user@domain.com)"

    if (-not $senderDomain -and -not $senderAddress) {
        Write-Warn "Sender domain or address is required"
        Pause-Menu
        return
    }

    Write-Host ""
    Write-Host "  RECIPIENT (optional - empty matches all):" -ForegroundColor Cyan
    $recipientDomain = Read-Host "Recipient Domain (e.g., @partner.com, *.external.com)"
    $recipientAddress = Read-Host "OR Recipient Address (e.g., orders@partner.com)"

    Write-Host ""
    Write-Host "  ROUTING:" -ForegroundColor Cyan
    Write-MenuOption "1" "Select existing connector"
    Write-MenuOption "2" "Create new connector"
    Write-MenuOption "3" "Enter address space manually"
    Write-Host ""
    $routeChoice = Read-Host "Select"

    $addressSpace = ""

    switch ($routeChoice) {
        "1" {
            try {
                $connectors = @(Get-SendConnector -ErrorAction Stop)
                Write-Host ""
                $i = 1
                foreach ($c in $connectors) {
                    $spaces = ($c.AddressSpaces | ForEach-Object { $_.Domain }) -join ", "
                    Write-Host "  [$i] $($c.Name) - $spaces" -ForegroundColor White
                    $i++
                }
                Write-Host ""
                $connIdx = [int](Read-Host "Select connector") - 1
                if ($connIdx -ge 0 -and $connIdx -lt $connectors.Count) {
                    $selectedConn = $connectors[$connIdx]
                    $spaces = @($selectedConn.AddressSpaces | Where-Object { $_.Domain -ne "*" })
                    if ($spaces.Count -gt 0) {
                        $addressSpace = $spaces[0].Domain
                        Write-Info "Using: $addressSpace"
                    } else {
                        Write-Warn "No custom address space on this connector"
                    }
                }
            } catch { Write-Err "Cannot list connectors: $_" }
        }
        "2" {
            $smartHost = Read-Host "Smart host IP or FQDN"
            $port = Read-Host "Port (default 25)"
            if (-not $port) { $port = 25 } else { $port = [int]$port }

            $addressSpace = "route-$($smartHost -replace '[\.\:]', '-').local"
            $connName = New-RoutingConnector -SmartHost $smartHost -AddressSpace $addressSpace -Port $port
        }
        "3" {
            $addressSpace = Read-Host "Address space (e.g., route-relay.local)"
        }
    }

    Write-Host ""
    Write-Host "  SEND-AS-ALIAS (optional):" -ForegroundColor Cyan
    Write-Host "  @domain.com = use sender's local part + domain" -ForegroundColor DarkGray
    Write-Host "  user@domain.com = fixed address" -ForegroundColor DarkGray
    $sendAsAlias = Read-Host "Alias"

    # Validate alias format
    if ($sendAsAlias -and -not $sendAsAlias.StartsWith("@") -and -not $sendAsAlias.Contains("@")) {
        Write-Warn "Alias should be @domain.com or user@domain.com"
        Pause-Menu
        return
    }

    Add-RoutingRuleToConfig -Name $name -SenderDomain $senderDomain -SenderAddress $senderAddress `
        -RecipientDomain $recipientDomain -RecipientAddress $recipientAddress `
        -AddressSpace $addressSpace -SendAsAlias $sendAsAlias

    if (Save-Configuration) {
        Write-Success "Rule added"
    }
    Pause-Menu
}

function Edit-Rule {
    $rules = Get-RoutingRules
    if ($rules.Count -eq 0) { Write-Warn "No rules"; Pause-Menu; return }

    Write-Host ""
    $idx = [int](Read-Host "Rule number to edit") - 1

    if ($idx -lt 0 -or $idx -ge $rules.Count) { Write-Warn "Invalid"; Pause-Menu; return }

    $rule = $rules[$idx]
    $rulesNode = $Script:Config.configuration.routingRules
    $xmlRule = $rulesNode.SelectNodes("rule")[$idx]

    Write-Header "Edit Rule #$($idx + 1)"

    Write-Host "  Leave empty to keep current value. Enter '-' to clear." -ForegroundColor DarkGray
    Write-Host ""

    $newName = Read-Host "Name [$($rule.Name)]"
    $newSenderDomain = Read-Host "Sender Domain [$($rule.SenderDomain)]"
    $newSenderAddress = Read-Host "Sender Address [$($rule.SenderAddress)]"
    $newRecipientDomain = Read-Host "Recipient Domain [$($rule.RecipientDomain)]"
    $newRecipientAddress = Read-Host "Recipient Address [$($rule.RecipientAddress)]"
    $newAddressSpace = Read-Host "Address Space [$($rule.AddressSpace)]"
    $newAlias = Read-Host "Send-As-Alias [$($rule.SendAsAlias)]"

    # Update attributes
    if ($newName -eq "-") { $xmlRule.RemoveAttribute("name") }
    elseif ($newName) { $xmlRule.SetAttribute("name", $newName) }

    if ($newSenderDomain -eq "-") { $xmlRule.RemoveAttribute("senderDomain") }
    elseif ($newSenderDomain) { $xmlRule.SetAttribute("senderDomain", $newSenderDomain) }

    if ($newSenderAddress -eq "-") { $xmlRule.RemoveAttribute("senderAddress") }
    elseif ($newSenderAddress) { $xmlRule.SetAttribute("senderAddress", $newSenderAddress) }

    if ($newRecipientDomain -eq "-") { $xmlRule.RemoveAttribute("recipientDomain") }
    elseif ($newRecipientDomain) { $xmlRule.SetAttribute("recipientDomain", $newRecipientDomain) }

    if ($newRecipientAddress -eq "-") { $xmlRule.RemoveAttribute("recipientAddress") }
    elseif ($newRecipientAddress) { $xmlRule.SetAttribute("recipientAddress", $newRecipientAddress) }

    if ($newAddressSpace -eq "-") { $xmlRule.RemoveAttribute("addressSpace") }
    elseif ($newAddressSpace) { $xmlRule.SetAttribute("addressSpace", $newAddressSpace) }

    if ($newAlias -eq "-") { $xmlRule.RemoveAttribute("sendAsAlias") }
    elseif ($newAlias) { $xmlRule.SetAttribute("sendAsAlias", $newAlias) }

    if (Save-Configuration) { Write-Success "Rule updated" }
    Pause-Menu
}

function Remove-Rule {
    $rules = Get-RoutingRules
    if ($rules.Count -eq 0) { Write-Warn "No rules"; Pause-Menu; return }

    Write-Host ""
    $idx = Read-Host "Rule number to delete"

    if (Remove-RoutingRuleFromConfig -Index ([int]$idx)) {
        if (Save-Configuration) { Write-Success "Rule deleted" }
    } else { Write-Warn "Invalid rule number" }
    Pause-Menu
}

function Toggle-Rule {
    $rules = Get-RoutingRules
    if ($rules.Count -eq 0) { Write-Warn "No rules"; Pause-Menu; return }

    Write-Host ""
    $idx = [int](Read-Host "Rule number to toggle")
    $rule = $rules | Where-Object { $_.Index -eq $idx }

    if ($rule) {
        if (Set-RuleEnabled -Index $idx -Enabled (-not $rule.Enabled)) {
            if (Save-Configuration) {
                $status = if (-not $rule.Enabled) { "enabled" } else { "disabled" }
                Write-Success "Rule $idx $status"
            }
        }
    } else { Write-Warn "Invalid" }
    Pause-Menu
}

function Move-RuleUp {
    Write-Host ""
    $idx = [int](Read-Host "Rule number to move up")
    if (Move-RoutingRule -Index $idx -Direction "up") {
        if (Save-Configuration) { Write-Success "Moved up" }
    } else { Write-Warn "Cannot move" }
    Pause-Menu
}

function Move-RuleDown {
    Write-Host ""
    $idx = [int](Read-Host "Rule number to move down")
    if (Move-RoutingRule -Index $idx -Direction "down") {
        if (Save-Configuration) { Write-Success "Moved down" }
    } else { Write-Warn "Cannot move" }
    Pause-Menu
}

function Duplicate-Rule {
    $rules = Get-RoutingRules
    if ($rules.Count -eq 0) { Write-Warn "No rules"; Pause-Menu; return }

    Write-Host ""
    $idx = [int](Read-Host "Rule number to duplicate") - 1

    if ($idx -ge 0 -and $idx -lt $rules.Count) {
        $r = $rules[$idx]
        Add-RoutingRuleToConfig -Name "$($r.Name) (Copy)" -Enabled $r.Enabled `
            -SenderDomain $r.SenderDomain -SenderAddress $r.SenderAddress `
            -RecipientDomain $r.RecipientDomain -RecipientAddress $r.RecipientAddress `
            -AddressSpace $r.AddressSpace -SendAsAlias $r.SendAsAlias
        if (Save-Configuration) { Write-Success "Rule duplicated" }
    } else { Write-Warn "Invalid" }
    Pause-Menu
}

function Show-TestRulesMenu {
    Write-Header "Test Rules"

    Write-Host "  Test how rules will process an email." -ForegroundColor DarkGray
    Write-Host ""

    $sender = Read-Host "Sender address"
    $recipient = Read-Host "Recipient address"

    if (-not $sender) { Write-Warn "Sender required"; Pause-Menu; return }

    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host " TEST RESULTS" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Sender:    $sender" -ForegroundColor White
    Write-Host "  Recipient: $(if ($recipient) { $recipient } else { '(none)' })" -ForegroundColor White
    Write-Host ""
    Write-Host "-" * 60 -ForegroundColor DarkGray

    $rules = Get-RoutingRules
    $matchedRule = $null

    foreach ($r in $rules) {
        $ruleName = if ($r.Name) { $r.Name } else { "Rule #$($r.Index)" }

        if (-not $r.Enabled) {
            Write-Host "  $ruleName : DISABLED (skipped)" -ForegroundColor DarkGray
            continue
        }

        $senderMatch = Test-SenderMatch -Rule $r -SenderAddress $sender
        $recipientMatch = Test-RecipientMatch -Rule $r -RecipientAddress $recipient

        $senderCond = if ($r.SenderAddress) { "Addr=$($r.SenderAddress)" } elseif ($r.SenderDomain) { "Dom=$($r.SenderDomain)" } else { "?" }
        $recipCond = if ($r.RecipientAddress) { "Addr=$($r.RecipientAddress)" } elseif ($r.RecipientDomain) { "Dom=$($r.RecipientDomain)" } else { "(any)" }

        $sMatch = if ($senderMatch) { "YES" } else { "NO" }
        $rMatch = if ($recipientMatch) { "YES" } else { "NO" }

        if ($senderMatch -and $recipientMatch) {
            Write-Host "  $ruleName : Sender=$sMatch, Recipient=$rMatch -> " -NoNewline -ForegroundColor White
            Write-Host "MATCHED" -ForegroundColor Green
            $matchedRule = $r
            break
        } else {
            Write-Host "  $ruleName : Sender=$sMatch, Recipient=$rMatch" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan

    if ($matchedRule) {
        Write-Host ""
        Write-Host "  MATCHED: $(if ($matchedRule.Name) { $matchedRule.Name } else { "Rule #$($matchedRule.Index)" })" -ForegroundColor Green
        Write-Host ""

        if ($matchedRule.AddressSpace) {
            Write-Host "  Route via: $($matchedRule.AddressSpace)" -ForegroundColor Cyan
        }

        if ($matchedRule.SendAsAlias) {
            $alias = $matchedRule.SendAsAlias
            if ($alias.StartsWith("@")) {
                $localPart = $sender.Split("@")[0]
                $aliasAddr = $localPart + $alias
                Write-Host "  From header: $aliasAddr (constructed)" -ForegroundColor Magenta
            } else {
                Write-Host "  From header: $alias" -ForegroundColor Magenta
            }
        }

        # Check local domain bypass
        if ($recipient) {
            $localDomains = Get-LocalDomains
            $recipDomain = $recipient.Split("@")[-1].ToLower()
            if ($localDomains -contains $recipDomain -and (Get-FeatureStatus "bypassLocalRecipients")) {
                Write-Host ""
                Write-Host "  NOTE: Recipient in local domain - routing BYPASSED" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host ""
        Write-Host "  NO MATCH - Default Exchange routing will be used" -ForegroundColor Yellow
    }

    Pause-Menu
}

function Show-SettingsMenu {
    while ($true) {
        Write-Header "Settings"

        $settings = @(
            @{ Name = "enableSendAsAlias"; Label = "Send-As-Alias"; Desc = "Preserve/set alias in From header" },
            @{ Name = "enableSenderBasedRouting"; Label = "Sender-Based Routing"; Desc = "Route based on sender rules" },
            @{ Name = "bypassLocalRecipients"; Label = "Bypass Local Recipients"; Desc = "Skip routing for internal recipients" },
            @{ Name = "routeByHeaderFrom"; Label = "Route By Header From (P2)"; Desc = "Match rules by alias instead of primary" },
            @{ Name = "validateProxyAddresses"; Label = "Validate Proxy Addresses"; Desc = "Check if user has alias in target domain" },
            @{ Name = "blockIfNoAlias"; Label = "Block If No Alias"; Desc = "Don't apply alias if user lacks it" }
        )

        $i = 1
        foreach ($s in $settings) {
            $status = Get-FeatureStatus $s.Name
            $statusText = if ($status) { "[ON]" } else { "[OFF]" }
            $statusColor = if ($status) { "Green" } else { "Red" }

            Write-Host "  [$i] $($s.Label.PadRight(28)) " -NoNewline
            Write-Host $statusText -ForegroundColor $statusColor
            Write-Host "      $($s.Desc)" -ForegroundColor DarkGray
            $i++
        }

        Write-Host ""
        Write-MenuOption "1-6" "Toggle setting"
        Write-MenuOption "B" "Back"

        Write-Host ""
        $choice = Read-Host "Select"

        if ($choice.ToUpper() -eq "B") { return }

        $idx = 0
        if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $settings.Count) {
            $setting = $settings[$idx - 1]
            $current = Get-FeatureStatus $setting.Name
            Set-FeatureStatus $setting.Name (-not $current)
            if (Save-Configuration) {
                $newStatus = if (-not $current) { "enabled" } else { "disabled" }
                Write-Success "$($setting.Label) $newStatus"
            }
            Pause-Menu
        }
    }
}

function Show-LocalDomainsMenu {
    while ($true) {
        Write-Header "Local Domains"

        Write-Host "  Recipients in these domains bypass routing rules." -ForegroundColor DarkGray
        Write-Host ""

        $domains = Get-LocalDomains
        if ($domains.Count -eq 0) {
            Write-Host "  No local domains configured." -ForegroundColor DarkGray
        } else {
            $i = 1
            foreach ($d in $domains) {
                Write-Host "  [$i] $d" -ForegroundColor Cyan
                $i++
            }
        }

        Write-Host ""
        Write-MenuOption "A" "Add Domain"
        Write-MenuOption "R" "Remove Domain"
        Write-MenuOption "D" "Auto-Detect from Exchange"
        Write-MenuOption "B" "Back"

        Write-Host ""
        $choice = Read-Host "Select"

        switch ($choice.ToUpper()) {
            "A" {
                $newDomain = Read-Host "Domain to add"
                if ($newDomain) {
                    $newDomain = $newDomain.ToLower().TrimStart('@')
                    $localDomainsNode = $Script:Config.configuration.SelectSingleNode("localDomains")
                    $domainElement = $Script:Config.CreateElement("domain")
                    $domainElement.InnerText = $newDomain
                    $localDomainsNode.AppendChild($domainElement) | Out-Null
                    if (Save-Configuration) { Write-Success "Added: $newDomain" }
                }
                Pause-Menu
            }
            "R" {
                if ($domains.Count -eq 0) { Write-Warn "No domains"; Pause-Menu; continue }
                $idx = [int](Read-Host "Domain number to remove") - 1
                if ($idx -ge 0 -and $idx -lt $domains.Count) {
                    $localDomainsNode = $Script:Config.configuration.SelectSingleNode("localDomains")
                    $domainNodes = $localDomainsNode.SelectNodes("domain")
                    $localDomainsNode.RemoveChild($domainNodes[$idx]) | Out-Null
                    if (Save-Configuration) { Write-Success "Removed" }
                }
                Pause-Menu
            }
            "D" {
                try {
                    $accepted = Get-AcceptedDomain -ErrorAction Stop
                    $localDomainsNode = $Script:Config.configuration.SelectSingleNode("localDomains")
                    $added = 0
                    foreach ($ad in $accepted) {
                        $dn = $ad.DomainName.ToString().ToLower()
                        if ($domains -notcontains $dn) {
                            $el = $Script:Config.CreateElement("domain")
                            $el.InnerText = $dn
                            $localDomainsNode.AppendChild($el) | Out-Null
                            Write-Host "  Added: $dn" -ForegroundColor Green
                            $added++
                        }
                    }
                    if ($added -gt 0) { Save-Configuration | Out-Null; Write-Success "Added $added domain(s)" }
                    else { Write-Info "No new domains" }
                } catch { Write-Err "Failed: $_" }
                Pause-Menu
            }
            "B" { return }
        }
    }
}

function Show-ConnectorsMenu {
    while ($true) {
        Write-Header "Send Connectors"

        try {
            $connectors = @(Get-SendConnector | Where-Object { $_.Name -like "SRA-Route-*" })

            if ($connectors.Count -eq 0) {
                Write-Host "  No SRA routing connectors found." -ForegroundColor DarkGray
            } else {
                foreach ($c in $connectors) {
                    $spaces = ($c.AddressSpaces | ForEach-Object { $_.Domain }) -join ", "
                    $hosts = ($c.SmartHosts | ForEach-Object { $_.ToString() }) -join ", "
                    $status = if ($c.Enabled) { "[Enabled]" } else { "[Disabled]" }
                    $color = if ($c.Enabled) { "Green" } else { "Red" }

                    Write-Host "  $($c.Name) " -NoNewline -ForegroundColor White
                    Write-Host $status -ForegroundColor $color
                    Write-Host "    Space: $spaces" -ForegroundColor Cyan
                    Write-Host "    Host:  $hosts" -ForegroundColor DarkGray
                    Write-Host ""
                }
            }
        } catch { Write-Err "Cannot list: $_" }

        Write-Host ""
        Write-MenuOption "N" "Create New Connector"
        Write-MenuOption "D" "Delete Connector"
        Write-MenuOption "L" "List ALL Connectors"
        Write-MenuOption "B" "Back"

        Write-Host ""
        $choice = Read-Host "Select"

        switch ($choice.ToUpper()) {
            "N" {
                $smartHost = Read-Host "Smart host IP or FQDN"
                if ($smartHost) {
                    $port = Read-Host "Port (default 25)"
                    if (-not $port) { $port = 25 } else { $port = [int]$port }
                    $addressSpace = "route-$($smartHost -replace '[\.\:]', '-').local"
                    New-RoutingConnector -SmartHost $smartHost -AddressSpace $addressSpace -Port $port
                }
                Pause-Menu
            }
            "D" {
                $name = Read-Host "Connector name to delete"
                if ($name) {
                    try {
                        Remove-SendConnector -Identity $name -Confirm:$false -ErrorAction Stop
                        Write-Success "Deleted: $name"
                    } catch { Write-Err "Failed: $_" }
                }
                Pause-Menu
            }
            "L" {
                Write-Host ""
                try {
                    $all = Get-SendConnector
                    foreach ($c in $all) {
                        $spaces = ($c.AddressSpaces | ForEach-Object { $_.Domain }) -join ", "
                        Write-Host "  $($c.Name) - $spaces" -ForegroundColor White
                    }
                } catch { Write-Err "$_" }
                Pause-Menu
            }
            "B" { return }
        }
    }
}

function Show-CurrentConfig {
    Write-Header "Configuration (XML)"
    Write-Host (Get-Content $Script:ConfigFile -Raw) -ForegroundColor White
    Pause-Menu
}

function Show-BackupMenu {
    Write-Header "Backup / Restore"

    Write-MenuOption "B" "Create Backup"
    Write-MenuOption "R" "Restore from Backup"
    Write-MenuOption "X" "Back"

    Write-Host ""
    $choice = Read-Host "Select"

    switch ($choice.ToUpper()) {
        "B" {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $backupFile = "$Script:ConfigFile.backup.$timestamp"
            try {
                Copy-Item $Script:ConfigFile $backupFile -Force
                Write-Success "Backed up to: $backupFile"
            } catch { Write-Err "Failed: $_" }
            Pause-Menu
        }
        "R" {
            $dir = Split-Path $Script:ConfigFile
            $backups = @(Get-ChildItem "$dir\*.backup.*" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)

            if ($backups.Count -eq 0) { Write-Warn "No backups found"; Pause-Menu; return }

            Write-Host ""
            $i = 1
            foreach ($b in $backups) {
                Write-Host "  [$i] $($b.Name) - $($b.LastWriteTime)" -ForegroundColor White
                $i++
            }

            Write-Host ""
            $idx = [int](Read-Host "Backup number to restore") - 1

            if ($idx -ge 0 -and $idx -lt $backups.Count) {
                Copy-Item $backups[$idx].FullName $Script:ConfigFile -Force
                Load-Configuration | Out-Null
                Write-Success "Restored from: $($backups[$idx].Name)"
            }
            Pause-Menu
        }
    }
}

function Restart-TransportService {
    Write-Header "Restart Transport Service"

    Write-Warn "This will briefly interrupt mail flow!"
    Write-Host ""

    $confirm = Read-Host "Type 'yes' to restart"

    if ($confirm -eq "yes") {
        try {
            Restart-Service MSExchangeTransport -Force
            Write-Success "Service restarted"
        } catch { Write-Err "Failed: $_" }
    } else {
        Write-Info "Cancelled"
    }
    Pause-Menu
}

function Show-Help {
    Write-Header "Help"

    $help = @"
ADVANCED SENDER BASED ROUTING - CONSOLE CONFIGURATION
======================================================

FEATURES:
  - Send-As-Alias: Changes From header and Return-Path to alias address
  - Sender-Based Routing: Routes emails via specific connectors
  - Advanced Rules: Sender AND recipient conditions with wildcards
  - Per-Recipient Routing: Different routing for different recipients

WILDCARDS (in sender/recipient fields):
  *  = matches any characters (zero or more)
  ?  = matches any single character

  Examples:
    @*.company.com     - any subdomain
    admin*@domain.com  - admin, admin1, admin2, etc.
    user?@domain.com   - user1, userA, etc.

RULE EVALUATION:
  - Rules are checked top-to-bottom
  - First matching rule wins
  - Use Move Up/Down to change priority
  - Each recipient is evaluated independently

SEND-AS-ALIAS FORMAT:
  @domain.com      - constructs alias from sender's local part
                     (user@old.com -> user@domain.com)
  user@domain.com  - uses exact address

ADDRESS SPACE:
  - Rules use connector address spaces, not direct IPs
  - Create connectors with "Manage Connectors" menu
  - Format: route-<ip>.local (e.g., route-10-10-10-10.local)

TROUBLESHOOTING:
  - Check agent: Get-TransportAgent "Advanced Sender Based Routing Agent"
  - View logs: Event Viewer > Application > MSExchangeTransport
  - Filter logs by source: AdvancedSenderRouting
  - Restart after changes: Restart-Service MSExchangeTransport
"@

    Write-Host $help -ForegroundColor White
    Pause-Menu
}

#endregion

#region Main

# Select or find config file
if ([string]::IsNullOrEmpty($ConfigPath)) {
    $Script:ConfigFile = Select-ConfigFile
    if (-not $Script:ConfigFile) {
        Write-Err "No configuration file selected"
        exit 1
    }
} else {
    $Script:ConfigFile = $ConfigPath
}

# Load configuration
if (-not (Load-Configuration)) {
    exit 1
}

# Show main menu
Show-MainMenu

Write-Host ""
Write-Host "Remember to restart transport service for changes to take effect:" -ForegroundColor Yellow
Write-Host "  Restart-Service MSExchangeTransport" -ForegroundColor White
Write-Host ""

#endregion
