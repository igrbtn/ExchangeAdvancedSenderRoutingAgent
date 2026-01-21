#Requires -RunAsAdministrator
<#
.SYNOPSIS
    GUI Configuration Manager for Advanced Sender Based Routing Agent.

.DESCRIPTION
    Windows Forms GUI for managing routing rules, local domains, and settings.
    Features:
    - Advanced rule management with sender AND recipient conditions
    - Wildcard support (* and ?) in rules
    - Connector selection or creation
    - Rule validation/testing
    - Proxy address validation settings

.EXAMPLE
    .\configure-gui.ps1
    Launch GUI with auto-detected config path.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Find config file
function Get-ConfigPath {
    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        return $ConfigPath
    }

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup",
        "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup"
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $installPath = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).MsiInstallPath
            if ($installPath) {
                $path = Join-Path $installPath "TransportRoles\agents\AdvancedSenderRouting\routing-config.xml"
                if (Test-Path $path) {
                    return $path
                }
            }
        }
    }

    $localPath = Join-Path $PSScriptRoot "routing-config.xml"
    if (Test-Path $localPath) {
        return $localPath
    }

    return $null
}

# Get existing Send Connectors
function Get-SRAConnectors {
    $connectors = @()
    try {
        $allConnectors = Get-SendConnector -ErrorAction Stop
        foreach ($conn in $allConnectors) {
            foreach ($as in $conn.AddressSpaces) {
                $connectors += @{
                    Name = $conn.Name
                    AddressSpace = $as.Domain
                    SmartHosts = ($conn.SmartHosts | ForEach-Object { $_.ToString() }) -join ", "
                }
            }
        }
    }
    catch {
        # Not running in Exchange Management Shell
    }
    return $connectors
}

# Load configuration from XML
function Load-Configuration {
    param([string]$Path)

    $config = @{
        Settings = @{
            EnableSendAsAlias = $true
            EnableSenderBasedRouting = $true
            BypassLocalRecipients = $true
            RouteByHeaderFrom = $false
            ValidateProxyAddresses = $true
            BlockIfNoAlias = $false
        }
        LocalDomains = @()
        Rules = @()
    }

    if (-not (Test-Path $Path)) {
        return $config
    }

    try {
        [xml]$xml = Get-Content $Path -Encoding UTF8
        $root = $xml.configuration

        if ($root.settings) {
            if ($root.settings.enableSendAsAlias) {
                $config.Settings.EnableSendAsAlias = [bool]::Parse($root.settings.enableSendAsAlias)
            }
            if ($root.settings.enableSenderBasedRouting) {
                $config.Settings.EnableSenderBasedRouting = [bool]::Parse($root.settings.enableSenderBasedRouting)
            }
            if ($root.settings.bypassLocalRecipients) {
                $config.Settings.BypassLocalRecipients = [bool]::Parse($root.settings.bypassLocalRecipients)
            }
            if ($root.settings.routeByHeaderFrom) {
                $config.Settings.RouteByHeaderFrom = [bool]::Parse($root.settings.routeByHeaderFrom)
            }
            if ($root.settings.validateProxyAddresses) {
                $config.Settings.ValidateProxyAddresses = [bool]::Parse($root.settings.validateProxyAddresses)
            }
            if ($root.settings.blockIfNoAlias) {
                $config.Settings.BlockIfNoAlias = [bool]::Parse($root.settings.blockIfNoAlias)
            }
        }

        if ($root.localDomains -and $root.localDomains.domain) {
            foreach ($domain in $root.localDomains.domain) {
                if ($domain -and $domain.Trim()) {
                    $config.LocalDomains += $domain.Trim()
                }
            }
        }

        if ($root.routingRules -and $root.routingRules.rule) {
            foreach ($rule in $root.routingRules.rule) {
                $ruleObj = @{
                    Name = if ($rule.name) { $rule.name } else { "" }
                    Enabled = if ($rule.enabled) { [bool]::Parse($rule.enabled) } else { $true }
                    SenderDomain = if ($rule.senderDomain) { $rule.senderDomain } else { "" }
                    SenderAddress = if ($rule.senderAddress) { $rule.senderAddress } else { "" }
                    RecipientDomain = if ($rule.recipientDomain) { $rule.recipientDomain } else { "" }
                    RecipientAddress = if ($rule.recipientAddress) { $rule.recipientAddress } else { "" }
                    AddressSpace = if ($rule.addressSpace) { $rule.addressSpace } else { "" }
                    SendAsAlias = if ($rule.sendAsAlias) { $rule.sendAsAlias } else { "" }
                }
                $config.Rules += $ruleObj
            }
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error loading config: $_", "Error", "OK", "Error")
    }

    return $config
}

# Save configuration to XML
function Save-Configuration {
    param([string]$Path, $Config)

    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<!--
  Advanced Sender Based Routing Agent Configuration
  Generated by configure-gui.ps1

  Wildcards supported in sender/recipient fields:
    * = any characters (zero or more)
    ? = any single character
  Examples: *@domain.com, user*@*.company.com, sales?@corp.com
-->
<configuration>

  <settings>
    <enableSendAsAlias>$($Config.Settings.EnableSendAsAlias.ToString().ToLower())</enableSendAsAlias>
    <enableSenderBasedRouting>$($Config.Settings.EnableSenderBasedRouting.ToString().ToLower())</enableSenderBasedRouting>
    <bypassLocalRecipients>$($Config.Settings.BypassLocalRecipients.ToString().ToLower())</bypassLocalRecipients>
    <routeByHeaderFrom>$($Config.Settings.RouteByHeaderFrom.ToString().ToLower())</routeByHeaderFrom>
    <validateProxyAddresses>$($Config.Settings.ValidateProxyAddresses.ToString().ToLower())</validateProxyAddresses>
    <blockIfNoAlias>$($Config.Settings.BlockIfNoAlias.ToString().ToLower())</blockIfNoAlias>
  </settings>

  <localDomains>
"@

    foreach ($domain in $Config.LocalDomains) {
        $xml += "`n    <domain>$domain</domain>"
    }

    $xml += @"

  </localDomains>

  <routingRules>
"@

    foreach ($rule in $Config.Rules) {
        $attrs = @()
        if ($rule.Name) { $attrs += "name=`"$($rule.Name)`"" }
        if (-not $rule.Enabled) { $attrs += "enabled=`"false`"" }
        if ($rule.SenderDomain) { $attrs += "senderDomain=`"$($rule.SenderDomain)`"" }
        if ($rule.SenderAddress) { $attrs += "senderAddress=`"$($rule.SenderAddress)`"" }
        if ($rule.RecipientDomain) { $attrs += "recipientDomain=`"$($rule.RecipientDomain)`"" }
        if ($rule.RecipientAddress) { $attrs += "recipientAddress=`"$($rule.RecipientAddress)`"" }
        if ($rule.AddressSpace) { $attrs += "addressSpace=`"$($rule.AddressSpace)`"" }
        if ($rule.SendAsAlias) { $attrs += "sendAsAlias=`"$($rule.SendAsAlias)`"" }

        if ($attrs.Count -gt 0) {
            $xml += "`n    <rule $($attrs -join ' ') />"
        }
    }

    $xml += @"

  </routingRules>

</configuration>
"@

    try {
        $xml | Out-File -FilePath $Path -Encoding UTF8 -Force
        return $true
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error saving config: $_", "Error", "OK", "Error")
        return $false
    }
}

# Wildcard pattern matching
function Test-WildcardMatch {
    param([string]$InputString, [string]$Pattern)

    if ([string]::IsNullOrEmpty($Pattern)) {
        return [string]::IsNullOrEmpty($InputString)
    }

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

# Test if sender matches rule
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
            if (-not $pattern.StartsWith("*")) {
                $pattern = "*@" + $pattern.TrimStart('@')
            }
            return Test-WildcardMatch -InputString $SenderAddress -Pattern $pattern
        }
        $domain = if ($pattern.StartsWith("@")) { $pattern } else { "@" + $pattern }
        return $SenderAddress.EndsWith($domain)
    }

    return $false
}

# Test if recipient matches rule
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
            if (-not $pattern.StartsWith("*")) {
                $pattern = "*@" + $pattern.TrimStart('@')
            }
            return Test-WildcardMatch -InputString $RecipientAddress -Pattern $pattern
        }
        $domain = if ($pattern.StartsWith("@")) { $pattern } else { "@" + $pattern }
        return $RecipientAddress.EndsWith($domain)
    }

    return $false
}

# Create Send Connector
function Create-SendConnector {
    param(
        [string]$SmartHost,
        [string]$AddressSpace,
        [int]$Port = 25
    )

    try {
        $null = Get-Command Get-SendConnector -ErrorAction Stop
        $connectorName = "SRA-Route-$($SmartHost -replace '\.', '-')"

        $existing = Get-SendConnector -Identity $connectorName -ErrorAction SilentlyContinue
        if ($existing) {
            return @{ Success = $true; Message = "Connector '$connectorName' already exists"; AddressSpace = $AddressSpace; ConnectorName = $connectorName }
        }

        New-SendConnector -Name $connectorName `
            -AddressSpaces "SMTP:${AddressSpace};1" `
            -SmartHosts $SmartHost `
            -Port $Port `
            -Usage Custom `
            -DNSRoutingEnabled $false `
            -SmartHostAuthMechanism None `
            -ErrorAction Stop

        return @{ Success = $true; Message = "Created connector '$connectorName' (port $Port)"; AddressSpace = $AddressSpace; ConnectorName = $connectorName }
    }
    catch {
        return @{ Success = $false; Message = "Error: $_"; AddressSpace = $AddressSpace }
    }
}

# Ask user which config file to edit
function Select-ConfigFile {
    $defaultConfig = Get-ConfigPath

    # Create selection form
    $selectForm = New-Object System.Windows.Forms.Form
    $selectForm.Text = "Select Configuration File"
    $selectForm.Size = New-Object System.Drawing.Size(500, 250)
    $selectForm.StartPosition = "CenterScreen"
    $selectForm.FormBorderStyle = "FixedDialog"
    $selectForm.MaximizeBox = $false
    $selectForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $lblPrompt = New-Object System.Windows.Forms.Label
    $lblPrompt.Text = "Select configuration file to edit:"
    $lblPrompt.Location = New-Object System.Drawing.Point(15, 15)
    $lblPrompt.Size = New-Object System.Drawing.Size(450, 20)

    # Radio buttons
    $radioDefault = New-Object System.Windows.Forms.RadioButton
    $radioDefault.Text = "Active configuration (installed agent)"
    $radioDefault.Location = New-Object System.Drawing.Point(20, 45)
    $radioDefault.Size = New-Object System.Drawing.Size(450, 25)
    $radioDefault.Checked = $true
    if (-not $defaultConfig) {
        $radioDefault.Text = "Active configuration (not found)"
        $radioDefault.Enabled = $false
        $radioDefault.Checked = $false
    }

    $radioLocal = New-Object System.Windows.Forms.RadioButton
    $radioLocal.Text = "Local config (current folder)"
    $radioLocal.Location = New-Object System.Drawing.Point(20, 70)
    $radioLocal.Size = New-Object System.Drawing.Size(450, 25)
    $localConfig = Join-Path $PSScriptRoot "routing-config.xml"
    if (-not (Test-Path $localConfig)) {
        $radioLocal.Text = "Local config (not found - will create new)"
    }
    if (-not $defaultConfig) {
        $radioLocal.Checked = $true
    }

    $radioBrowse = New-Object System.Windows.Forms.RadioButton
    $radioBrowse.Text = "Browse for file (backup, sample, etc.)..."
    $radioBrowse.Location = New-Object System.Drawing.Point(20, 95)
    $radioBrowse.Size = New-Object System.Drawing.Size(450, 25)

    $radioNew = New-Object System.Windows.Forms.RadioButton
    $radioNew.Text = "Create new configuration file"
    $radioNew.Location = New-Object System.Drawing.Point(20, 120)
    $radioNew.Size = New-Object System.Drawing.Size(450, 25)

    # Path display
    $lblPath = New-Object System.Windows.Forms.Label
    $lblPath.Text = if ($defaultConfig) { "Path: $defaultConfig" } else { "Path: (none)" }
    $lblPath.Location = New-Object System.Drawing.Point(20, 155)
    $lblPath.Size = New-Object System.Drawing.Size(450, 20)
    $lblPath.ForeColor = [System.Drawing.Color]::Gray

    # Update path label based on selection
    $updatePath = {
        if ($radioDefault.Checked -and $defaultConfig) {
            $lblPath.Text = "Path: $defaultConfig"
        } elseif ($radioLocal.Checked) {
            $lblPath.Text = "Path: $localConfig"
        } elseif ($radioBrowse.Checked) {
            $lblPath.Text = "Path: (will browse...)"
        } elseif ($radioNew.Checked) {
            $lblPath.Text = "Path: (will select location...)"
        }
    }

    $radioDefault.Add_CheckedChanged($updatePath)
    $radioLocal.Add_CheckedChanged($updatePath)
    $radioBrowse.Add_CheckedChanged($updatePath)
    $radioNew.Add_CheckedChanged($updatePath)

    # Buttons
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = "OK"
    $btnOK.Location = New-Object System.Drawing.Point(300, 180)
    $btnOK.Size = New-Object System.Drawing.Size(80, 30)
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(390, 180)
    $btnCancel.Size = New-Object System.Drawing.Size(80, 30)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $selectForm.AcceptButton = $btnOK
    $selectForm.CancelButton = $btnCancel

    $selectForm.Controls.AddRange(@($lblPrompt, $radioDefault, $radioLocal, $radioBrowse, $radioNew, $lblPath, $btnOK, $btnCancel))

    $result = $selectForm.ShowDialog()

    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        return $null  # User cancelled
    }

    # Determine selected path
    if ($radioDefault.Checked -and $defaultConfig) {
        return $defaultConfig
    }
    elseif ($radioLocal.Checked) {
        return $localConfig
    }
    elseif ($radioBrowse.Checked) {
        $openDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openDialog.Filter = "XML files (*.xml)|*.xml|All files (*.*)|*.*"
        $openDialog.Title = "Select Configuration File"
        if ($PSScriptRoot) {
            $openDialog.InitialDirectory = $PSScriptRoot
        }
        if ($openDialog.ShowDialog() -eq "OK") {
            return $openDialog.FileName
        }
        return $null
    }
    elseif ($radioNew.Checked) {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "XML files (*.xml)|*.xml"
        $saveDialog.FileName = "routing-config.xml"
        $saveDialog.Title = "Create New Configuration File"
        if ($PSScriptRoot) {
            $saveDialog.InitialDirectory = $PSScriptRoot
        }
        if ($saveDialog.ShowDialog() -eq "OK") {
            return $saveDialog.FileName
        }
        return $null
    }

    return $null
}

# Initialize - ask user for config file
$configFile = Select-ConfigFile

if (-not $configFile) {
    # User cancelled
    exit
}

$config = $null
$connectors = @()

if (Test-Path $configFile) {
    $config = Load-Configuration -Path $configFile
} else {
    # New file - use defaults
    $config = @{
        Settings = @{
            EnableSendAsAlias = $true
            EnableSenderBasedRouting = $true
            BypassLocalRecipients = $true
            RouteByHeaderFrom = $false
            ValidateProxyAddresses = $true
            BlockIfNoAlias = $false
        }
        LocalDomains = @()
        Rules = @()
    }
}

$connectors = Get-SRAConnectors

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Advanced Sender Based Routing - Configuration"
$form.Size = New-Object System.Drawing.Size(950, 750)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(915, 650)

# ============= RULES TAB =============
$tabRules = New-Object System.Windows.Forms.TabPage
$tabRules.Text = "Routing Rules"
$tabRules.Padding = New-Object System.Windows.Forms.Padding(10)

# Rules ListView
$listRules = New-Object System.Windows.Forms.ListView
$listRules.Location = New-Object System.Drawing.Point(10, 10)
$listRules.Size = New-Object System.Drawing.Size(880, 280)
$listRules.View = "Details"
$listRules.FullRowSelect = $true
$listRules.GridLines = $true

$listRules.Columns.Add("#", 35) | Out-Null
$listRules.Columns.Add("", 40) | Out-Null
$listRules.Columns.Add("Name", 85) | Out-Null
$listRules.Columns.Add("Sender Domain", 105) | Out-Null
$listRules.Columns.Add("Sender Address", 105) | Out-Null
$listRules.Columns.Add("Rcpt Domain", 95) | Out-Null
$listRules.Columns.Add("Rcpt Address", 95) | Out-Null
$listRules.Columns.Add("Connector/Space", 135) | Out-Null
$listRules.Columns.Add("Send As Alias", 95) | Out-Null

function Refresh-RulesList {
    $listRules.Items.Clear()
    $ruleNum = 0
    foreach ($rule in $config.Rules) {
        $ruleNum++
        $item = New-Object System.Windows.Forms.ListViewItem($ruleNum.ToString())
        $item.SubItems.Add($(if ($rule.Enabled) { "[X]" } else { "[ ]" }))
        $item.SubItems.Add($rule.Name)
        $item.SubItems.Add($rule.SenderDomain)
        $item.SubItems.Add($rule.SenderAddress)
        $item.SubItems.Add($rule.RecipientDomain)
        $item.SubItems.Add($rule.RecipientAddress)
        $item.SubItems.Add($rule.AddressSpace)
        $item.SubItems.Add($rule.SendAsAlias)
        $item.Tag = $rule
        if (-not $rule.Enabled) {
            $item.ForeColor = [System.Drawing.Color]::Gray
        }
        $listRules.Items.Add($item)
    }
}

# Rule editor panel
$panelRule = New-Object System.Windows.Forms.GroupBox
$panelRule.Text = "Rule Editor (Wildcards: * = any chars, ? = single char)"
$panelRule.Location = New-Object System.Drawing.Point(10, 300)
$panelRule.Size = New-Object System.Drawing.Size(880, 300)

# Row 1: Name, Enabled
$lblName = New-Object System.Windows.Forms.Label
$lblName.Text = "Rule Name:"
$lblName.Location = New-Object System.Drawing.Point(10, 25)
$lblName.Size = New-Object System.Drawing.Size(70, 20)

$txtName = New-Object System.Windows.Forms.TextBox
$txtName.Location = New-Object System.Drawing.Point(85, 22)
$txtName.Size = New-Object System.Drawing.Size(180, 23)

$chkEnabled = New-Object System.Windows.Forms.CheckBox
$chkEnabled.Text = "Enabled"
$chkEnabled.Location = New-Object System.Drawing.Point(280, 22)
$chkEnabled.Checked = $true

# Row 2: Sender
$lblSenderDomain = New-Object System.Windows.Forms.Label
$lblSenderDomain.Text = "Sender Domain:"
$lblSenderDomain.Location = New-Object System.Drawing.Point(10, 55)
$lblSenderDomain.Size = New-Object System.Drawing.Size(95, 20)

$txtSenderDomain = New-Object System.Windows.Forms.TextBox
$txtSenderDomain.Location = New-Object System.Drawing.Point(105, 52)
$txtSenderDomain.Size = New-Object System.Drawing.Size(160, 23)

$lblSenderAddress = New-Object System.Windows.Forms.Label
$lblSenderAddress.Text = "OR Sender Address:"
$lblSenderAddress.Location = New-Object System.Drawing.Point(280, 55)
$lblSenderAddress.Size = New-Object System.Drawing.Size(115, 20)

$txtSenderAddress = New-Object System.Windows.Forms.TextBox
$txtSenderAddress.Location = New-Object System.Drawing.Point(395, 52)
$txtSenderAddress.Size = New-Object System.Drawing.Size(180, 23)

$lblSenderHelp = New-Object System.Windows.Forms.Label
$lblSenderHelp.Text = "e.g. @domain.com or *@*.company.com"
$lblSenderHelp.Location = New-Object System.Drawing.Point(585, 55)
$lblSenderHelp.Size = New-Object System.Drawing.Size(250, 20)
$lblSenderHelp.ForeColor = [System.Drawing.Color]::Gray

# Row 3: Recipient
$lblRecipientDomain = New-Object System.Windows.Forms.Label
$lblRecipientDomain.Text = "Recipient Domain:"
$lblRecipientDomain.Location = New-Object System.Drawing.Point(10, 85)
$lblRecipientDomain.Size = New-Object System.Drawing.Size(105, 20)

$txtRecipientDomain = New-Object System.Windows.Forms.TextBox
$txtRecipientDomain.Location = New-Object System.Drawing.Point(115, 82)
$txtRecipientDomain.Size = New-Object System.Drawing.Size(150, 23)

$lblRecipientAddress = New-Object System.Windows.Forms.Label
$lblRecipientAddress.Text = "OR Recipient Addr:"
$lblRecipientAddress.Location = New-Object System.Drawing.Point(280, 85)
$lblRecipientAddress.Size = New-Object System.Drawing.Size(120, 20)

$txtRecipientAddress = New-Object System.Windows.Forms.TextBox
$txtRecipientAddress.Location = New-Object System.Drawing.Point(400, 82)
$txtRecipientAddress.Size = New-Object System.Drawing.Size(175, 23)

$lblRecipientHelp = New-Object System.Windows.Forms.Label
$lblRecipientHelp.Text = "Empty=all, wildcards: * ? (e.g. *.com)"
$lblRecipientHelp.Location = New-Object System.Drawing.Point(585, 85)
$lblRecipientHelp.Size = New-Object System.Drawing.Size(250, 20)
$lblRecipientHelp.ForeColor = [System.Drawing.Color]::Gray

# Row 4: Connector selection
$lblConnector = New-Object System.Windows.Forms.Label
$lblConnector.Text = "Send Connector:"
$lblConnector.Location = New-Object System.Drawing.Point(10, 120)
$lblConnector.Size = New-Object System.Drawing.Size(95, 20)

$cboConnector = New-Object System.Windows.Forms.ComboBox
$cboConnector.Location = New-Object System.Drawing.Point(105, 117)
$cboConnector.Size = New-Object System.Drawing.Size(300, 23)
$cboConnector.DropDownStyle = "DropDownList"
$cboConnector.Items.Add("-- Create New Connector --")
$cboConnector.SelectedIndex = 0

foreach ($conn in $connectors) {
    $cboConnector.Items.Add("$($conn.Name) [$($conn.AddressSpace)] -> $($conn.SmartHosts)")
}

$lblAddressSpace = New-Object System.Windows.Forms.Label
$lblAddressSpace.Text = "Address Space:"
$lblAddressSpace.Location = New-Object System.Drawing.Point(420, 120)
$lblAddressSpace.Size = New-Object System.Drawing.Size(85, 20)

$txtAddressSpace = New-Object System.Windows.Forms.TextBox
$txtAddressSpace.Location = New-Object System.Drawing.Point(505, 117)
$txtAddressSpace.Size = New-Object System.Drawing.Size(180, 23)

# Row 5: New connector creation
$lblSmartHost = New-Object System.Windows.Forms.Label
$lblSmartHost.Text = "New Smart Host:"
$lblSmartHost.Location = New-Object System.Drawing.Point(10, 150)
$lblSmartHost.Size = New-Object System.Drawing.Size(105, 20)

$txtSmartHost = New-Object System.Windows.Forms.TextBox
$txtSmartHost.Location = New-Object System.Drawing.Point(115, 147)
$txtSmartHost.Size = New-Object System.Drawing.Size(120, 23)

$lblPort = New-Object System.Windows.Forms.Label
$lblPort.Text = "Port:"
$lblPort.Location = New-Object System.Drawing.Point(240, 150)
$lblPort.Size = New-Object System.Drawing.Size(35, 20)

$txtPort = New-Object System.Windows.Forms.TextBox
$txtPort.Location = New-Object System.Drawing.Point(275, 147)
$txtPort.Size = New-Object System.Drawing.Size(45, 23)
$txtPort.Text = "25"

$btnCreateConnector = New-Object System.Windows.Forms.Button
$btnCreateConnector.Text = "Create Connector"
$btnCreateConnector.Location = New-Object System.Drawing.Point(330, 146)
$btnCreateConnector.Size = New-Object System.Drawing.Size(120, 25)

$lblNewConnHelp = New-Object System.Windows.Forms.Label
$lblNewConnHelp.Text = "Enter IP and port, click Create"
$lblNewConnHelp.Location = New-Object System.Drawing.Point(460, 150)
$lblNewConnHelp.Size = New-Object System.Drawing.Size(200, 20)
$lblNewConnHelp.ForeColor = [System.Drawing.Color]::Gray

# Row 6: Send As Alias
$lblSendAsAlias = New-Object System.Windows.Forms.Label
$lblSendAsAlias.Text = "Send As Alias:"
$lblSendAsAlias.Location = New-Object System.Drawing.Point(10, 185)
$lblSendAsAlias.Size = New-Object System.Drawing.Size(95, 20)

$txtSendAsAlias = New-Object System.Windows.Forms.TextBox
$txtSendAsAlias.Location = New-Object System.Drawing.Point(105, 182)
$txtSendAsAlias.Size = New-Object System.Drawing.Size(200, 23)

$lblAliasHelp = New-Object System.Windows.Forms.Label
$lblAliasHelp.Text = "@domain.com (uses sender's local part) or full address"
$lblAliasHelp.Location = New-Object System.Drawing.Point(315, 185)
$lblAliasHelp.Size = New-Object System.Drawing.Size(350, 20)
$lblAliasHelp.ForeColor = [System.Drawing.Color]::Gray

# Buttons
$btnAddRule = New-Object System.Windows.Forms.Button
$btnAddRule.Text = "Add Rule"
$btnAddRule.Location = New-Object System.Drawing.Point(10, 225)
$btnAddRule.Size = New-Object System.Drawing.Size(100, 30)

$btnUpdateRule = New-Object System.Windows.Forms.Button
$btnUpdateRule.Text = "Update Rule"
$btnUpdateRule.Location = New-Object System.Drawing.Point(120, 225)
$btnUpdateRule.Size = New-Object System.Drawing.Size(100, 30)

$btnDeleteRule = New-Object System.Windows.Forms.Button
$btnDeleteRule.Text = "Delete Rule"
$btnDeleteRule.Location = New-Object System.Drawing.Point(230, 225)
$btnDeleteRule.Size = New-Object System.Drawing.Size(100, 30)

$btnMoveUp = New-Object System.Windows.Forms.Button
$btnMoveUp.Text = "Move Up"
$btnMoveUp.Location = New-Object System.Drawing.Point(350, 225)
$btnMoveUp.Size = New-Object System.Drawing.Size(80, 30)

$btnMoveDown = New-Object System.Windows.Forms.Button
$btnMoveDown.Text = "Move Down"
$btnMoveDown.Location = New-Object System.Drawing.Point(440, 225)
$btnMoveDown.Size = New-Object System.Drawing.Size(90, 30)

$btnClearForm = New-Object System.Windows.Forms.Button
$btnClearForm.Text = "Clear Form"
$btnClearForm.Location = New-Object System.Drawing.Point(550, 225)
$btnClearForm.Size = New-Object System.Drawing.Size(90, 30)

$btnDuplicate = New-Object System.Windows.Forms.Button
$btnDuplicate.Text = "Duplicate"
$btnDuplicate.Location = New-Object System.Drawing.Point(650, 225)
$btnDuplicate.Size = New-Object System.Drawing.Size(90, 30)

# Order note
$lblOrderNote = New-Object System.Windows.Forms.Label
$lblOrderNote.Text = "Rules are evaluated in order from top to bottom. First matching rule wins."
$lblOrderNote.Location = New-Object System.Drawing.Point(10, 265)
$lblOrderNote.Size = New-Object System.Drawing.Size(500, 20)
$lblOrderNote.ForeColor = [System.Drawing.Color]::DarkBlue

# Add controls to rule panel
$panelRule.Controls.AddRange(@(
    $lblName, $txtName, $chkEnabled,
    $lblSenderDomain, $txtSenderDomain, $lblSenderAddress, $txtSenderAddress, $lblSenderHelp,
    $lblRecipientDomain, $txtRecipientDomain, $lblRecipientAddress, $txtRecipientAddress, $lblRecipientHelp,
    $lblConnector, $cboConnector, $lblAddressSpace, $txtAddressSpace,
    $lblSmartHost, $txtSmartHost, $lblPort, $txtPort, $btnCreateConnector, $lblNewConnHelp,
    $lblSendAsAlias, $txtSendAsAlias, $lblAliasHelp,
    $btnAddRule, $btnUpdateRule, $btnDeleteRule, $btnMoveUp, $btnMoveDown, $btnClearForm, $btnDuplicate,
    $lblOrderNote
))

$tabRules.Controls.AddRange(@($listRules, $panelRule))

# ============= VALIDATION TAB =============
$tabValidation = New-Object System.Windows.Forms.TabPage
$tabValidation.Text = "Test Rules"
$tabValidation.Padding = New-Object System.Windows.Forms.Padding(10)

$lblTestInfo = New-Object System.Windows.Forms.Label
$lblTestInfo.Text = "Test how routing rules will process an email:"
$lblTestInfo.Location = New-Object System.Drawing.Point(10, 10)
$lblTestInfo.Size = New-Object System.Drawing.Size(400, 20)

$lblTestSender = New-Object System.Windows.Forms.Label
$lblTestSender.Text = "Sender Address:"
$lblTestSender.Location = New-Object System.Drawing.Point(10, 45)
$lblTestSender.Size = New-Object System.Drawing.Size(100, 20)

$txtTestSender = New-Object System.Windows.Forms.TextBox
$txtTestSender.Location = New-Object System.Drawing.Point(115, 42)
$txtTestSender.Size = New-Object System.Drawing.Size(300, 23)

$lblTestRecipient = New-Object System.Windows.Forms.Label
$lblTestRecipient.Text = "Recipient Address:"
$lblTestRecipient.Location = New-Object System.Drawing.Point(10, 75)
$lblTestRecipient.Size = New-Object System.Drawing.Size(100, 20)

$txtTestRecipient = New-Object System.Windows.Forms.TextBox
$txtTestRecipient.Location = New-Object System.Drawing.Point(115, 72)
$txtTestRecipient.Size = New-Object System.Drawing.Size(300, 23)

$btnTestRules = New-Object System.Windows.Forms.Button
$btnTestRules.Text = "Test Rules"
$btnTestRules.Location = New-Object System.Drawing.Point(430, 42)
$btnTestRules.Size = New-Object System.Drawing.Size(100, 50)

$txtTestResult = New-Object System.Windows.Forms.TextBox
$txtTestResult.Location = New-Object System.Drawing.Point(10, 110)
$txtTestResult.Size = New-Object System.Drawing.Size(880, 480)
$txtTestResult.Multiline = $true
$txtTestResult.ScrollBars = "Both"
$txtTestResult.Font = New-Object System.Drawing.Font("Consolas", 10)
$txtTestResult.ReadOnly = $true

$tabValidation.Controls.AddRange(@($lblTestInfo, $lblTestSender, $txtTestSender, $lblTestRecipient, $txtTestRecipient, $btnTestRules, $txtTestResult))

# ============= SETTINGS TAB =============
$tabSettings = New-Object System.Windows.Forms.TabPage
$tabSettings.Text = "Settings"
$tabSettings.Padding = New-Object System.Windows.Forms.Padding(20)

$chkEnableSendAsAlias = New-Object System.Windows.Forms.CheckBox
$chkEnableSendAsAlias.Text = "Enable Send-As-Alias Feature"
$chkEnableSendAsAlias.Location = New-Object System.Drawing.Point(20, 20)
$chkEnableSendAsAlias.Size = New-Object System.Drawing.Size(300, 25)
$chkEnableSendAsAlias.Checked = $config.Settings.EnableSendAsAlias

$lblSendAsAliasHelp = New-Object System.Windows.Forms.Label
$lblSendAsAliasHelp.Text = "Preserves or sets sender alias address in From header"
$lblSendAsAliasHelp.Location = New-Object System.Drawing.Point(40, 45)
$lblSendAsAliasHelp.Size = New-Object System.Drawing.Size(400, 20)
$lblSendAsAliasHelp.ForeColor = [System.Drawing.Color]::Gray

$chkEnableSenderRouting = New-Object System.Windows.Forms.CheckBox
$chkEnableSenderRouting.Text = "Enable Sender-Based Routing"
$chkEnableSenderRouting.Location = New-Object System.Drawing.Point(20, 80)
$chkEnableSenderRouting.Size = New-Object System.Drawing.Size(300, 25)
$chkEnableSenderRouting.Checked = $config.Settings.EnableSenderBasedRouting

$lblSenderRoutingHelp = New-Object System.Windows.Forms.Label
$lblSenderRoutingHelp.Text = "Routes emails through specific connectors based on sender/recipient rules"
$lblSenderRoutingHelp.Location = New-Object System.Drawing.Point(40, 105)
$lblSenderRoutingHelp.Size = New-Object System.Drawing.Size(500, 20)
$lblSenderRoutingHelp.ForeColor = [System.Drawing.Color]::Gray

$chkBypassLocal = New-Object System.Windows.Forms.CheckBox
$chkBypassLocal.Text = "Bypass Local Recipients"
$chkBypassLocal.Location = New-Object System.Drawing.Point(20, 140)
$chkBypassLocal.Size = New-Object System.Drawing.Size(300, 25)
$chkBypassLocal.Checked = $config.Settings.BypassLocalRecipients

$lblBypassLocalHelp = New-Object System.Windows.Forms.Label
$lblBypassLocalHelp.Text = "Skip routing override for recipients in local domains (deliver directly)"
$lblBypassLocalHelp.Location = New-Object System.Drawing.Point(40, 165)
$lblBypassLocalHelp.Size = New-Object System.Drawing.Size(500, 20)
$lblBypassLocalHelp.ForeColor = [System.Drawing.Color]::Gray

$chkRouteByHeader = New-Object System.Windows.Forms.CheckBox
$chkRouteByHeader.Text = "Route by From Header (P2/Alias)"
$chkRouteByHeader.Location = New-Object System.Drawing.Point(20, 200)
$chkRouteByHeader.Size = New-Object System.Drawing.Size(300, 25)
$chkRouteByHeader.Checked = $config.Settings.RouteByHeaderFrom

$lblRouteByHeaderHelp = New-Object System.Windows.Forms.Label
$lblRouteByHeaderHelp.Text = "Match rules against From header instead of envelope sender (MAIL FROM)"
$lblRouteByHeaderHelp.Location = New-Object System.Drawing.Point(40, 225)
$lblRouteByHeaderHelp.Size = New-Object System.Drawing.Size(500, 20)
$lblRouteByHeaderHelp.ForeColor = [System.Drawing.Color]::Gray

# Proxy validation settings
$grpProxyValidation = New-Object System.Windows.Forms.GroupBox
$grpProxyValidation.Text = "Alias Validation"
$grpProxyValidation.Location = New-Object System.Drawing.Point(20, 265)
$grpProxyValidation.Size = New-Object System.Drawing.Size(600, 130)

$chkValidateProxy = New-Object System.Windows.Forms.CheckBox
$chkValidateProxy.Text = "Validate Sender Has Alias in Target Domain"
$chkValidateProxy.Location = New-Object System.Drawing.Point(15, 25)
$chkValidateProxy.Size = New-Object System.Drawing.Size(350, 25)
$chkValidateProxy.Checked = $config.Settings.ValidateProxyAddresses

$lblValidateProxyHelp = New-Object System.Windows.Forms.Label
$lblValidateProxyHelp.Text = "Check if user's From header already shows an address in the alias domain"
$lblValidateProxyHelp.Location = New-Object System.Drawing.Point(35, 50)
$lblValidateProxyHelp.Size = New-Object System.Drawing.Size(550, 20)
$lblValidateProxyHelp.ForeColor = [System.Drawing.Color]::Gray

$chkBlockNoAlias = New-Object System.Windows.Forms.CheckBox
$chkBlockNoAlias.Text = "Block External Email if No Alias (Requires validation enabled)"
$chkBlockNoAlias.Location = New-Object System.Drawing.Point(15, 75)
$chkBlockNoAlias.Size = New-Object System.Drawing.Size(400, 25)
$chkBlockNoAlias.Checked = $config.Settings.BlockIfNoAlias

$lblBlockNoAliasHelp = New-Object System.Windows.Forms.Label
$lblBlockNoAliasHelp.Text = "If sender doesn't have proxy address in alias domain, don't apply alias or routing"
$lblBlockNoAliasHelp.Location = New-Object System.Drawing.Point(35, 100)
$lblBlockNoAliasHelp.Size = New-Object System.Drawing.Size(550, 20)
$lblBlockNoAliasHelp.ForeColor = [System.Drawing.Color]::Gray

$grpProxyValidation.Controls.AddRange(@($chkValidateProxy, $lblValidateProxyHelp, $chkBlockNoAlias, $lblBlockNoAliasHelp))

$tabSettings.Controls.AddRange(@(
    $chkEnableSendAsAlias, $lblSendAsAliasHelp,
    $chkEnableSenderRouting, $lblSenderRoutingHelp,
    $chkBypassLocal, $lblBypassLocalHelp,
    $chkRouteByHeader, $lblRouteByHeaderHelp,
    $grpProxyValidation
))

# ============= LOCAL DOMAINS TAB =============
$tabDomains = New-Object System.Windows.Forms.TabPage
$tabDomains.Text = "Local Domains"
$tabDomains.Padding = New-Object System.Windows.Forms.Padding(10)

$lblDomainsInfo = New-Object System.Windows.Forms.Label
$lblDomainsInfo.Text = "Recipients in these domains will be delivered directly (bypass routing rules):"
$lblDomainsInfo.Location = New-Object System.Drawing.Point(10, 10)
$lblDomainsInfo.Size = New-Object System.Drawing.Size(500, 20)

$listDomains = New-Object System.Windows.Forms.ListBox
$listDomains.Location = New-Object System.Drawing.Point(10, 35)
$listDomains.Size = New-Object System.Drawing.Size(300, 400)

function Refresh-DomainsList {
    $listDomains.Items.Clear()
    foreach ($domain in $config.LocalDomains) {
        $listDomains.Items.Add($domain)
    }
}

$txtNewDomain = New-Object System.Windows.Forms.TextBox
$txtNewDomain.Location = New-Object System.Drawing.Point(10, 445)
$txtNewDomain.Size = New-Object System.Drawing.Size(200, 23)

$btnAddDomain = New-Object System.Windows.Forms.Button
$btnAddDomain.Text = "Add Domain"
$btnAddDomain.Location = New-Object System.Drawing.Point(220, 443)
$btnAddDomain.Size = New-Object System.Drawing.Size(90, 27)

$btnRemoveDomain = New-Object System.Windows.Forms.Button
$btnRemoveDomain.Text = "Remove"
$btnRemoveDomain.Location = New-Object System.Drawing.Point(320, 35)
$btnRemoveDomain.Size = New-Object System.Drawing.Size(100, 27)

$btnAutoDetect = New-Object System.Windows.Forms.Button
$btnAutoDetect.Text = "Auto-Detect from Exchange"
$btnAutoDetect.Location = New-Object System.Drawing.Point(320, 70)
$btnAutoDetect.Size = New-Object System.Drawing.Size(180, 27)

$tabDomains.Controls.AddRange(@($lblDomainsInfo, $listDomains, $txtNewDomain, $btnAddDomain, $btnRemoveDomain, $btnAutoDetect))

# ============= HELP TAB =============
$tabHelp = New-Object System.Windows.Forms.TabPage
$tabHelp.Text = "Help"
$tabHelp.Padding = New-Object System.Windows.Forms.Padding(10)

$txtHelp = New-Object System.Windows.Forms.TextBox
$txtHelp.Location = New-Object System.Drawing.Point(10, 10)
$txtHelp.Size = New-Object System.Drawing.Size(880, 590)
$txtHelp.Multiline = $true
$txtHelp.ScrollBars = "Both"
$txtHelp.WordWrap = $false
$txtHelp.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtHelp.ReadOnly = $true
$txtHelp.BackColor = [System.Drawing.Color]::White

$helpText = @"
================================================================================
             ADVANCED SENDER BASED ROUTING AGENT - HELP & DOCUMENTATION
================================================================================

OVERVIEW
--------
This transport agent for Microsoft Exchange 2019 provides advanced features:

1. SENDER-BASED ROUTING: Route outbound emails through specific Send Connectors
   based on sender and/or recipient addresses.

2. SEND-AS-ALIAS: Change the From header and Return-Path to use a different
   domain/address (alias) instead of the sender's primary SMTP address.

3. ADVANCED RULES: Support for combined sender AND recipient conditions with
   wildcard matching (* and ? patterns).

4. PER-RECIPIENT ROUTING: Different routing decisions for different recipients
   in the same message.


================================================================================
                              ROUTING RULES TAB
================================================================================

RULE FIELDS
-----------

  #                   Rule number (evaluation order, 1 = first)
  Enabled             [X] = active, [ ] = disabled (skipped during evaluation)
  Rule Name           Optional name for identification

  SENDER CONDITIONS (at least one required):
  ------------------------------------------
  Sender Domain       Match emails FROM this domain
                      Examples: @company.com, @sales.company.com, *.company.com

  Sender Address      Match emails FROM this exact address (or pattern)
                      Examples: user@company.com, admin*@company.com

  RECIPIENT CONDITIONS (optional - empty = match all):
  ----------------------------------------------------
  Recipient Domain    Match emails TO this domain
                      Examples: @partner.com, *.external.com

  Recipient Address   Match emails TO this exact address (or pattern)
                      Examples: orders@partner.com, *@gmail.com

  ACTIONS:
  --------
  Send Connector      Select existing connector or create new one
  Address Space       The connector's address space (auto-filled when selecting)
                      Example: route-10-10-10-10.local

  Send As Alias       Change the From header to this alias
                      @domain.com      -> user1@domain.com (uses sender's local part)
                      user@domain.com  -> user@domain.com (fixed address)


WILDCARDS
---------
All sender/recipient fields support wildcards:

  *     Matches any characters (zero or more)
  ?     Matches any single character

Examples:
  *                        Matches everything
  @*.company.com           Matches @sales.company.com, @hr.company.com
  admin*@domain.com        Matches admin@domain.com, admin1@domain.com
  user?@domain.com         Matches user1@domain.com, userA@domain.com
  *@gmail.com              Matches any Gmail address


RULE EVALUATION ORDER
---------------------
- Rules are evaluated from TOP to BOTTOM (rule #1 first)
- FIRST matching rule wins - no further rules are checked
- Use Move Up/Move Down buttons to change order
- More specific rules should be placed BEFORE general rules

Example order:
  1. user1@company.com -> specific user rule
  2. @sales.company.com -> department rule
  3. @company.com -> catch-all company rule


================================================================================
                              TEST RULES TAB
================================================================================

Use this tab to test how rules will process an email:

1. Enter sender address (the From address)
2. Enter recipient address (the To address)
3. Click "Test Rules"

The output shows:
- Each rule evaluated and whether it matched
- Which rule was selected (first match)
- What actions will be applied (routing, alias change)
- Warnings about local domain bypass


================================================================================
                              SETTINGS TAB
================================================================================

FEATURE TOGGLES
---------------

Enable Send-As-Alias
    Turn on/off the alias rewriting feature

Enable Sender-Based Routing
    Turn on/off the routing override feature

Bypass Local Recipients
    If enabled, recipients in Local Domains are delivered directly
    (not routed through rules). Prevents external relay for internal mail.

Route by From Header (P2)
    If enabled, rules match against From header (alias selected by user)
    If disabled, rules match against envelope sender (MAIL FROM / P1)
    Enable this if users select aliases in Outlook/OWA


ALIAS VALIDATION
----------------

Validate Sender Has Alias in Target Domain
    Checks if user's current From header is already in the alias domain
    If user selected @ya.ru alias in Outlook, use that exact address
    Prevents constructing aliases for users without proper proxy addresses

Block External if No Alias
    If user doesn't have alias in target domain, don't apply alias/routing
    Email will go through default Exchange routing instead


================================================================================
                            LOCAL DOMAINS TAB
================================================================================

Recipients in local domains are delivered directly by Exchange without
routing override (when "Bypass Local Recipients" is enabled).

- Add your internal/accepted domains here
- Use "Auto-Detect from Exchange" to import accepted domains
- Prevents external relay for internal recipients


================================================================================
                           SEND CONNECTOR SETUP
================================================================================

The agent routes emails by overriding the recipient's routing to a specific
Send Connector's ADDRESS SPACE (not directly to an IP).

TO CREATE A NEW ROUTE:
1. Enter Smart Host IP in "New Smart Host" field (e.g., 10.10.10.10)
2. Click "Create Connector"
3. This creates connector "SRA-Route-10-10-10-10" with address space
   "route-10-10-10-10.local"
4. Select the connector from dropdown
5. Address Space field is auto-filled

MANUAL CONNECTOR CREATION (PowerShell):
  New-SendConnector -Name "SRA-Route-10-10-10-10" ``
      -AddressSpaces "SMTP:route-10-10-10-10.local;1" ``
      -SmartHosts "10.10.10.10" ``
      -Usage Custom -DNSRoutingEnabled `$false


================================================================================
                              TROUBLESHOOTING
================================================================================

AGENT NOT WORKING?
------------------
1. Check if agent is enabled:
   Get-TransportAgent "Advanced Sender Based Routing Agent"

2. Check Event Viewer for logs:
   Event Viewer -> Windows Logs -> Application
   Filter by Source: MSExchangeTransport
   Look for "AdvancedSenderRouting" in message

3. Restart transport service after config changes:
   Restart-Service MSExchangeTransport

4. Verify config file location:
   Config must be next to the agent DLL in:
   C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\agents\AdvancedSenderRouting\

5. Reinstall if needed:
   .\install.ps1 -KeepConfig


FROM HEADER NOT CHANGING?
-------------------------
- Check sendAsAlias format: must be @domain.com or user@domain.com
- "ya.ru" is WRONG, "@ya.ru" is CORRECT
- Check if validateProxyAddresses is blocking (user needs alias in that domain)
- Check Event Viewer for "Send-As-Alias" log entries


ROUTING NOT WORKING?
--------------------
- Verify Send Connector exists and is enabled
- Check addressSpace matches connector's address space exactly
- Check if recipient is in Local Domains (bypassed)
- Check Event Viewer for "Sender-Based Routing" log entries


================================================================================
                                 EXAMPLES
================================================================================

EXAMPLE 1: Route sales department through specific relay
----------------------------------------------------------
Sender Domain:    @sales.company.com
Address Space:    route-sales-relay.local
Send As Alias:    (empty - keep original From)

EXAMPLE 2: Change From domain for external emails
--------------------------------------------------
Sender Domain:    @internal.company.com
Recipient Domain: (empty - all external)
Send As Alias:    @company.com

EXAMPLE 3: Route emails to partner through dedicated connection
---------------------------------------------------------------
Sender Domain:    *
Recipient Domain: @partner.com
Address Space:    route-partner-vpn.local

EXAMPLE 4: Specific user to specific recipient
----------------------------------------------
Sender Address:   ceo@company.com
Recipient Address: vip@important-client.com
Address Space:    route-secure.local
Send As Alias:    @executive.company.com


================================================================================
                                  SUPPORT
================================================================================

Project: Exchange Transport Agent - Advanced Sender Based Routing Agent
For issues: Check Event Viewer logs first, then review configuration

Config file format: XML
Config location: Next to agent DLL or specify path when launching GUI

================================================================================
"@

$txtHelp.Text = $helpText -replace "`n", "`r`n"

$tabHelp.Controls.Add($txtHelp)

# Add tabs
$tabControl.TabPages.AddRange(@($tabRules, $tabValidation, $tabSettings, $tabDomains, $tabHelp))

# Bottom buttons
$lblConfigPath = New-Object System.Windows.Forms.Label
$lblConfigPath.Text = "Config: $configFile"
$lblConfigPath.Location = New-Object System.Drawing.Point(10, 670)
$lblConfigPath.Size = New-Object System.Drawing.Size(600, 20)
$lblConfigPath.ForeColor = [System.Drawing.Color]::Gray

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = "Save Configuration"
$btnSave.Location = New-Object System.Drawing.Point(780, 665)
$btnSave.Size = New-Object System.Drawing.Size(130, 35)

$btnReload = New-Object System.Windows.Forms.Button
$btnReload.Text = "Reload"
$btnReload.Location = New-Object System.Drawing.Point(690, 665)
$btnReload.Size = New-Object System.Drawing.Size(80, 35)

$form.Controls.AddRange(@($tabControl, $lblConfigPath, $btnSave, $btnReload))

# ============= EVENT HANDLERS =============

# Connector selection changed
$cboConnector.Add_SelectedIndexChanged({
    if ($cboConnector.SelectedIndex -gt 0) {
        $idx = $cboConnector.SelectedIndex - 1
        if ($idx -lt $connectors.Count) {
            $txtAddressSpace.Text = $connectors[$idx].AddressSpace
        }
    }
})

# Create connector
$btnCreateConnector.Add_Click({
    $smartHost = $txtSmartHost.Text.Trim()
    if (-not $smartHost) {
        [System.Windows.Forms.MessageBox]::Show("Enter Smart Host IP address", "Validation", "OK", "Warning")
        return
    }

    # Parse and validate port
    $port = 25
    if ($txtPort.Text.Trim()) {
        if (-not [int]::TryParse($txtPort.Text.Trim(), [ref]$port)) {
            [System.Windows.Forms.MessageBox]::Show("Port must be a number (1-65535)", "Validation", "OK", "Warning")
            return
        }
        if ($port -lt 1 -or $port -gt 65535) {
            [System.Windows.Forms.MessageBox]::Show("Port must be between 1 and 65535", "Validation", "OK", "Warning")
            return
        }
    }

    $addressSpace = "route-$($smartHost -replace '\.', '-').local"
    $result = Create-SendConnector -SmartHost $smartHost -AddressSpace $addressSpace -Port $port

    if ($result.Success) {
        [System.Windows.Forms.MessageBox]::Show($result.Message, "Success", "OK", "Information")

        # Refresh connectors list
        $script:connectors = Get-SRAConnectors
        $cboConnector.Items.Clear()
        $cboConnector.Items.Add("-- Create New Connector --")
        foreach ($conn in $connectors) {
            $cboConnector.Items.Add("$($conn.Name) [$($conn.AddressSpace)] -> $($conn.SmartHosts)")
        }

        # Select the new connector
        for ($i = 0; $i -lt $connectors.Count; $i++) {
            if ($connectors[$i].AddressSpace -eq $addressSpace) {
                $cboConnector.SelectedIndex = $i + 1
                break
            }
        }

        $txtAddressSpace.Text = $addressSpace
        $txtSmartHost.Text = ""
        $txtPort.Text = "25"
    } else {
        [System.Windows.Forms.MessageBox]::Show($result.Message, "Error", "OK", "Error")
    }
})

# List selection changed
$listRules.Add_SelectedIndexChanged({
    if ($listRules.SelectedItems.Count -gt 0) {
        $rule = $listRules.SelectedItems[0].Tag
        $txtName.Text = $rule.Name
        $chkEnabled.Checked = $rule.Enabled
        $txtSenderDomain.Text = $rule.SenderDomain
        $txtSenderAddress.Text = $rule.SenderAddress
        $txtRecipientDomain.Text = $rule.RecipientDomain
        $txtRecipientAddress.Text = $rule.RecipientAddress
        $txtAddressSpace.Text = $rule.AddressSpace
        $txtSendAsAlias.Text = $rule.SendAsAlias
        $txtSmartHost.Text = ""

        # Try to select connector
        $cboConnector.SelectedIndex = 0
        for ($i = 0; $i -lt $connectors.Count; $i++) {
            if ($connectors[$i].AddressSpace -eq $rule.AddressSpace) {
                $cboConnector.SelectedIndex = $i + 1
                break
            }
        }
    }
})

# Clear form function
function Clear-RuleForm {
    $txtName.Text = ""
    $txtSenderDomain.Text = ""
    $txtSenderAddress.Text = ""
    $txtRecipientDomain.Text = ""
    $txtRecipientAddress.Text = ""
    $txtAddressSpace.Text = ""
    $txtSendAsAlias.Text = ""
    $txtSmartHost.Text = ""
    $chkEnabled.Checked = $true
    $cboConnector.SelectedIndex = 0
    $listRules.SelectedItems.Clear()
}

# Clear form button
$btnClearForm.Add_Click({
    Clear-RuleForm
})

# Validate rule fields
function Validate-Rule {
    $errors = @()
    $warnings = @()

    # Check sender condition (required)
    if (-not $txtSenderDomain.Text.Trim() -and -not $txtSenderAddress.Text.Trim()) {
        $errors += "Sender Domain or Sender Address is required"
    }

    # Validate sender domain format
    if ($txtSenderDomain.Text.Trim()) {
        $sd = $txtSenderDomain.Text.Trim()
        if ($sd -notmatch '^[@\*]' -and $sd -notmatch '\.') {
            $warnings += "Sender Domain: Consider using '@domain.com' or '*.domain.com' format"
        }
    }

    # Validate sender address format
    if ($txtSenderAddress.Text.Trim()) {
        $sa = $txtSenderAddress.Text.Trim()
        if ($sa -notmatch '@' -and $sa -notmatch '\*') {
            $errors += "Sender Address: Must contain '@' (e.g., user@domain.com or *@domain.com)"
        }
    }

    # Validate recipient domain format
    if ($txtRecipientDomain.Text.Trim()) {
        $rd = $txtRecipientDomain.Text.Trim()
        if ($rd -notmatch '^[@\*\?]' -and $rd -notmatch '[\.\*\?]') {
            $warnings += "Recipient Domain: Consider using '@domain.com' or wildcards (*, ?)`nExamples: @partner.com, *.external.com, partner?.com"
        }
    }

    # Validate recipient address format
    if ($txtRecipientAddress.Text.Trim()) {
        $ra = $txtRecipientAddress.Text.Trim()
        if ($ra -notmatch '@' -and $ra -notmatch '[\*\?]') {
            $errors += "Recipient Address: Must contain '@' or wildcards (*, ?)`nExamples: user@domain.com, *@domain.com, admin*@*.com"
        }
    }

    # Validate Send As Alias format
    if ($txtSendAsAlias.Text.Trim()) {
        $alias = $txtSendAsAlias.Text.Trim()
        if ($alias -notmatch '^@' -and $alias -notmatch '@') {
            $errors += "Send As Alias: Must be '@domain.com' (for dynamic) or 'user@domain.com' (fixed)`n`nExamples:`n  @ya.ru -> user1@ya.ru (uses sender's local part)`n  noreply@ya.ru -> noreply@ya.ru (fixed address)"
        }
        elseif ($alias -match '^@' -and $alias -notmatch '^@[a-zA-Z0-9]') {
            $errors += "Send As Alias: Invalid domain format after @"
        }
    }

    # Validate address space
    if ($txtAddressSpace.Text.Trim()) {
        $as = $txtAddressSpace.Text.Trim()
        if ($as -match '^\d+\.\d+\.\d+\.\d+$') {
            $errors += "Address Space: Cannot be an IP address directly.`n`nUse connector's address space (e.g., route-10-10-10-10.local)`nor create a connector first using 'New Smart Host' field."
        }
    }

    # Check if routing action is specified
    if (-not $txtAddressSpace.Text.Trim() -and -not $txtSendAsAlias.Text.Trim()) {
        $warnings += "No routing action: Rule has no Address Space or Send As Alias.`nThis rule will only match but won't change anything."
    }

    return @{ Errors = $errors; Warnings = $warnings }
}

# Add rule
$btnAddRule.Add_Click({
    $validation = Validate-Rule

    if ($validation.Errors.Count -gt 0) {
        $msg = "Please fix the following errors:`n`n" + ($validation.Errors -join "`n`n")
        [System.Windows.Forms.MessageBox]::Show($msg, "Validation Error", "OK", "Error")
        return
    }

    if ($validation.Warnings.Count -gt 0) {
        $msg = "Warnings:`n`n" + ($validation.Warnings -join "`n`n") + "`n`nDo you want to add the rule anyway?"
        $result = [System.Windows.Forms.MessageBox]::Show($msg, "Validation Warning", "YesNo", "Warning")
        if ($result -ne "Yes") {
            return
        }
    }

    $newRule = @{
        Name = $txtName.Text.Trim()
        Enabled = $chkEnabled.Checked
        SenderDomain = $txtSenderDomain.Text.Trim()
        SenderAddress = $txtSenderAddress.Text.Trim()
        RecipientDomain = $txtRecipientDomain.Text.Trim()
        RecipientAddress = $txtRecipientAddress.Text.Trim()
        AddressSpace = $txtAddressSpace.Text.Trim()
        SendAsAlias = $txtSendAsAlias.Text.Trim()
    }

    $config.Rules += $newRule
    Refresh-RulesList
    Clear-RuleForm
})

# Update rule
$btnUpdateRule.Add_Click({
    if ($listRules.SelectedIndices.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a rule to update", "Info", "OK", "Information")
        return
    }

    $validation = Validate-Rule

    if ($validation.Errors.Count -gt 0) {
        $msg = "Please fix the following errors:`n`n" + ($validation.Errors -join "`n`n")
        [System.Windows.Forms.MessageBox]::Show($msg, "Validation Error", "OK", "Error")
        return
    }

    if ($validation.Warnings.Count -gt 0) {
        $msg = "Warnings:`n`n" + ($validation.Warnings -join "`n`n") + "`n`nDo you want to update the rule anyway?"
        $result = [System.Windows.Forms.MessageBox]::Show($msg, "Validation Warning", "YesNo", "Warning")
        if ($result -ne "Yes") {
            return
        }
    }

    $index = $listRules.SelectedIndices[0]

    $config.Rules[$index] = @{
        Name = $txtName.Text.Trim()
        Enabled = $chkEnabled.Checked
        SenderDomain = $txtSenderDomain.Text.Trim()
        SenderAddress = $txtSenderAddress.Text.Trim()
        RecipientDomain = $txtRecipientDomain.Text.Trim()
        RecipientAddress = $txtRecipientAddress.Text.Trim()
        AddressSpace = $txtAddressSpace.Text.Trim()
        SendAsAlias = $txtSendAsAlias.Text.Trim()
    }

    Refresh-RulesList
    $listRules.Items[$index].Selected = $true
})

# Delete rule
$btnDeleteRule.Add_Click({
    if ($listRules.SelectedIndices.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a rule to delete", "Info", "OK", "Information")
        return
    }

    $result = [System.Windows.Forms.MessageBox]::Show("Delete selected rule?", "Confirm", "YesNo", "Question")
    if ($result -eq "Yes") {
        $index = $listRules.SelectedIndices[0]
        $config.Rules = @($config.Rules | Where-Object { $config.Rules.IndexOf($_) -ne $index })
        Refresh-RulesList
    }
})

# Duplicate rule
$btnDuplicate.Add_Click({
    if ($listRules.SelectedIndices.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a rule to duplicate", "Info", "OK", "Information")
        return
    }

    $original = $config.Rules[$listRules.SelectedIndices[0]]
    $newRule = @{
        Name = $original.Name + " (Copy)"
        Enabled = $original.Enabled
        SenderDomain = $original.SenderDomain
        SenderAddress = $original.SenderAddress
        RecipientDomain = $original.RecipientDomain
        RecipientAddress = $original.RecipientAddress
        AddressSpace = $original.AddressSpace
        SendAsAlias = $original.SendAsAlias
    }

    $config.Rules += $newRule
    Refresh-RulesList
})

# Move up
$btnMoveUp.Add_Click({
    if ($listRules.SelectedIndices.Count -eq 0 -or $listRules.SelectedIndices[0] -eq 0) { return }
    $index = $listRules.SelectedIndices[0]
    $temp = $config.Rules[$index]
    $config.Rules[$index] = $config.Rules[$index - 1]
    $config.Rules[$index - 1] = $temp
    Refresh-RulesList
    $listRules.Items[$index - 1].Selected = $true
})

# Move down
$btnMoveDown.Add_Click({
    if ($listRules.SelectedIndices.Count -eq 0 -or $listRules.SelectedIndices[0] -ge $config.Rules.Count - 1) { return }
    $index = $listRules.SelectedIndices[0]
    $temp = $config.Rules[$index]
    $config.Rules[$index] = $config.Rules[$index + 1]
    $config.Rules[$index + 1] = $temp
    Refresh-RulesList
    $listRules.Items[$index + 1].Selected = $true
})

# Test rules
$btnTestRules.Add_Click({
    $sender = $txtTestSender.Text.Trim()
    $recipient = $txtTestRecipient.Text.Trim()

    if (-not $sender) {
        [System.Windows.Forms.MessageBox]::Show("Enter sender address", "Validation", "OK", "Warning")
        return
    }

    $result = @()
    $result += "=" * 70
    $result += "RULE EVALUATION TEST"
    $result += "=" * 70
    $result += ""
    $result += "Input:"
    $result += "  Sender:    $sender"
    $result += "  Recipient: $(if ($recipient) { $recipient } else { '(none - will match rules without recipient condition)' })"
    $result += ""
    $result += "-" * 70
    $result += "Evaluating rules in order..."
    $result += "-" * 70
    $result += ""

    $matchedRule = $null
    $ruleNum = 0

    foreach ($rule in $config.Rules) {
        $ruleNum++
        $ruleName = if ($rule.Name) { $rule.Name } else { "Rule #$ruleNum" }

        $result += "Rule: $ruleName"

        if (-not $rule.Enabled) {
            $result += "  Status: DISABLED (skipped)"
            $result += ""
            continue
        }

        $senderMatch = Test-SenderMatch -Rule $rule -SenderAddress $sender
        $recipientMatch = Test-RecipientMatch -Rule $rule -RecipientAddress $recipient

        $senderCond = if ($rule.SenderAddress) { "Address='$($rule.SenderAddress)'" } elseif ($rule.SenderDomain) { "Domain='$($rule.SenderDomain)'" } else { "(none)" }
        $recipientCond = if ($rule.RecipientAddress) { "Address='$($rule.RecipientAddress)'" } elseif ($rule.RecipientDomain) { "Domain='$($rule.RecipientDomain)'" } else { "(any recipient)" }

        $result += "  Sender condition:    $senderCond -> $(if ($senderMatch) { 'MATCH' } else { 'NO MATCH' })"
        $result += "  Recipient condition: $recipientCond -> $(if ($recipientMatch) { 'MATCH' } else { 'NO MATCH' })"

        if ($senderMatch -and $recipientMatch) {
            $result += "  Result: ** MATCHED **"
            $matchedRule = $rule
            $matchedRuleName = $ruleName
            break
        } else {
            $result += "  Result: Not matched"
        }
        $result += ""
    }

    $result += ""
    $result += "=" * 70
    $result += "RESULT"
    $result += "=" * 70
    $result += ""

    if ($matchedRule) {
        $result += "Matched Rule: $matchedRuleName"
        $result += ""
        $result += "Actions that will be applied:"

        if ($matchedRule.AddressSpace) {
            $result += "  - Route through connector with address space: $($matchedRule.AddressSpace)"

            # Find connector info
            foreach ($conn in $connectors) {
                if ($conn.AddressSpace -eq $matchedRule.AddressSpace) {
                    $result += "    (Connector: $($conn.Name), SmartHosts: $($conn.SmartHosts))"
                    break
                }
            }
        } else {
            $result += "  - No routing override (use default Exchange routing)"
        }

        if ($matchedRule.SendAsAlias) {
            $alias = $matchedRule.SendAsAlias
            if ($alias.StartsWith("@")) {
                $localPart = $sender.Split("@")[0]
                $aliasAddr = $localPart + $alias
                $result += "  - Change From header to: $aliasAddr"
                $result += "    (constructed from sender's local part + alias domain)"
            } else {
                $result += "  - Change From header to: $alias"
            }
        } else {
            $result += "  - No From header change"
        }

        # Check local domain bypass
        if ($recipient -and $config.Settings.BypassLocalRecipients) {
            $recipDomain = $recipient.Split("@")[-1].ToLower()
            if ($config.LocalDomains -contains $recipDomain) {
                $result += ""
                $result += "NOTE: Recipient is in local domain '$recipDomain'"
                $result += "      Routing override will be SKIPPED (deliver directly)"
            }
        }
    } else {
        $result += "No matching rule found."
        $result += ""
        $result += "Email will:"
        $result += "  - Use default Exchange routing"
        $result += "  - Keep original From header (or Exchange will use primary SMTP)"
    }

    $txtTestResult.Text = $result -join "`r`n"
})

# Add domain
$btnAddDomain.Add_Click({
    $domain = $txtNewDomain.Text.Trim().ToLower().TrimStart('@')
    if ($domain -and $config.LocalDomains -notcontains $domain) {
        $config.LocalDomains += $domain
        Refresh-DomainsList
        $txtNewDomain.Text = ""
    }
})

# Remove domain
$btnRemoveDomain.Add_Click({
    if ($listDomains.SelectedIndex -ge 0) {
        $domain = $listDomains.SelectedItem
        $config.LocalDomains = @($config.LocalDomains | Where-Object { $_ -ne $domain })
        Refresh-DomainsList
    }
})

# Auto-detect domains
$btnAutoDetect.Add_Click({
    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        $added = 0
        foreach ($ad in $acceptedDomains) {
            $domain = $ad.DomainName.ToString().ToLower()
            if ($config.LocalDomains -notcontains $domain) {
                $config.LocalDomains += $domain
                $added++
            }
        }
        Refresh-DomainsList
        [System.Windows.Forms.MessageBox]::Show("Imported $added new domains (total: $($acceptedDomains.Count) accepted domains)", "Success", "OK", "Information")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error: $_`n`nRun from Exchange Management Shell.", "Error", "OK", "Error")
    }
})

# Save
$btnSave.Add_Click({
    $config.Settings.EnableSendAsAlias = $chkEnableSendAsAlias.Checked
    $config.Settings.EnableSenderBasedRouting = $chkEnableSenderRouting.Checked
    $config.Settings.BypassLocalRecipients = $chkBypassLocal.Checked
    $config.Settings.RouteByHeaderFrom = $chkRouteByHeader.Checked
    $config.Settings.ValidateProxyAddresses = $chkValidateProxy.Checked
    $config.Settings.BlockIfNoAlias = $chkBlockNoAlias.Checked

    if (-not $configFile) {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "XML files (*.xml)|*.xml"
        $saveDialog.FileName = "routing-config.xml"
        if ($saveDialog.ShowDialog() -eq "OK") {
            $script:configFile = $saveDialog.FileName
            $lblConfigPath.Text = "Config: $configFile"
        } else {
            return
        }
    }

    if (Save-Configuration -Path $configFile -Config $config) {
        [System.Windows.Forms.MessageBox]::Show("Configuration saved!`n`nRestart MSExchangeTransport service to apply changes.", "Success", "OK", "Information")
    }
})

# Reload
$btnReload.Add_Click({
    if ($configFile -and (Test-Path $configFile)) {
        $script:config = Load-Configuration -Path $configFile
        $script:connectors = Get-SRAConnectors

        $chkEnableSendAsAlias.Checked = $config.Settings.EnableSendAsAlias
        $chkEnableSenderRouting.Checked = $config.Settings.EnableSenderBasedRouting
        $chkBypassLocal.Checked = $config.Settings.BypassLocalRecipients
        $chkRouteByHeader.Checked = $config.Settings.RouteByHeaderFrom
        $chkValidateProxy.Checked = $config.Settings.ValidateProxyAddresses
        $chkBlockNoAlias.Checked = $config.Settings.BlockIfNoAlias

        # Refresh connector dropdown
        $cboConnector.Items.Clear()
        $cboConnector.Items.Add("-- Create New Connector --")
        foreach ($conn in $connectors) {
            $cboConnector.Items.Add("$($conn.Name) [$($conn.AddressSpace)] -> $($conn.SmartHosts)")
        }
        $cboConnector.SelectedIndex = 0

        Refresh-RulesList
        Refresh-DomainsList
        Clear-RuleForm

        [System.Windows.Forms.MessageBox]::Show("Configuration reloaded", "Info", "OK", "Information")
    }
})

# Initialize
Refresh-RulesList
Refresh-DomainsList

[void]$form.ShowDialog()
