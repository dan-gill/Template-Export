# Created by Dan Gill
# Date: August 26, 2021
# Purpose: Use a dialog box to export OVF/OVA template from selected vCenter server.
# Dependencies: Uses Windows credentials to connect to vCenter server.


#######################
# Configure the variables below
#######################
# Specify a directory to download and install the new PowerCLI module to for future offline access
$PSModulePath = $Env:SystemDrive + '\PowerCLIModule\'
# Config import
Get-Content -Path '.\settings.txt' |
ForEach-Object -Begin {
    # Create Hashtable
    $Settings = @{}
} -Process {
    # Retrieve line with '=' and split them
    $k = [regex]::Split($_, '=')
    if (($k[0].CompareTo('') -ne 0) -and ($k[0].StartsWith('[') -ne $True)) {
        # Add the Key, Value into the Hashtable
        $Settings.Add(($k[0] -replace '\s+', ''), ($k[1] -replace '\s+', ''))
    }
}
# Ohio vCenters
$vCentersOH = 'OHOS-VDI-VCS107.opsus.local', 'OHOS-VC01.opsus.local'
# Texas vCenters
$vCentersTX = 'TXOS-VDI-VCS104.opsus.local', 'TXOS-VC01.opsus.local'
# DataDomain password
$password = ConvertTo-SecureString $Settings.Get_Item('passwd') -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($Settings.Get_Item('username'), $password)
# DataDomains
$DataDomainOH = '\\ohos-dd6300-1\z_EUC_From_OH'
$DataDomainTX = '\\txos-dd6300-1\z_EUC_From_TX'
# Match any case of {3 to 4 character mneumonic}-view, {3 to 4 character mneumonic}-view-{1 character},
# {3 to 4 character mneumonic}-ctx-appmx, or {3 to 4 character mneumonic}-ctx-appmx-{1 character}
# Mneumonic must only contain letters from the English alphabet
$regexPattern = '^[a-zA-Z]{3,4}-(?:[Vv][Ii][Ee][Ww]|[Cc][Tt][Xx]-[Aa][Pp][Pp][Mm][Xx])(?:-.){0,1}$'

# Number of backups to retain
$retain = 26

# The script needs to run on an OH or TX Engineer Desktop
if ($env:computername -match '^[Tt][Xx][Oo][Ss]-[Ee][Nn][Gg]\d{2}$') {
    # Local computer is in TX, only list TX vCenters
    $vCenters = $vCentersTX
} elseif ($env:computername -match '^(?:[Oo][Hh][Oo][Ss]|[Oo][Pp][Ss][Uu][Ss])-[Ee][Nn][Gg]-\d{2}$') {
    # Local computer is in OH, only list OH vCenters
    $vCenters = $vCentersOH
} else {
    Write-Error -Message "You must run this script from a VDI in OH or TX.`r`nExamples: OPSUS-ENG-12, OHOS-ENG-35, or TXOS-ENG97" -Category PermissionDenied
    Exit 99              # Exiting script
}
#####################################################################
# Nothing to change below this line, commented throughout to explain
#####################################################################
#######################
# Testing if TLS 1.2 or above is enabled
#######################
if ([Net.ServicePointManager]::SecurityProtocol -notlike '*Tls1[23]*') {
    #######################
    # Set Strong Cryptography - https://docs.microsoft.com/en-us/officeonlineserver/enable-tls-1-1-and-tls-1-2-support-in-office-online-server#enable-strong-cryptography-in-net-framework-45-or-higher
    #######################
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord -Force -Confirm:$false
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord -Force -Confirm:$false
    #######################
    # Disable TLS 1.0 and 1.1
    #######################
    if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client') {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force -Confirm:$false
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -Value '0' -Type DWord -Force -Confirm:$false
    }
    if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server') {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force -Confirm:$false
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value '0' -Type DWord -Force -Confirm:$false
    }
    if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client') {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force -Confirm:$false
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value '0' -Type DWord -Force -Confirm:$false
    }
    if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server') {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force -Confirm:$false
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value '0' -Type DWord -Force -Confirm:$false
    }
    #######################
    # Exit and ask user to re-run the script
    #######################
    Write-Warning 'This system did not have TLS 1.2 or above enabled. Please re-run the script so that the changes to enable TLS 1.2 and above take effect.'
    Exit
}
  
#######################
# Testing if PS Module path exists, if not creating it
#######################
$PSModulePathTest = Test-Path $PSModulePath
if ($PSModulePathTest -eq $False) {
    New-Item -ItemType Directory -Force -Path $PSModulePath
}
#######################
# Checking to see if PowerCLI is installed in Program Files, takes 5-30 seconds
#######################
Write-Progress -Id 1 -Activity 'Checking for PowerCLI' -CurrentOperation 'Checking if PowerCLI is installed in Program Files, wait 5-30 seconds'
$PowerCLIInstalled = Get-WmiObject -Class Win32_Product -Filter "Name='VMware vSphere PowerCLI'"
#######################
# If PowerCLI is installed then removing it, so we can run from the module instead
#######################
if ($PowerCLIInstalled) {
    Write-Progress -Id 2 -ParentId 1 -Activity 'PowerCLI in Program Files' -CurrentOperation 'Uninstalling to allow for new PowerCLI module'
    # Uninstalling PS module
    $PowerCLIUninstall = $PowerCLIInstalled.Uninstall()
    # Checking return value for success
    $PowerCLIUninstallValue = $PowerCLIUninstall.ReturnValue
    if ($PowerCLIUninstallValue -ne 0) {
        Write-Error -Message 'Uninstall Of PowerCLI Failed - Most likely due to not running as administrator' -Category PermissionDenied
    }
    # Finished uninstall
    Write-Progress -Id 2 -ParentId 1 -Activity 'PowerCLI in Program Files' -Completed
}
Write-Progress -Id 1 -Activity 'Checking for PowerCLI' -Completed
#######################
# Checking to see if the NuGet Package Provider is already installed
#######################
$NuGetPackageProviderCheck = Get-PackageProvider -Name 'NuGet' -ListAvailable
#######################
# If NuGet Provider is not installed, nothing found, then running install...
#######################
if (!$NuGetPackageProviderCheck) {
    Write-Progress -Id 1 -Activity 'NuGet Package Provider' -CurrentOperation 'Not Found - Installing'
    # Trusting PS Gallery to remove prompt on install
    Set-PackageSource -Name 'PSGallery' -Trusted
    # Not installed, finding module online
    Find-PackageProvider -Name 'NuGet' -AllVersions
    # Installing module
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
    Write-Progress -Id 1 -Activity 'NuGet Package Provider' -Completed
}
#######################
# Checking to see if the PowerCLI module is already installed
#######################
$PowerCLIModuleCheck = Get-Module -ListAvailable -Name 'VMware.PowerCLI'
#######################
# If PowerCLI module is not installed, nothing found, then running install...
#######################
if (!$PowerCLIModuleCheck) {
    Write-Progress -Id 1 -Activity 'PowerCLI Module' -CurrentOperation 'Not Found - Installing'
    # Trusting PS Gallery to remove prompt on install
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    # Not installed, finding module online
    Find-Module -Name 'VMware.PowerCLI'
    # Installing module
    Install-Module -Name 'VMware.PowerCLI' -Confirm:$false -AllowClobber -Force
    # If running this is a repeat demo/test, you can uninstall the module using the below:
    # Uninstall-Module -Name VMware.PowerCLI -Confirm:$false
    Write-Progress -Id 1 -Activity 'PowerCLI Module' -Completed
}
#######################
# Testing import of PowerCLI module
#######################
Write-Progress -Id 1 -Activity 'PowerCLI Module' -CurrentOperation 'Importing'
$null = Import-Module -Name 'VMware.PowerCLI'
Write-Progress -Id 1 -Activity 'PowerCLI Module' -Completed
Try {
    $null = Get-VICommand
    $PowerCLIImportTest = $True
} Catch {
    $PowerCLIImportTest = $False
} Finally {
    #######################
    # Outputting result
    #######################
    if ($PowerCLIImportTest) {
        Write-Information 'New PowerCLI Module Successfully Installed'
    } else {
        Write-Error -Message "Something went wrong! Maybe you, maybe me. Does this computer have internet access and did you run as administrator?`r`nTry installing PowerCLI in offline mode (Procedure 3): https://tinyurl.com/VMware-PowerCLI"
        Exit 22
    }
}

# Warn if the Certificate is invalid, but continue
Set-PowerCLIConfiguration -InvalidCertificateAction Warn -Scope Session -Confirm:$false

# Needed for dialog boxes
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create a dialog box for connecting to vCenter and listing VMs from vCenter
function myDialogBox {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$Title,
        [Parameter(Mandatory)]
        [string[]]$Prompt,
        [Parameter(Mandatory)]
        [string[]]$Values
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(300, 200)
    $form.StartPosition = 'CenterScreen'

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75, 120)
    $okButton.Size = New-Object System.Drawing.Size(75, 23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150, 120)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 20)
    $label.Size = New-Object System.Drawing.Size(280, 20)
    $label.Text = $Prompt
    $form.Controls.Add($label)

    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10, 40)
    $listBox.Size = New-Object System.Drawing.Size(260, 20)
    $listBox.Height = 80

    foreach ($value in $Values)
    { [void] $listBox.Items.Add($value) }

    $form.Controls.Add($listBox)

    $form.Topmost = $true

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $x = $listBox.SelectedItem
        return $x
    } else {
        # The user canceled, so exit the script. If the user canceled after connecting to vCenter, disconnect first.
        try {
            Disconnect-VIServer * -Confirm:$false
            Write-Warning 'User canceled dialog box. Exiting script.'
        } catch { Write-Warning 'Exiting before selecting a vCenter.' }
        finally { Exit }
    }
    
}

# Prompt user for vCenter to connect to
$vCenter = myDialogBox -Title 'Select a vCenter:' -Prompt 'Please select a vCenter:' -Values $vCenters

# Connect to vCenter selected
Connect-VIServer $vCenter

# Retrieve list of powered off VMs formatted according to $regexPattern variable
$TotalVMs = Get-VM | Where-Object { $_.PowerState -eq 'PoweredOff' -and $_.Name -match $regexPattern } | Sort-Object

# Prompt user to select the VM for export
$vm = myDialogBox -Title 'Select a Template:' -Prompt 'Please select the Template:' -Values $TotalVMs.Name

# Make sure VM does not have any ISOs attached to it
Get-VM -Name $vm | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false

# Hardcoded to No because removing snapshots will break the production image.
# $removeSnapshot = myDialogBox -Title "Remove snapshot:" -Prompt "Do you want to remove snapshots from the VM?" -Values Yes, No
$removeSnapshot = 'No'

if ($removeSnapshot -eq 'Yes') {
    # Removes snapshots from VM if $removeSnapshot variable is Yes
    Get-Snapshot $vm | Remove-Snapshot -Confirm:$false
}

# Hardcoded to OVA so that only a single file exists. OVFs output several files in a subfolder.
# $exportType = myDialogBox -Title "Select a format:" -Prompt "Please select the output format:" -Values OVA, OVF
$exportType = 'OVA'

# Determines where vCenter is and only exports to same DC DataDomain
if ($vCenter -in $vCentersOH) {
    $dataDomain = $DataDomainOH
} elseif ($vCenter -in $vCentersTX) {
    $dataDomain = $DataDomainTX
}

# Creates timestamped filename with the VM name as an OVA file
$filenamePrefix = $vm + '-' + $(Get-Date -Format 'yyyyMMddHHmmss')
$filename = $filenamePrefix + '.ova'
#$hashFilename = $filenamePrefix + ".md5"

# Creates connection to appropriate DataDomain
New-PSDrive -Name 'DataDomain' -Root $dataDomain -PSProvider 'FileSystem' -Credential $Cred
$saveToPath = $dataDomain + '\' + $filename
#$saveHashToPath = $dataDomain + "\" + $hashFilename

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    # Exports VM to destination in specified format
    Export-VApp -VM $vm -Destination "$saveToPath" -Format $exportType -ErrorAction Stop # Stop exists without trying, SilentlyContinue keeps going without catching
    # Creating the MD5 hash adds approximately 25 min runtime for an 18GB file. Commented out to speed up runtime.
    #Get-FileHash "$saveToPath" -Algorithm MD5 | Format-Table Algorithm, Hash | Out-File -FilePath "$saveHashToPath"
} catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ViServerConnectionException] {
    $message = $_
    Export-VApp -VM $vm -Destination "$saveToPath" -Format $exportType -ErrorAction SilentlyContinue #OnError exists without trying, SilentlyContinue keeps going without catching
    Write-Warning -Message "Verify that VM exported correctly. The vCenter disconnected during export. $message"
} catch {
    $message = $_
    Write-Error -Message 'An unexpected error occurred.'
} Finally {
    Get-ChildItem -Path $dataDomain -Filter "$vm*.ova" -File | # get files that start with the VM name and have the extension ".ova"
    Where-Object { $_.BaseName -match '-\d{14}$' } | # that end with a dash followed by 14 digits
    Sort-Object -Property @{Expression = { $_.BaseName.Substring(14) } } -Descending | # sort on the last 14 digits descending
    Select-Object -Skip $retain | # select them all except for the last $retain
    Remove-Item -Force #-WhatIf                                                      # delete selected files

    <# Removed because script no longer calculates checksum
Get-ChildItem -Path $dataDomain -Filter "$vm*.md5" -File |      # get files that start with the VM name and have the extension ".md5"
    Where-Object { $_.BaseName -match "-\d{14}$" } |                                 # that end with a dash followed by 14 digits
    Sort-Object -Property @{Expression = {$_.BaseName.Substring(14)}} -Descending |  # sort on the last 14 digits descending
    Select-Object -Skip $retain |                                                    # select them all except for the last $retain
    Remove-Item -Force #-WhatIf                                                      # delete selected files
#>

    # Disconnect from DataDomain
    Remove-PSDrive -Name 'DataDomain'

    # Disconnect from vCenter
    Disconnect-VIServer * -Confirm:$false

    $wshell = New-Object -ComObject Wscript.Shell
    $elapsedMinutes = $stopwatch.Elapsed.TotalMinutes
    $wshell.Popup("Operation Completed in $elapsedMinutes minutes", 0, 'Done', 0)
}
#####END OF SCRIPT#######