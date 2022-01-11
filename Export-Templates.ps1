# Created by Dan Gill
# Date: August 26, 2021
# Purpose: Use a dialog box to export OVF/OVA template from selected vCenter server.
# Dependencies: Uses Windows credentials to connect to vCenter server.


#######################
# Configure the variables below
#######################
# Specify a directory to download and install the new PowerCLI module to for future offline access
$PSModulePath = "$Env:SystemDrive\PowerCLIModule\"
# Import settings from settings.json file
$Settings = Get-Content "$PSScriptRoot\settings.json" -Raw | ConvertFrom-Json
#$MaxRunspaces = $Settings.General.MaxRunspaces
# Ohio vCenters
$vCentersOH = $Settings.vCenters.vCentersOH
# Texas vCenters
$vCentersTX = $Settings.vCenters.vCentersTX
# Synchronized hashtable
$Configuration = [hashtable]::Synchronized(@{})
$Configuration.ScriptResults = @()
# Delete path if it already exists
$SavePath = "$Env:SystemDrive\CWave\Export-Templates"
if (Test-Path -Path $SavePath) { Remove-Item -Path "$SavePath" -Recurse -Force }
$null = New-Item -Path "$SavePath" -ItemType Directory -Force
$ScriptResults = "$SavePath\$(Get-Date -f yyyy-MM-dd)_ScriptResults.log"
# DataDomain password
$Cred = New-Object System.Management.Automation.PSCredential ($Settings.DataDomain.username, (ConvertTo-SecureString $Settings.DataDomain.passwd -AsPlainText -Force))
# DataDomains
$DataDomainOH = $Settings.DataDomain.DataDomainOH
$DataDomainTX = $Settings.DataDomain.DataDomainTX
# Match any case of {3 to 4 character mneumonic}-view*, {3 to 4 character mneumonic}-ctx-appmx*
# Mneumonic must only contain letters from the English alphabet
$regexPattern = '^[a-zA-Z]{3,4}-(?:[Vv][Ii][Ee][Ww]|[Cc][Tt][Xx]-[Aa][Pp][Pp][Mm][Xx]).*$'

# Number of backups to retain
$retain = $Settings.General.RetainedCopies

# The script needs to run on an OH or TX Engineer Desktop
if ($env:computername -match '^[Tt][Xx][Oo][Ss]-[Ee][Nn][Gg]\d{2}$') {
    # Local computer is in TX, only list TX vCenters
    $vCenters = $vCentersTX
    $dataDomain = $DataDomainTX
} elseif ($env:computername -match '^(?:[Oo][Hh][Oo][Ss]|[Oo][Pp][Ss][Uu][Ss])-[Ee][Nn][Gg]-\d{2}$') {
    # Local computer is in OH, only list OH vCenters
    $vCenters = $vCentersOH
    $dataDomain = $DataDomainOH
} else {
    Write-Error -Message "You must run this script from a VDI in OH or TX.`r`nExamples: OPSUS-ENG-12, OHOS-ENG-35, or TXOS-ENG97" -Category PermissionDenied
    Exit 10              # Exiting script
}

#####################################################################
# Nothing to change below this line, commented throughout to explain
#####################################################################

if (!(Get-Module -ListAvailable -Name VMware.PowerCLI)) {
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
}
# Warn if the Certificate is invalid, but continue
$null = Set-PowerCLIConfiguration -InvalidCertificateAction Warn -Scope Session -Confirm:$false

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

$Worker = {
    param($VISrvr, $VM, $DD, $Configuration)
    # Make sure VM does not have any ISOs attached to it
    $null = Get-VM -Server $VISrvr -Name $VM | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false

    # Hardcoded to OVA so that only a single file exists. OVFs output several files in a subfolder.
    $exportType = 'OVA'

    # Creates timestamped filename with the VM name as an OVA file
    $saveToPath = "$DD\$VM-$(Get-Date -Format 'yyyyMMddHHmmss').$($exportType.ToLower())"
 
    try {
        # Exports VM to destination in specified format
        $null = Export-VApp -Server $VISrvr -VM $VM -Destination "$saveToPath" -Format $exportType -ErrorAction Stop # Stop exists without trying, SilentlyContinue keeps going without catching
        $Configuration.ScriptResults += "INFO: Finished exporting $VM on $VISrvr."
    } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ViServerConnectionException] {
        $null = Export-VApp -Server $VISrvr -VM $VM -Destination "$saveToPath" -Format $exportType -ErrorAction SilentlyContinue #OnError exists without trying, SilentlyContinue keeps going without catching
        $Configuration.ScriptResults += "WARNING: Finished exporting $VM on $VISrvr. Verify that VM exported correctly. The vCenter disconnected during export. $_"
    } catch {
        $Configuration.ScriptResults += "ERROR: An unexpected error occurred. $_"
    } Finally {
        $null = Get-ChildItem -Path $DD -Filter "$VM*.$($exportType.ToLower())" -File | # get files that start with the VM name and have the extension ".ova"
        Where-Object { $_.BaseName -match '-\d{14}$' } | # that end with a dash followed by 14 digits
        Sort-Object -Property @{Expression = { $_.BaseName.Substring(14) } } -Descending | # sort on the last 14 digits descending
        Select-Object -Skip $retain | # select them all except for the last $retain
        Remove-Item -Force #-WhatIf                                                      # delete selected files
    }
}

# Creates connection to appropriate DataDomain
$null = New-PSDrive -Name 'DataDomain' -Root $dataDomain -PSProvider 'FileSystem' -Credential $Cred

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($vCenter in $vCenters) {
    # Connect to vCenter selected using logged on user credentials
    $VIServer = $null
    while (!$VIServer) { $VIServer = Connect-VIServer $vCenter }
    
    # Retrieve list of powered off VMs formatted according to $regexPattern variable
    $VMs = Get-VM -Server $VIServer | Where-Object { $_.PowerState -eq 'PoweredOff' -and $_.Name -match $regexPattern }
    $MaxRunspaces = (Get-VMHost -Server $VIServer -VM $VMs -ErrorAction SilentlyContinue | Sort-Object | Get-Unique).Count

    # Create runspace pool for parralelization
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $SessionState, $Host)
    $RunspacePool.Open()

    $Jobs = New-Object System.Collections.ArrayList

    # Display progress bar
    Write-Progress -Id 1 -Activity 'Creating Runspaces' -Status "Creating runspaces for $($VMs.Count) templates on $vCenter." -PercentComplete 0

    $VMindex = 1
    # Create job for each VM
    foreach ($VirtualMachine in $VMs) {
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool
        $null = $PowerShell.AddScript($Worker).AddArgument($VIServer).AddArgument($VirtualMachine).AddArgument($dataDomain).AddArgument($Configuration)
        
        $JobObj = New-Object -TypeName PSObject -Property @{
            Runspace   = $PowerShell.BeginInvoke()
            PowerShell = $PowerShell  
        }
    
        $null = $Jobs.Add($JobObj)
        $RSPercentComplete = ($VMindex / $VMs.Count ).ToString('P')
        Write-Progress -Id 1 -Activity "Runspace creation: Processing $VirtualMachine on $vCenter" -Status "$VMindex/$($VMs.Count) : $RSPercentComplete Complete" -PercentComplete $RSPercentComplete.Replace('%', '')
    
        $VMindex++
    }
    Write-Progress -Id 1 -Activity 'Runspace creation' -Completed
    
    # Used to determine percentage completed.
    $TotalJobs = $Jobs.Runspace.Count
    
    Write-Progress -Id 2 -Activity "Export Templates on $vCenter" -Status 'Exporting templates.' -PercentComplete 0
    
    # Updated percentage complete and wait until all jobs are finished.
    while ($Jobs.Runspace.IsCompleted -contains $false) {
        $CompletedJobs = ($Jobs.Runspace.IsCompleted -eq $true).Count
        $PercentComplete = ($CompletedJobs / $TotalJobs ).ToString('P')
        Write-Progress -Id 2 -Activity "Export Templates on $vCenter" -Status "$CompletedJobs/$TotalJobs : $PercentComplete Complete" -PercentComplete $PercentComplete.Replace('%', '')
        Start-Sleep -Milliseconds 100
    }
    
    # Disconnect from vCenter
    Disconnect-VIServer -Server $VIServer -Force -Confirm:$false
    
    # Clean up runspace.
    $RunspacePool.Close()
    
    Write-Progress -Id 2 -Activity "Export Templates on $vCenter" -Completed
    
}

# Disconnect from DataDomain
$null = Remove-PSDrive -Name 'DataDomain'

# Write script errors to log file
if (Test-Path -Path $ScriptResults -PathType leaf) { Clear-Content -Path $ScriptResults }
Add-Content -Path $ScriptResults -Value $Configuration.ScriptResults

Write-Host "Script log saved to $ScriptResults"

$wshell = New-Object -ComObject Wscript.Shell
$elapsedMinutes = $stopwatch.Elapsed.TotalMinutes
$wshell.Popup("$TotalJobs templates exported in $elapsedMinutes minutes. Average $($elapsedMinutes/$TotalJobs) minutes per template.", 0, 'Done', 0)
#####END OF SCRIPT#######