<# Ensure running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an administrator. Exiting..." -ForegroundColor Red
    exit 1
}

$flagFile = "C:\LOGS\remediation_done.txt"
if (-Not (Test-Path $flagFile)) {
    # Run remediation tasks...
    Set-Content $flagFile "Remediation completed on $(Get-Date)"
}
#>

# Log start time for verification
$logPath = "C:\LOGS\hardening.log"
Add-Content -Path $logPath -Value "Script started: $(Get-Date)"

#####################################################################################################

# Set execution policy to bypass for the current session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

#####################################################################################################

# Detect operating system version
Write-Host "Detecting operating system version..."
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$osVersion = [Version]$osInfo.Version

$isWindows10 = $osVersion.Major -eq 10 -and $osVersion.Build -lt 22000
$isWindows11 = $osVersion.Major -eq 10 -and $osVersion.Build -ge 22000

if (-not ($isWindows10 -or $isWindows11)) {
    Write-Host "Unsupported OS version. Exiting..." -ForegroundColor Red
    exit 1
}

Write-Host "Operating System Detected: $($osInfo.Caption) ($osVersion)" -ForegroundColor Green
#
#####################################################################################################
#
# Directory and Backup Setup
$logsDirectory          = "C:\LOGS"
$registryBackupDirectory = "$logsDirectory\RegistryBackup"
$seceditBackupDirectory  = "$logsDirectory\SecEdit"

function Ensure-Directory {
    param (
        [string]$Path
    )
    try {
        $resolvedPath = [System.IO.Path]::GetFullPath($Path)
        if (-not (Test-Path -Path $resolvedPath)) {
            New-Item -Path $resolvedPath -ItemType Directory -Force | Out-Null
            Write-Host "Created directory: $resolvedPath" -ForegroundColor Green
            $dirItem = Get-Item -Path $resolvedPath -ErrorAction Stop
            $dirItem.Attributes = $dirItem.Attributes -bor [System.IO.FileAttributes]::Hidden
            Write-Host "Directory $resolvedPath is now hidden." -ForegroundColor Yellow
        }
        else {
            Write-Host "Directory already exists: $resolvedPath" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Error ensuring directory '$Path': $_" -ForegroundColor Red
        throw
    }
}

$directories = @($logsDirectory, $registryBackupDirectory, $seceditBackupDirectory)
$directories | ForEach-Object { Ensure-Directory -Path $_ }

# Backup Operations
$registryHives = @{
    "HKLM" = "HKEY_LOCAL_MACHINE"
    "HKCU" = "HKEY_CURRENT_USER"
    "HKU"  = "HKEY_USERS"
    "HKCR" = "HKEY_CLASSES_ROOT"
    "HKCC" = "HKEY_CURRENT_CONFIG"
}
$computerName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name

foreach ($hive in $registryHives.Keys) {
    $childPath = "{0}-{1}.reg" -f $computerName, $hive
    $backupFilePath = Join-Path -Path $registryBackupDirectory -ChildPath $childPath
    if (-not (Test-Path -Path $backupFilePath)) {
        try {
            reg export $registryHives[$hive] "$backupFilePath" /y | Out-Null
            Write-Host "Registry backup saved: $backupFilePath" -ForegroundColor Green
        }
        catch {
            Write-Host "Error backing up registry hive '$hive': $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Registry backup already exists: $backupFilePath" -ForegroundColor Cyan
    }
}

# Save the secpol settings
$seceditChild = "{0}-secEdit.cfg" -f $computerName
$seceditBackupFile = Join-Path -Path $seceditBackupDirectory -ChildPath $seceditChild
if (-not (Test-Path -Path $seceditBackupFile)) {
    try {
        secedit /export /cfg "$seceditBackupFile" | Out-Null
        Write-Host "Security policy backup saved: $seceditBackupFile" -ForegroundColor Green
    }
    catch {
        Write-Host "Error backing up Local Security Policy: $_" -ForegroundColor Red
    }
}
else {
    Write-Host "Security policy backup already exists: $seceditBackupFile" -ForegroundColor Cyan
}

Write-Host "Full system backup completed successfully. Proceed with caution before making any system changes!" -ForegroundColor Green

################################################################################################

# Define download URLs for Windows 10 & 11 Administrative Templates
$admxUrlWindows10 = "https://download.microsoft.com/download/c/3/c/c3cd85c0-0785-4cf7-a48e-cdc9b8e20108/Administrative%20Templates%20(.admx)%20for%20Windows%2010%20October%202022%20Update.msi"
$admxUrlWindows11 = "https://download.microsoft.com/download/b/e/e/bee408b9-d574-4c96-a1a6-45648d5565bf/Administrative%20Templates%20(.admx)%20for%20Windows%2011%20October%202023%20Update.msi"

# Set appropriate URL based on OS version
$downloadUrl = if ($isWindows10) { $admxUrlWindows10 } elseif ($isWindows11) { $admxUrlWindows11 } else { "" }

if ([string]::IsNullOrEmpty($downloadUrl)) {
    Write-Host "No valid download URL found. Exiting..." -ForegroundColor Red
    exit 1
}

# Define the download and extraction paths
$downloadPath = "C:\LOGS\ADMX"
$installerPath = "$downloadPath\admx_installer.msi"

# Ensure the download directory exists
if (-not (Test-Path $downloadPath)) {
    New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    Write-Host "Created directory: $downloadPath"
}

# Download the ADMX templates
Write-Host "Downloading Administrative Templates from: $downloadUrl..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath

if (!(Test-Path $installerPath)) {
    Write-Host "Download failed! Exiting..." -ForegroundColor Red
    exit 1
}

Write-Host "Download complete: $installerPath"

# Install the ADMX templates
Write-Host "Installing Administrative Templates..."
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait

Write-Host "Installation complete."

# ==============================
# Fix Permissions on PolicyDefinitions (If Required)
# ==============================
$policyDefinitionsPath = "C:\Windows\PolicyDefinitions"
$admxSourcePath = Get-ChildItem -Path "C:\Program Files (x86)\Microsoft Group Policy" -Directory | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 1 -ExpandProperty FullName

if (Test-Path "$admxSourcePath\PolicyDefinitions") {
    Write-Host "Taking ownership of PolicyDefinitions to allow copying..." -ForegroundColor Yellow
    takeown /f $policyDefinitionsPath /r /d Y | Out-Null
    icacls $policyDefinitionsPath /grant Administrators:F /t /c /q | Out-Null
    Write-Host "Ownership and permissions fixed."
} else {
    Write-Host "ERROR: Could not locate extracted PolicyDefinitions. Manual intervention required." -ForegroundColor Red
    exit 1
}

# ==============================
# Copy ADMX Templates to PolicyDefinitions
# ==============================
Write-Host "Copying ADMX templates to $policyDefinitionsPath..."
Copy-Item -Path "$admxSourcePath\PolicyDefinitions\*" -Destination $policyDefinitionsPath -Recurse -Force -ErrorAction Stop
Write-Host "ADMX templates copied successfully." -ForegroundColor Green

# Cleanup downloaded files
Write-Host "Cleaning up installation files..."
Remove-Item -Path $installerPath -Force

Write-Host "Administrative Templates installation complete. You may need to restart the system for changes to take effect." -ForegroundColor Green

# ==============================
# Check if a Reboot is Required
# ==============================
function Test-PendingReboot {
    $rebootKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    )

    foreach ($key in $rebootKeys) {
        if (Test-Path $key) {
            return $true
        }
    }

    try {
        $comp = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        # Check if the property exists before comparing its value.
        if ($comp.PSObject.Properties.Name -contains "RebootPending") {
            if ($comp.RebootPending -eq $true) {
                return $true
            }
        }
    }
    catch {
        # Ignore errors if the property cannot be read.
    }

    return $false
}

if (Test-PendingReboot) {
    Write-Host "A system reboot is required to complete the installation. Please restart the computer." -ForegroundColor Yellow
} else {
    Write-Host "No reboot is required. You can start using gpedit.msc immediately." -ForegroundColor Magenta
}

Write-Host "Administrative Templates installation complete." -ForegroundColor Green

#########################################################################################################################

# Uncommented this because already installed on the target machine for testing purposes.
# Define paths
$DownloadDir = "C:\LOGS\Apps"
$ZipFilePath = "$DownloadDir\LGPO.zip"
$ExtractTempPath = "$DownloadDir\LGPO_30"
$FinalLGPOPath = "$DownloadDir\LGPO"

# Ensure download directory exists
if (-Not (Test-Path $DownloadDir)) {
    New-Item -Path $DownloadDir -ItemType Directory -Force | Out-Null
}

# Download LGPO.zip
$DownloadUrl = "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip"
Write-Host "Downloading LGPO.zip to $ZipFilePath..."
Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipFilePath

# Ensure previous extraction folders are removed
if (Test-Path $ExtractTempPath) {
    Remove-Item -Path $ExtractTempPath -Recurse -Force
}
if (Test-Path $FinalLGPOPath) {
    Remove-Item -Path $FinalLGPOPath -Recurse -Force
}

# Extract LGPO.zip
Write-Host "Extracting LGPO.zip..."
Expand-Archive -Path $ZipFilePath -DestinationPath $DownloadDir -Force

# Ensure LGPO folder exists
New-Item -Path $FinalLGPOPath -ItemType Directory -Force | Out-Null

# Move contents from LGPO_30 to LGPO directory
Write-Host "Moving LGPO files to $FinalLGPOPath..."
Get-ChildItem -Path $ExtractTempPath | Move-Item -Destination $FinalLGPOPath -Force

# Move LGPO.exe to System32 for global access
$LGPOExePath = "$FinalLGPOPath\LGPO.exe"
if (Test-Path $LGPOExePath) {
    Write-Host "Moving LGPO.exe to C:\Windows\System32..."
    Copy-Item $LGPOExePath -Destination "C:\Windows\System32\" -Force
    Write-Host "LGPO.exe installed successfully!"
} else {
    Write-Host "Error: LGPO.exe not found in extracted folder!" -ForegroundColor Red
}

# Cleanup
Write-Host "Cleaning up installation files..."
Remove-Item -Path $ZipFilePath -Force
Remove-Item -Path $ExtractTempPath -Recurse -Force
Write-Host "LGPO setup completed successfully!"
#
#
##############################################################################################################

Write-Host "Gathering all local user accounts and their group memberships..." -ForegroundColor Cyan
Get-LocalUser | ForEach-Object {
    $User = $_.Name
    $Groups = (Get-LocalGroup | Where-Object { (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue) -match $User }).Name
    Write-Host "User: $User | Groups: $($Groups -join ', ')" -ForegroundColor Green
}

##############################################################################################################

# ALL TESTS PASSED
# ==============================================================
# CIS Benchmark 19.5.1.1 - Turn off toast notifications on the lock screen (User Configuration)
# ==============================================================
Write-Host "Configuring User Configuration: Turn off toast notifications on the lock screen..." -ForegroundColor Cyan

# ==============================
# Step 1: Ensure LGPO Directory is Fresh
# ==============================
$lgpoDirectory = "C:\LOGS\LGPO"

if (Test-Path $lgpoDirectory) {
    Write-Host "Existing LGPO directory found. Removing it to ensure a fresh configuration..." -ForegroundColor Yellow
    Remove-Item -Path $lgpoDirectory -Recurse -Force
    Start-Sleep -Seconds 2  
    Write-Host "Old LGPO directory removed successfully." -ForegroundColor Green
}

if (-not (Test-Path $lgpoDirectory)) {
    New-Item -ItemType Directory -Path $lgpoDirectory -Force | Out-Null
    Write-Host "Created directory: $lgpoDirectory"
}

$lgpoDirAttributes = (Get-Item $lgpoDirectory).Attributes
if (-not ($lgpoDirAttributes -band [System.IO.FileAttributes]::Hidden)) {
    Set-ItemProperty -Path $lgpoDirectory -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
    Write-Host "Set directory to Hidden: $lgpoDirectory"
} else {
    Write-Host "Directory already set to Hidden: $lgpoDirectory"
}

# ==============================
# Step 2: Export Local Group Policy (All Policies - no /un or /m switch)
# ==============================
Write-Host "Exporting Local Group Policy settings..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/b C:\LOGS\LGPO"
Start-Sleep -Seconds 2  

# ==============================
# Step 3: Locate and Rename GUID Folder
# ==============================
$GUIDFolder = Get-ChildItem -Path $lgpoDirectory | Where-Object { $_.PSIsContainer -and $_.Name -match "^\{.*\}$" } | Select-Object -ExpandProperty FullName
if ($GUIDFolder) {
    $backupFolder = Join-Path $lgpoDirectory "LGPO_Backup"
    Rename-Item -Path $GUIDFolder -NewName $backupFolder -Force
    Write-Host "Renamed $GUIDFolder to $backupFolder"
} else {
    Write-Host "ERROR: No GUID folder found in $lgpoDirectory!" -ForegroundColor Red
    exit 1
}

# ==============================
# Step 4: Parse registry.pol to Generate lgpo.txt (User Configuration)
# ==============================
$registryPolPath = "C:\LOGS\LGPO\LGPO_Backup\DomainSysvol\GPO\User\registry.pol"
$outputTextFile = "C:\LOGS\LGPO\LGPO_Backup\lgpo.txt"
Write-Host "Parsing registry.pol to create $outputTextFile..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/parse /un `"$registryPolPath`"" -RedirectStandardOutput $outputTextFile # Removed /un from argumentlist
if (Test-Path $outputTextFile) {
    Write-Host "Successfully created parsed output at $outputTextFile" -ForegroundColor Green
} else {
    Write-Host "ERROR: Parsed output file was not created!" -ForegroundColor Red
    exit 1
}
Write-Host "LGPO backup and parsing completed successfully!" -ForegroundColor Cyan

# ==============================
# Step 5: Modify lgpo.txt for Toast Notifications Setting
# ==============================
Write-Host "Modifying LGPO text file to apply toast notification setting..." -ForegroundColor Cyan

# Read the content into a list for modification
$content = [System.Collections.Generic.List[string]]::new()
$content.AddRange([string[]](Get-Content -Path $outputTextFile))

# Identify the insertion point: first line beginning with "; PARSING COMPLETED."
$finalCommentLine = $content | Where-Object { $_ -match '^; PARSING COMPLETED\.' } | Select-Object -First 1
$insertionIndex = $content.IndexOf($finalCommentLine)
if ($insertionIndex -lt 0) { $insertionIndex = $content.Count }

# Define the desired toast notification setting block (4 lines)
$toastSetting = @(
    "User",
    "Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
    "NoToastApplicationNotificationOnLockScreen",
    "DWORD:1"
)

# Ensure a blank line before insertion if needed
if ($insertionIndex -gt 0 -and $content[$insertionIndex - 1] -ne "") {
    $content.Insert($insertionIndex, "")
    $insertionIndex++
}

# Search for an existing toast notification setting block
$foundIndex = -1
for ($i = 0; $i -le $content.Count - 4; $i++) {
    if ($content[$i] -eq "User" -and 
        $content[$i+1] -eq "Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -and 
        $content[$i+2] -eq "NoToastApplicationNotificationOnLockScreen") {
        $foundIndex = $i
        break
    }
}

if ($foundIndex -ge 0) {
    # Update the value if necessary
    if ($content[$foundIndex + 3] -ne "DWORD:1") {
        $content[$foundIndex + 3] = "DWORD:1"
        Write-Host "Updated existing toast notification setting in lgpo.txt" -ForegroundColor Yellow
    } else {
        Write-Host "Toast notification setting already exists with correct value. No change needed." -ForegroundColor Cyan
    }
} else {
    # Insert the new toast notification setting block
    $content.InsertRange($insertionIndex, [System.Collections.Generic.List[string]]$toastSetting)
    Write-Host "Inserted new toast notification setting in lgpo.txt" -ForegroundColor Green
}

# ==============================
# Step 6: Modify lgpo.txt for Additional User Configuration Settings
# ==============================
Write-Host "Modifying LGPO text file to apply additional User Configuration settings..." -ForegroundColor Cyan

$additionalSettings = @(
    # Attachment Manager
    @{ Section = "User"; Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments";   Key = "SaveZoneInformation";           Value = "DWORD:2" },
    @{ Section = "User"; Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments";   Key = "ScanWithAntiVirus";              Value = "DWORD:3" },
    # Cloud Content (base settings)
    @{ Section = "User"; Path = "Software\Policies\Microsoft\Windows\CloudContent";               Key = "ConfigureWindowsSpotlight";    Value = "DWORD:2" },
    @{ Section = "User"; Path = "Software\Policies\Microsoft\Windows\CloudContent";               Key = "DisableThirdPartySuggestions";   Value = "DWORD:1" },
    @{ Section = "User"; Path = "Software\Policies\Microsoft\Windows\CloudContent";               Key = "DisableSpotlightCollectionOnDesktop"; Value = "DWORD:1" },
    # Network Sharing
    @{ Section = "User"; Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";    Key = "NoInplaceSharing";               Value = "DWORD:1" },
    # Windows Installer
    @{ Section = "User"; Path = "Software\Policies\Microsoft\Windows\Installer";                Key = "AlwaysInstallElevated";          Value = "DWORD:0" },
    # Prevent Codec Download (Windows Media Player)
    @{ Section = "User"; Path = "Software\Policies\Microsoft\WindowsMediaPlayer";               Key = "Pr";                             Value = "DWORD:1" }
)

# Append Windows 11–only settings if running on Windows 11
if ($isWindows11) {
    $additionalSettings += @{ Section = "User"; Path = "Software\Policies\Microsoft\Windows\CloudContent"; Key = "DisableTailoredExperiencesWithDiagnosticData"; Value = "DWORD:1" }
    $additionalSettings += @{ Section = "User"; Path = "Software\Policies\Microsoft\Windows\CloudContent"; Key = "DisableWindowsSpotlightFeatures";                         Value = "DWORD:1" }
    $additionalSettings += @{ Section = "User"; Path = "Software\Policies\Microsoft\Assistance\Client\1.0"; Key = "NoImplicitFeedback"; Value = "DWORD:1" }
}

# Process each additional setting
foreach ($setting in $additionalSettings) {
    $section      = $setting.Section
    $regPath      = $setting.Path
    $key          = $setting.Key
    $desiredValue = $setting.Value

    # Identify insertion point: first line beginning with "; PARSING COMPLETED."
    $finalCommentLine = $content | Where-Object { $_ -match '^; PARSING COMPLETED\.' } | Select-Object -First 1
    $insertionIndex = $content.IndexOf($finalCommentLine)
    if ($insertionIndex -lt 0) { $insertionIndex = $content.Count }

    # Ensure a blank line before insertion if needed
    if ($insertionIndex -gt 0 -and $content[$insertionIndex - 1] -ne "") {
        $content.Insert($insertionIndex, "")
        $insertionIndex++
    }

    # Search for an existing block for this setting (4 lines: Section, RegPath, Key, Value)
    $foundIndex = -1
    for ($i = 0; $i -le $content.Count - 4; $i++) {
        if ($content[$i] -eq $section -and 
            $content[$i+1] -eq $regPath -and 
            $content[$i+2] -eq $key) {
            $foundIndex = $i
            break
        }
    }

    if ($foundIndex -ge 0) {
        # Update the value if it differs
        if ($content[$foundIndex + 3] -ne $desiredValue) {
            $content[$foundIndex + 3] = $desiredValue
            Write-Host "Updated existing setting for $regPath\$key in lgpo.txt" -ForegroundColor Yellow
        } else {
            Write-Host "Setting for $regPath\$key already exists with correct value. No change needed." -ForegroundColor Cyan
        }
    } else {
        # Insert the new setting block (4 lines)
        $newSetting = @(
            $section,
            $regPath,
            $key,
            $desiredValue
        )
        $content.InsertRange($insertionIndex, [System.Collections.Generic.List[string]]$newSetting)
        Write-Host "Inserted new setting for $regPath\$key in lgpo.txt" -ForegroundColor Green
    }
}

# Save the modified lgpo.txt with additional settings
# Convert all "User:Non-Administrators" to "User" just before rebuild
for ($i = 0; $i -lt $content.Count; $i++) {
    if ($content[$i] -eq "User:Non-Administrators") {
        $content[$i] = "User"
    }
}

$content | Set-Content -Path $outputTextFile -Encoding UTF8
Write-Host "LGPO text file has been successfully updated with additional settings." -ForegroundColor Green

# ==============================
# Step 7: Apply Windows 11–Only Windows Copilot Setting Directly
# ==============================
if ($isWindows11) {
    # Ensure the folder for the user configuration script exists.
    $scriptDir = "C:\LOGS\Scripts"
    if (-not (Test-Path $scriptDir)) {
        New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
        Write-Host "Created scripts directory: $scriptDir" -ForegroundColor Green
    }

    # Write (or update) the user configuration script that applies the Windows Copilot setting.
    $userConfigScriptContent = @'
# userConfiguration.ps1
# This script applies the Windows Copilot setting for non-administrator users.
# It runs in the context of the logged-on user.
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator account detected. Skipping Windows Copilot setting."
    exit
}

$copilotPath = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
if (Test-Path $copilotPath) {
    $existingValue = (Get-ItemProperty -Path $copilotPath -Name "TurnOffWindowsCopilot" -ErrorAction SilentlyContinue).TurnOffWindowsCopilot
    if ($existingValue -eq 1) {
        Write-Host "Windows Copilot setting already applied. Exiting."
        exit
    }
}

if (-not (Test-Path $copilotPath)) {
    New-Item -Path $copilotPath -Force | Out-Null
    Write-Host "Created registry path $copilotPath"
}

Set-ItemProperty -Path $copilotPath -Name "TurnOffWindowsCopilot" -Type DWord -Value 1 -Force
Write-Host "Applied Windows Copilot setting for the current user."
'@

    $userConfigScriptPath = Join-Path $scriptDir "userConfiguration.ps1"
    $userConfigScriptContent | Set-Content -Path $userConfigScriptPath -Encoding UTF8
    Write-Host "User configuration script written to $userConfigScriptPath" -ForegroundColor Green

    # Create a scheduled task that runs at logon for all users.
    # Using /RU INTERACTIVE causes the task to run in the context of the interactive user.
    $taskName = "Apply Windows Copilot Setting for All Users"
    $taskAction = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$userConfigScriptPath`""
    
    # If the task exists, delete it for re-creation.
    schtasks.exe /Query /TN "$taskName" > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Scheduled task '$taskName' already exists. Deleting for re-creation..." -ForegroundColor Yellow
        schtasks.exe /Delete /TN "$taskName" /F | Out-Null
    }
    
    Write-Host "Creating scheduled task '$taskName' for all users..."
    schtasks.exe /Create /SC ONLOGON /TN "$taskName" /TR "$taskAction" /RU INTERACTIVE /RL HIGHEST /F | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Scheduled task '$taskName' created successfully." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to create scheduled task '$taskName'." -ForegroundColor Red
    }
}

# ==============================
# Step 8: Convert Modified LGPO Text File Back to registry.pol for User Configuration (Mimicking Machine Process)
# ==============================
$registryPolFile = Join-Path $backupFolder "registry.pol"
Write-Host "Rebuilding registry.pol from lgpo.txt for User Configuration..." -ForegroundColor Cyan
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/r `"$outputTextFile`" /w `"$registryPolFile`""
if (-not (Test-Path $registryPolFile)) {
    Write-Host "ERROR: registry.pol was not created successfully!" -ForegroundColor Red
    exit 1
}
Write-Host "registry.pol has been successfully rebuilt." -ForegroundColor Green

# ==============================
# Step 9: Apply the updated registry.pol file for Non-Administrators
# ==============================
Write-Host "Applying updated Registry.pol for Non-Administrators using LGPO.exe..." -ForegroundColor Cyan

$modifiedRegistryPol = Join-Path $backupFolder "registry.pol"

if (Test-Path $modifiedRegistryPol) {
    # Ensure the filename uses correct case (LGPO is case-sensitive with file extensions)
    Rename-Item -Path $modifiedRegistryPol -NewName "Registry.pol" -Force
    $renamedRegistryPol = Join-Path $backupFolder "Registry.pol"

    # Apply to Non-Administrators only using /un switch
    Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/un `"$renamedRegistryPol`""
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully applied policy to Non-Administrators." -ForegroundColor Green
    } else {
        Write-Host "ERROR: LGPO.exe failed to apply policy to Non-Administrators." -ForegroundColor Red
        exit 1
    }

    # Apply Group Policy updates
    Write-Host "Forcing Group Policy update..."
    gpupdate /force
    Write-Host "Group Policy update complete." -ForegroundColor Green
} else {
    Write-Host "ERROR: Rebuilt Registry.pol not found at $modifiedRegistryPol" -ForegroundColor Red
    exit 1
}

#########################################################################################################################

# ALL TESTS PASSED HERE
# ==============================
# CIS Benchmark 18.10.25 - Event Log Policies (Fixing Retention Failures via LGPO.exe)
# ==============================
Write-Host "Configuring Event Log policies using LGPO.exe..." -ForegroundColor Cyan

# ------------------------------
# Pre-Step: Ensure LGPO Directory is Fresh
# ------------------------------
$lgpoDirectory = "C:\LOGS\LGPO"
if (Test-Path $lgpoDirectory) {
    Write-Host "Existing LGPO directory found. Removing it for a fresh configuration..." -ForegroundColor Yellow
    Remove-Item -Path $lgpoDirectory -Recurse -Force
    Start-Sleep -Seconds 2
    Write-Host "Old LGPO directory removed successfully." -ForegroundColor Green
}

# ------------------------------
# Step 1: Create LGPO Directory and Set Hidden Attribute
# ------------------------------
New-Item -ItemType Directory -Path $lgpoDirectory -Force | Out-Null
Write-Host "Created directory: $lgpoDirectory"
Set-ItemProperty -Path $lgpoDirectory -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
Write-Host "Set directory to Hidden: $lgpoDirectory"

# ------------------------------
# Step 2: Export Local Group Policy Settings and Rename GUID Folder
# ------------------------------
Write-Host "Exporting Local Group Policy settings..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/b `"$lgpoDirectory`""

$GUIDFolder = Get-ChildItem -Path $lgpoDirectory | Where-Object { $_.PSIsContainer -and $_.Name -match "^\{.*\}$" } | Select-Object -ExpandProperty FullName
if ($GUIDFolder) {
    $backupFolder = Join-Path $lgpoDirectory "LGPO_Backup"
    Rename-Item -Path $GUIDFolder -NewName $backupFolder -Force
    Write-Host "Renamed $GUIDFolder to $backupFolder"
} else {
    Write-Host "ERROR: No GUID folder found in $lgpoDirectory!" -ForegroundColor Red
    exit 1
}

# ------------------------------
# Step 3: Parse registry.pol to Create lgpo.txt
# ------------------------------
$registryPolPath = Join-Path $backupFolder "DomainSysvol\GPO\Machine\registry.pol"
$outputTextFile  = Join-Path $backupFolder "lgpo.txt"
Write-Host "Parsing registry.pol to create $outputTextFile..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/parse /m `"$registryPolPath`"" -RedirectStandardOutput $outputTextFile

if (Test-Path $outputTextFile) {
    Write-Host "Successfully created parsed output at $outputTextFile"
} else {
    Write-Host "ERROR: Parsed output file was not created!" -ForegroundColor Red
    exit 1
}
Write-Host "LGPO backup and parsing completed successfully!"

# ------------------------------
# Step 4: Update lgpo.txt with the Correct Event Log Settings
# ------------------------------

# Read the current content into a strongly typed List for easier manipulation.
$lines = New-Object System.Collections.Generic.List[string]
$lines.AddRange([string[]](Get-Content $outputTextFile))

# Identify the insertion point using a final comment marker (e.g., "; PARSING COMPLETED.").
$finalCommentLine = $lines | Where-Object { $_ -match '^; PARSING COMPLETED\.' } | Select-Object -First 1
$insertionIndex = $lines.IndexOf($finalCommentLine)
if ($insertionIndex -lt 0) {
    $insertionIndex = $lines.Count
}

# Determine desired retention value based on OS version
# (Assumes $isWindows10 is defined elsewhere)
if ($isWindows10 -or $isWindows11) {
    $desiredRetentionValue = "SZ:0"
} else {
    $desiredRetentionValue = "DWORD:0"
}

# Define Event Log Retention settings.
$retentionSettings = @(
    @{ Path = "Software\Policies\Microsoft\Windows\EventLog\Application"; Key = "Retention"; Value = $desiredRetentionValue },
    @{ Path = "Software\Policies\Microsoft\Windows\EventLog\Security";    Key = "Retention"; Value = $desiredRetentionValue },
    @{ Path = "Software\Policies\Microsoft\Windows\EventLog\Setup";       Key = "Retention"; Value = $desiredRetentionValue },
    @{ Path = "Software\Policies\Microsoft\Windows\EventLog\System";      Key = "Retention"; Value = $desiredRetentionValue }
)

# Process each Retention setting.
foreach ($setting in $retentionSettings) {
    $section = "Computer"
    $foundIndices = @()
    for ($i = 0; $i -le $lines.Count - 4; $i++) {
        if ($lines[$i] -eq $section -and 
            $lines[$i+1] -eq $setting.Path -and 
            $lines[$i+2] -eq $setting.Key) {
            $foundIndices += $i
        }
    }
    if ($foundIndices.Count -eq 0) {
        $block = @("Computer", $setting.Path, $setting.Key, $setting.Value)
        $lines.InsertRange($insertionIndex, [string[]]$block)
        $insertionIndex += $block.Count
        Write-Host "Inserted new block for $($setting.Path)\$($setting.Key) with value '$($setting.Value)'" -ForegroundColor Green
    }
    else {
        $masterIndex = $foundIndices[0]
        if ($lines[$masterIndex + 3] -ne $setting.Value) {
            $lines[$masterIndex + 3] = $setting.Value
            Write-Host "Updated $($setting.Path)\$($setting.Key) to '$($setting.Value)'" -ForegroundColor Yellow
        }
        if ($foundIndices.Count -gt 1) {
            foreach ($dupIndex in ($foundIndices[1..($foundIndices.Count - 1)] | Sort-Object -Descending)) {
                $lines.RemoveRange($dupIndex, 4)
                if ($dupIndex -lt $insertionIndex) { $insertionIndex -= 4 }
            }
        }
    }
}

# Define Event Log MaxSize settings.
$maxSizeSettings = @(
    @{ Path = "Software\Policies\Microsoft\Windows\EventLog\Application"; Key = "MaxSize"; Value = "DWORD:32768" },
    @{ Path = "Software\Policies\Microsoft\Windows\EventLog\Security";    Key = "MaxSize"; Value = "DWORD:196608" },
    @{ Path = "Software\Policies\Microsoft\Windows\EventLog\Setup";       Key = "MaxSize"; Value = "DWORD:32768" },
    @{ Path = "Software\Policies\Microsoft\Windows\EventLog\System";      Key = "MaxSize"; Value = "DWORD:32768" }
)

# Process each MaxSize setting.
foreach ($setting in $maxSizeSettings) {
    $section = "Computer"
    $foundIndices = @()
    for ($i = 0; $i -le $lines.Count - 4; $i++) {
        if ($lines[$i] -eq $section -and 
            $lines[$i+1] -eq $setting.Path -and 
            $lines[$i+2] -eq $setting.Key) {
            $foundIndices += $i
        }
    }
    if ($foundIndices.Count -eq 0) {
        $block = @("Computer", $setting.Path, $setting.Key, $setting.Value)
        $lines.InsertRange($insertionIndex, [string[]]$block)
        $insertionIndex += $block.Count
        Write-Host "Inserted new block for $($setting.Path)\$($setting.Key) with value '$($setting.Value)'" -ForegroundColor Green
    }
    else {
        $masterIndex = $foundIndices[0]
        if ($lines[$masterIndex + 3] -ne $setting.Value) {
            $lines[$masterIndex + 3] = $setting.Value
            Write-Host "Updated $($setting.Path)\$($setting.Key) to '$($setting.Value)'" -ForegroundColor Yellow
        }
        if ($foundIndices.Count -gt 1) {
            foreach ($dupIndex in ($foundIndices[1..($foundIndices.Count - 1)] | Sort-Object -Descending)) {
                $lines.RemoveRange($dupIndex, 4)
                if ($dupIndex -lt $insertionIndex) { $insertionIndex -= 4 }
            }
        }
    }
}

# Remove any incomplete blocks.
for ($i = $lines.Count - 4; $i -ge 0; $i--) {
    if ($lines[$i] -eq "Computer") {
        if ((($i+1) -ge $lines.Count) -or [string]::IsNullOrWhiteSpace($lines[$i+1]) -or
            (($i+2) -ge $lines.Count) -or [string]::IsNullOrWhiteSpace($lines[$i+2]) -or
            (($i+3) -ge $lines.Count) -or [string]::IsNullOrWhiteSpace($lines[$i+3])) {
            $lines.RemoveRange($i, $lines.Count - $i)
        }
    }
}

# Insert a blank line before every block starting with "Computer" for readability.
for ($i = $lines.Count - 1; $i -ge 1; $i--) {
    if ($lines[$i] -eq "Computer" -and $lines[$i-1] -ne "") {
        $lines.Insert($i, "")
    }
}

# Write the updated content back to lgpo.txt.
$lines | Set-Content -Path $outputTextFile -Encoding UTF8
Write-Host "lgpo.txt has been updated with Event Log settings." -ForegroundColor Green

# ------------------------------
# Step 5: Apply the Updated LGPO Settings to the Local Group Policy
# ------------------------------
Write-Host "Applying modified LGPO settings from text file..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/t `"$outputTextFile`""
Write-Host "Modified LGPO settings have been applied to the active Group Policy." -ForegroundColor Green

# ------------------------------
# Step 6: (Optional) Back Up the Updated registry.pol File
# ------------------------------
Write-Host "Backing up updated registry.pol file..."
Copy-Item -Path "C:\Windows\System32\GroupPolicy\Machine\registry.pol" -Destination (Join-Path $backupFolder "registry.pol") -Force
Write-Host "Backup of registry.pol completed."

# ------------------------------
# Step 7: Force Group Policy Update
# ------------------------------
Write-Host "Forcing Group Policy update..."
gpupdate /force
Write-Host "Local Group Policy settings have been successfully applied!" -ForegroundColor Green

#########################################################################################################################

# ALL TESTS PASSED HERE
#########################################################################################################################
# CIS Benchmark 18.10.92 - Windows Update Policies (Fixed via LGPO.exe)
#########################################################################################################################
Write-Host "Configuring Windows Update policies using LGPO.exe..." -ForegroundColor Yellow

# ------------------------------
# Pre-Step: Ensure LGPO Directory is Fresh
# ------------------------------
$lgpoDirectory = "C:\LOGS\LGPO"
if (Test-Path $lgpoDirectory) {
    Write-Host "Existing LGPO directory found. Removing it for a fresh configuration..." -ForegroundColor Yellow
    Remove-Item -Path $lgpoDirectory -Recurse -Force
    Start-Sleep -Seconds 2
    Write-Host "Old LGPO directory removed successfully." -ForegroundColor Green
}

# ------------------------------
# Step 1: Create LGPO Directory and Set Hidden Attribute
# ------------------------------
New-Item -ItemType Directory -Path $lgpoDirectory -Force | Out-Null
Write-Host "Created directory: $lgpoDirectory"
Set-ItemProperty -Path $lgpoDirectory -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
Write-Host "Set directory to Hidden: $lgpoDirectory"

# ------------------------------
# Step 2: Export Local Group Policy Settings and Rename GUID Folder
# ------------------------------
Write-Host "Exporting Local Group Policy settings..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/b `"$lgpoDirectory`""

$GUIDFolder = Get-ChildItem -Path $lgpoDirectory | Where-Object { $_.PSIsContainer -and $_.Name -match "^\{.*\}$" } | Select-Object -ExpandProperty FullName
if ($GUIDFolder) {
    $backupFolder = Join-Path $lgpoDirectory "LGPO_Backup"
    Rename-Item -Path $GUIDFolder -NewName $backupFolder -Force
    Write-Host "Renamed $GUIDFolder to $backupFolder"
} else {
    Write-Host "ERROR: No GUID folder found in $lgpoDirectory!" -ForegroundColor Red
    exit 1
}

# ------------------------------
# Step 3: Parse registry.pol to Create lgpo.txt
# ------------------------------
$registryPolPath = Join-Path $backupFolder "DomainSysvol\GPO\Machine\registry.pol"
$outputTextFile  = Join-Path $backupFolder "lgpo.txt"
Write-Host "Parsing registry.pol to create $outputTextFile..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/parse /m `"$registryPolPath`"" -RedirectStandardOutput $outputTextFile

if (Test-Path $outputTextFile) {
    Write-Host "Successfully created parsed output at $outputTextFile"
} else {
    Write-Host "ERROR: Parsed output file was not created!" -ForegroundColor Red
    exit 1
}
Write-Host "LGPO backup and parsing completed successfully!"

# ------------------------------
# Step 4: Update lgpo.txt with the Correct Windows Update Settings
# ------------------------------

# Read the current content into a strongly typed list for easier manipulation.
$lines = New-Object System.Collections.Generic.List[string]
$lines.AddRange([string[]](Get-Content $outputTextFile))

# Identify the insertion point using a final comment marker.
$finalCommentLine = $lines | Where-Object { $_ -match '^; PARSING COMPLETED\.' } | Select-Object -First 1
$insertionIndex = $lines.IndexOf($finalCommentLine)
if ($insertionIndex -lt 0) {
    $insertionIndex = $lines.Count
}

# Define the consolidated Windows Update settings to be applied (including AUOptions).
$wuSettings = @(
    # 18.10.92.1 Legacy Policies
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate\Au"; Key = "NoAutoRebootWithLoggedOnUsers"; Value = "DWORD:0" },
    
    # 18.10.92.2 Manage End User Experience (common to both Windows 10 & 11)
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate\Au"; Key = "NoAutoUpdate";            Value = "DWORD:0" },
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate\Au"; Key = "ScheduledInstallDay";     Value = "DWORD:0" },
    # NEW: Set AUOptions to 4 (Auto download and schedule install)
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate\Au"; Key = "AUOptions";             Value = "DWORD:4" },
    
    # Windows 11–only settings
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Key = "AllowTemporaryEnterpriseFeatureControl"; Value = "DWORD:0"; Windows11Only = $true },
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Key = "SetDisablePauseUXAccess";              Value = "DWORD:1" },
    
    # 18.10.92.4 Manage Updates Offered from Windows Update
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Key = "ManagePreviewBuildsPolicyValue"; Value = "DWORD:1" },
    
    # Preview Builds / Feature Updates:
    # Windows 10 uses "DeferFeatureUpdates" with value 180
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Key = "DeferFeatureUpdates"; Value = "DWORD:180"; Windows10Only = $true },
    # Windows 11 uses "DeferFeatureUpdatesPeriodInDays" with value 180
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Key = "DeferFeatureUpdatesPeriodInDays"; Value = "DWORD:180"; Windows11Only = $true },
    
    # Quality Updates settings (unchanged)
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Key = "DeferQualityUpdates"; Value = "DWORD:1" },
    
    # Optional Updates:
    # Windows 10: use "AllowOptionalContent" set to 0
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Key = "AllowOptionalContent"; Value = "DWORD:0"; Windows10Only = $true },
    # Windows 11: use "SetAllowOptionalContent" set to 0
    @{ Path = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Key = "SetAllowOptionalContent"; Value = "DWORD:0"; Windows11Only = $true }
)

# Process each Windows Update setting.
foreach ($setting in $wuSettings) {
    # Skip settings marked Windows10Only or Windows11Only if not applicable.
    if ($setting.ContainsKey("Windows10Only") -and $setting.Windows10Only -and -not $isWindows10) {
        Write-Host "Skipping $($setting.Path)\$($setting.Key) as it is applied only on Windows 10." -ForegroundColor Cyan
        continue
    }
    if ($setting.ContainsKey("Windows11Only") -and $setting.Windows11Only -and -not $isWindows11) {
        Write-Host "Skipping $($setting.Path)\$($setting.Key) as it is applied only on Windows 11." -ForegroundColor Cyan
        continue
    }
    
    # Look for existing 4-line blocks (Computer, Path, Key, Value).
    $foundIndices = @()
    for ($i = 0; $i -le $lines.Count - 4; $i++) {
        if ($lines[$i] -eq "Computer" -and `
            $lines[$i+1] -eq $setting.Path -and `
            $lines[$i+2] -eq $setting.Key) {
            $foundIndices += $i
        }
    }
    if ($foundIndices.Count -eq 0) {
        # Insert new block.
        $block = @("Computer", $setting.Path, $setting.Key, $setting.Value)
        $lines.InsertRange($insertionIndex, [string[]]$block)
        $insertionIndex += $block.Count
        Write-Host "Inserted new block for $($setting.Path)\$($setting.Key) with value '$($setting.Value)'" -ForegroundColor Green
    }
    else {
        # Update the master block.
        $masterIndex = $foundIndices[0]
        if ($lines[$masterIndex + 3] -ne $setting.Value) {
            $lines[$masterIndex + 3] = $setting.Value
            Write-Host "Updated $($setting.Path)\$($setting.Key) to '$($setting.Value)'" -ForegroundColor Yellow
        }
        # Remove any duplicate blocks.
        if ($foundIndices.Count -gt 1) {
            foreach ($dupIndex in ($foundIndices[1..($foundIndices.Count - 1)] | Sort-Object -Descending)) {
                $lines.RemoveRange($dupIndex, 4)
                if ($dupIndex -lt $insertionIndex) { $insertionIndex -= 4 }
            }
        }
    }
}

# Remove any incomplete blocks.
for ($i = $lines.Count - 4; $i -ge 0; $i--) {
    if ($lines[$i] -eq "Computer") {
        if ((($i+1) -ge $lines.Count) -or [string]::IsNullOrWhiteSpace($lines[$i+1]) -or
            (($i+2) -ge $lines.Count) -or [string]::IsNullOrWhiteSpace($lines[$i+2]) -or
            (($i+3) -ge $lines.Count) -or [string]::IsNullOrWhiteSpace($lines[$i+3])) {
            $lines.RemoveRange($i, $lines.Count - $i)
        }
    }
}

# Insert a blank line before every block starting with "Computer" for readability.
for ($i = $lines.Count - 1; $i -ge 1; $i--) {
    if ($lines[$i] -eq "Computer" -and $lines[$i-1] -ne "") {
        $lines.Insert($i, "")
    }
}

# Write the updated content back to lgpo.txt.
$lines | Set-Content -Path $outputTextFile -Encoding UTF8
Write-Host "lgpo.txt has been updated with Windows Update settings." -ForegroundColor Green

# ------------------------------
# Step 5: Apply the Updated LGPO Settings to the Local Group Policy
# ------------------------------
Write-Host "Applying modified LGPO settings from text file..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/t `"$outputTextFile`""
Write-Host "Modified LGPO settings have been applied to the active Group Policy." -ForegroundColor Green

# ------------------------------
# Step 6: (Optional) Back Up the Updated registry.pol File
# ------------------------------
Write-Host "Backing up updated registry.pol file..."
Copy-Item -Path "C:\Windows\System32\GroupPolicy\Machine\registry.pol" -Destination (Join-Path $backupFolder "registry.pol") -Force
Write-Host "Backup of registry.pol completed."

# ------------------------------
# Step 7: Force Group Policy Update
# ------------------------------
Write-Host "Forcing Group Policy update..."
gpupdate /force
Write-Host "Local Group Policy settings have been successfully applied!" -ForegroundColor Green

#######################################################################################################################

# CIS Benchmark 9 - Windows Firewall
Write-Host "Starting process of setting CIS Benchmark 9 - Windows Firewall..." -ForegroundColor Yellow

# ==============================
# Pre-Step: Ensure LGPO Directory is Fresh
# ==============================
$lgpoDirectory = "C:\LOGS\LGPO"

# If the LGPO directory already exists, delete it first to avoid conflicts
if (Test-Path $lgpoDirectory) {
    Write-Host "Existing LGPO directory found. Removing it to ensure a fresh configuration..." -ForegroundColor Yellow
    Remove-Item -Path $lgpoDirectory -Recurse -Force
    Start-Sleep -Seconds 2  # Give a short delay to ensure deletion is completed
    Write-Host "Old LGPO directory removed successfully." -ForegroundColor Green
}

# Step 1: Ensure C:\LOGS\LGPO exists and set hidden attribute
$lgpoDirectory = "C:\LOGS\LGPO"

if (-not (Test-Path $lgpoDirectory)) {
    New-Item -ItemType Directory -Path $lgpoDirectory -Force | Out-Null
    Write-Host "Created directory: $lgpoDirectory"
}

$lgpoDirAttributes = (Get-Item $lgpoDirectory).Attributes
if (-not ($lgpoDirAttributes -band [System.IO.FileAttributes]::Hidden)) {
    Set-ItemProperty -Path $lgpoDirectory -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
    Write-Host "Set directory to Hidden: $lgpoDirectory"
} else {
    Write-Host "Directory already set to Hidden: $lgpoDirectory"
}

# Step 2: Ensure the Windows Firewall domain log file exists
$firewallLogDir = "$env:SystemRoot\System32\logfiles\firewall"
$domainLogFile = Join-Path $firewallLogDir "domainfw.log"

if (-not (Test-Path $firewallLogDir)) {
    New-Item -ItemType Directory -Path $firewallLogDir -Force | Out-Null
    Write-Host "Created firewall log directory: $firewallLogDir"
}

if (-not (Test-Path $domainLogFile)) {
    New-Item -ItemType File -Path $domainLogFile -Force | Out-Null
    Write-Host "Created firewall log file: $domainLogFile"
} else {
    Write-Host "Firewall log file already exists: $domainLogFile"
}

# Step 3: Export Local Group Policy settings using LGPO.exe and rename the generated GUID folder
Write-Host "Exporting Local Group Policy settings..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/b C:\LOGS\LGPO"

$GUIDFolder = Get-ChildItem -Path $lgpoDirectory | Where-Object { $_.PSIsContainer -and $_.Name -match "^\{.*\}$" } | Select-Object -ExpandProperty FullName
if ($GUIDFolder) {
    $backupFolder = Join-Path $lgpoDirectory "LGPO_Backup"
    Rename-Item -Path $GUIDFolder -NewName $backupFolder -Force
    Write-Host "Renamed $GUIDFolder to $backupFolder"
} else {
    Write-Host "ERROR: No GUID folder found in $lgpoDirectory!" -ForegroundColor Red
    exit 1
}

# Step 4: Parse registry.pol and output the results to a text file in the LGPO_Backup folder
$registryPolPath = "C:\LOGS\LGPO\LGPO_Backup\DomainSysvol\GPO\Machine\registry.pol"
$outputTextFile = "C:\LOGS\LGPO\LGPO_Backup\lgpo.txt"

Write-Host "Parsing registry.pol to create $outputTextFile..."
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/parse /m `"$registryPolPath`"" -RedirectStandardOutput $outputTextFile

if (Test-Path $outputTextFile) {
    Write-Host "Successfully created parsed output at $outputTextFile"
} else {
    Write-Host "ERROR: Parsed output file was not created!" -ForegroundColor Red
    exit 1
}

Write-Host "LGPO backup and parsing completed successfully!"

# Step 5: Update lgpo.txt with the correct Windows Firewall settings
# This step will:
#   1. Read the current lgpo.txt.
#   2. For each required firewall setting, it will:
#       a. Look for a complete “section” (4 lines: "Computer", <Path>, <Key>, <Value>).
#       b. If not found, insert the block (prepending it before the first block).
#       c. If found but the Value doesn’t match, update the Value line.
#       d. Remove duplicate blocks.
#   3. Remove any incomplete blocks.
#   4. Remove a generic Logging block (with "*" and "CREATEKEY") if detailed Logging blocks exist.
#   5. Insert a blank line before every block for easier reading.
#   6. Write the updated content back to lgpo.txt.

$filePath = "C:\LOGS\LGPO\LGPO_Backup\lgpo.txt"

# Read file content as a strongly typed string array
$content = [string[]](Get-Content $filePath)

# Identify the insertion point: the first line that exactly equals "Computer"
$firstComputerLine = $content | Where-Object { $_ -match '^Computer$' } | Select-Object -First 1
$insertionIndex = $content.IndexOf($firstComputerLine)
if ($insertionIndex -lt 0) {
    $insertionIndex = 0
}

# Define desired firewall settings for all profiles.
$desiredSettings = @(
    # Top-level setting
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall"; Key = "PolicyVersion"; Value = "DWORD:542" },
    
    # DomainProfile settings
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile"; Key = "AllowLocalPolicyMerge";       Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile"; Key = "AllowLocalIPsecPolicyMerge";    Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile"; Key = "EnableFirewall";            Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile"; Key = "DefaultOutboundAction";     Value = "DWORD:0" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile"; Key = "DefaultInboundAction";      Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile"; Key = "DisableNotifications";      Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"; Key = "LogFilePath";           Value = "SZ:%SystemRoot%\System32\logfiles\firewall\domainfw.log" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"; Key = "LogFileSize";           Value = "DWORD:16384" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"; Key = "LogDroppedPackets";     Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"; Key = "LogSuccessfulConnections"; Value = "DWORD:1" },
    
    # PrivateProfile settings (same as DomainProfile except for log file name if desired)
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"; Key = "AllowLocalPolicyMerge";       Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"; Key = "AllowLocalIPsecPolicyMerge";    Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"; Key = "EnableFirewall";            Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"; Key = "DefaultOutboundAction";     Value = "DWORD:0" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"; Key = "DefaultInboundAction";      Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"; Key = "DisableNotifications";      Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"; Key = "LogFilePath";           Value = "SZ:%SystemRoot%\System32\logfiles\firewall\privatefw.log" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"; Key = "LogFileSize";           Value = "DWORD:16384" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"; Key = "LogDroppedPackets";     Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"; Key = "LogSuccessfulConnections"; Value = "DWORD:1" },
    
    # PublicProfile settings (merge values set to 0)
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile"; Key = "AllowLocalPolicyMerge";       Value = "DWORD:0" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile"; Key = "AllowLocalIPsecPolicyMerge";    Value = "DWORD:0" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile"; Key = "EnableFirewall";            Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile"; Key = "DefaultOutboundAction";     Value = "DWORD:0" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile"; Key = "DefaultInboundAction";      Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile"; Key = "DisableNotifications";      Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"; Key = "LogFilePath";           Value = "SZ:%SystemRoot%\System32\logfiles\firewall\publicfw.log" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"; Key = "LogFileSize";           Value = "DWORD:16384" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"; Key = "LogDroppedPackets";     Value = "DWORD:1" },
    @{ Path = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"; Key = "LogSuccessfulConnections"; Value = "DWORD:1" }
	
	# Double check the PromptOnSecureDesktop setting and reset to '1'
	@{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Key = "PromptOnSecureDesktop"; Value = "DWORD:1" }
)

# Convert content into a List[string] for easier manipulation
$lines = New-Object System.Collections.Generic.List[string]
$lines.AddRange([string[]]$content)

# Process each desired firewall setting
foreach ($setting in $desiredSettings) {
    # Look for blocks: 4 lines starting with "Computer", then Path, Key, Value.
    $foundIndices = @()
    for ($i = 0; $i -le $lines.Count - 4; $i++) {
        if ($lines[$i] -eq "Computer" -and `
            $lines[$i+1] -eq $setting.Path -and `
            $lines[$i+2] -eq $setting.Key) {
            $foundIndices += $i
        }
    }
    if ($foundIndices.Count -eq 0) {
        # Block not found: insert new block (4 lines) before the first existing block.
        $block = [string[]]("Computer", $setting.Path, $setting.Key, $setting.Value)
        $lines.InsertRange($insertionIndex, [string[]]$block)
        $insertionIndex += $block.Count
    }
    else {
        # Use first occurrence as master block.
        $masterIndex = $foundIndices[0]
        if ($lines[$masterIndex + 3] -ne $setting.Value) {
            $lines[$masterIndex + 3] = $setting.Value
        }
        # Remove duplicate blocks if any.
        if ($foundIndices.Count -gt 1) {
            foreach ($dupIndex in ($foundIndices[1..($foundIndices.Count-1)] | Sort-Object -Descending)) {
                $lines.RemoveRange($dupIndex, 4)
                if ($dupIndex -lt $insertionIndex) {
                    $insertionIndex -= 4
                }
            }
        }
    }
}

# Remove any incomplete blocks.
for ($i = $lines.Count - 4; $i -ge 0; $i--) {
    if ($lines[$i] -eq "Computer") {
        if ( ($i+1) -ge $lines.Count -or [string]::IsNullOrWhiteSpace($lines[$i+1]) -or
             ($i+2) -ge $lines.Count -or [string]::IsNullOrWhiteSpace($lines[$i+2]) -or
             ($i+3) -ge $lines.Count -or [string]::IsNullOrWhiteSpace($lines[$i+3]) ) {
            $lines.RemoveRange($i, $lines.Count - $i)
        }
    }
}

# Remove generic Logging block if detailed Logging blocks exist.
# This removes a block that looks like:
#   Computer
#   Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging
#   *
#   CREATEKEY
for ($i = $lines.Count - 4; $i -ge 0; $i--) {
    if ($lines[$i] -eq "Computer" -and `
        $lines[$i+1] -eq "Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -and `
        $lines[$i+2] -eq "*" -and `
        $lines[$i+3] -eq "CREATEKEY") {
        $lines.RemoveRange($i, 4)
    }
}

# Insert a blank line before every block that starts with "Computer"
# (except if it's the first line or already preceded by a blank line)
for ($i = $lines.Count - 1; $i -ge 1; $i--) {
    if ($lines[$i] -eq "Computer" -and $lines[$i-1] -ne "") {
        $lines.Insert($i, "")
    }
}

# Write the updated lines back to the file.
$lines | Set-Content $filePath -Encoding UTF8
Write-Host "Firewall settings in lgpo.txt have been updated successfully!"

# Step 6: Apply the updated LGPO settings from the modified text file to the local Group Policy
Write-Host "Applying modified LGPO settings from text file..."
# $filePath points to the modified text file (lgpo.txt)
Start-Process -NoNewWindow -Wait -FilePath "LGPO.exe" -ArgumentList "/t `"$filePath`""
Write-Host "Modified LGPO settings have been applied to the active Group Policy." -ForegroundColor Green

# Step 7: (Optional) Back up the updated registry.pol file
# This copies the active registry.pol (now updated) into your backup folder,
# so your backup reflects the new settings.
Write-Host "Backing up updated registry.pol file..."
Copy-Item -Path "C:\Windows\System32\GroupPolicy\Machine\registry.pol" `
          -Destination "C:\LOGS\LGPO\LGPO_Backup\DomainSysvol\GPO\Machine\registry.pol" -Force
Write-Host "Backup of registry.pol completed."

# Step 8: Force Group Policy update so the new settings take effect
Write-Host "Forcing Group Policy update..."
gpupdate /force
Write-Host "Local Group Policy settings have been successfully applied!" -ForegroundColor Green

#######################################################################################################################

# From here to Windows Firewall TESTED GOOD
# CIS Benchmark 1.1 Password Policy
Write-Host "Configuring Password Policy..."

# CIS Benchmark 1.1.1 - Enforce password history
Write-Host "Setting 'Enforce password history' to 24 passwords..."
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 24" | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /quiet
Remove-Item C:\secpol.cfg -Force

# CIS Benchmark 1.1.2 - Maximum password age
Write-Host "Setting 'Maximum password age' to 365 days..."
net accounts /MAXPWAGE:365

# CIS Benchmark 1.1.3 - Minimum password age
Write-Host "Setting 'Minimum password age' to 1 day..."
net accounts /MINPWAGE:1

# CIS Benchmark 1.1.4 - Minimum password length
Write-Host "Setting 'Minimum password length' to 14 characters..."
net accounts /MINPWLEN:14

# CIS Benchmark 1.1.5 - Password must meet complexity requirements
Write-Host "Enabling 'Password must meet complexity requirements'..."
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace "PasswordComplexity = \d+", "PasswordComplexity = 1" | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /quiet
Remove-Item C:\secpol.cfg -Force

# CIS Benchmark 1.1.6 - Relax minimum password length limits
Write-Host "Configuring 'Relax minimum password length limits'..."
$samPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SAM"
Set-ItemProperty -Path $samPath -Name "RelaxMinimumPasswordLengthLimits" -Value 1 -Type DWord -Force
Write-Host "Registry updated: RelaxMinimumPasswordLengthLimits = 1"

# CIS Benchmark 1.1.7 - Store passwords using reversible encryption (Disabled)
Write-Host "Disabling 'Store passwords using reversible encryption'..."
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace "ClearTextPassword = \d+", "ClearTextPassword = 0" | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /quiet
Remove-Item C:\secpol.cfg -Force

Write-Host "Password policy configuration completed successfully!" -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

##################################################################################################################

# CIS Benchmark 1.2 - Account Lockout Policy
Write-Host "Configuring Account Lockout Policy..."

# CIS Benchmark 1.2.1 - Account lockout duration
Write-Host "Setting 'Account lockout duration' to 15 minutes..."
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace "LockoutDuration = \d+", "LockoutDuration = 15" | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /quiet
Remove-Item C:\secpol.cfg -Force

# CIS Benchmark 1.2.2 - Account lockout threshold
Write-Host "Setting 'Account lockout threshold' to 5 invalid logon attempts..."
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace "LockoutBadCount = \d+", "LockoutBadCount = 5" | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /quiet
Remove-Item C:\secpol.cfg -Force

# CIS Benchmark 1.2.3 - Allow Administrator account lockout (manual configuration required)
Write-Host "'Allow Administrator account lockout' requires manual configuration."

# CIS Benchmark 1.2.4 - Reset account lockout counter after
Write-Host "Setting 'Reset account lockout counter after' to 15 minutes..."
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace "ResetLockoutCount = \d+", "ResetLockoutCount = 15" | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /quiet
Remove-Item C:\secpol.cfg -Force

Write-Host "Account lockout policy configuration completed."

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

########################################################################################################
<#
# CIS Benchmark 2 - Local Policies Configuration
Write-Host "Configuring Local Policies..."

# Define temporary policy file paths
$secpolCfg = "$env:TEMP\secpol.cfg"
$secpolDb = "C:\Windows\security\local.sdb"

# Predefined Standard SIDs for Windows 10 & 11
$AccountSIDs = @{
    "Administrators"         = "*S-1-5-32-544"
    "Users"                  = "*S-1-5-32-545"
    "Guests"                 = "*S-1-5-32-546"
    "LOCAL SERVICE"          = "*S-1-5-19"
    "NETWORK SERVICE"        = "*S-1-5-20"
    "SERVICE"                = "*S-1-5-6"
    "Remote Desktop Users"   = "*S-1-5-32-555"
    "Local account"          = "*S-1-5-113"
    "Window Manager\Window Manager Group" = "*S-1-5-90-0"
    "NT SERVICE\WdiServiceHost" = "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
}

# Function to update security policy settings (using secedit)
function Update-SecurityPolicy {
    param (
        [string]$SettingName,  # Security right name (e.g., SeNetworkLogonRight)
        [array]$Accounts       # Array of account names (as keys in $AccountSIDs)
    )
    
    Write-Host "Updating '$SettingName'..."

    # Export current security policy to a temporary config file
    secedit /export /cfg $secpolCfg /quiet
    if (-Not (Test-Path $secpolCfg)) {
        Write-Host "Error: Security policy export failed. Check permissions." -ForegroundColor Red
        return
    }

    # Read the exported security policy file
    $secpolContent = Get-Content $secpolCfg

    # Resolve the account names to SIDs
    $ResolvedSIDs = @()
    foreach ($Account in $Accounts) {
        if ($AccountSIDs.ContainsKey($Account)) {
            $ResolvedSIDs += $AccountSIDs[$Account]
        } else {
            Write-Host "Warning: Account '$Account' not found in predefined SID list." -ForegroundColor Yellow
        }
    }
    
    # Handle case when no valid accounts are provided
    $NewValue = if ($ResolvedSIDs.Count -eq 0) { "*" } else { $ResolvedSIDs -join "," }
    
    # Update or add the setting in the configuration file
    if ($secpolContent -match "$SettingName =.*") {
        $secpolContent = $secpolContent -replace "$SettingName =.*", "$SettingName = $NewValue"
    } else {
        $secpolContent += "`n$SettingName = $NewValue"
    }
    
    # Save the updated configuration (using Unicode encoding)
    $secpolContent | Set-Content $secpolCfg -Encoding Unicode

    # Apply the updated security policy
    secedit /configure /db $secpolDb /cfg $secpolCfg /quiet

    # Cleanup temporary file
    Remove-Item $secpolCfg -Force
    Write-Host "'$SettingName' updated successfully!" -ForegroundColor Green
}

# Update the settings as recommended by the CIS benchmarks:

# 2.2.1 - Access Credential Manager as a trusted caller - No One
Update-SecurityPolicy -SettingName "SeTrustedCredManAccessPrivilege" -Accounts @()

# 2.2.2 Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'
Update-SecurityPolicy -SettingName "SeNetworkLogonRight" -Accounts @("Administrators", "Remote Desktop Users")

# 2.2.3 - Act as part of the operating system - No One
Update-SecurityPolicy -SettingName "SeTcbPrivilege" -Accounts @()

# 2.2.4 - Adjust memory quotas for a process - Administrators, LOCAL SERVICE, NETWORK SERVICE
Update-SecurityPolicy -SettingName "SeIncreaseQuotaPrivilege" -Accounts @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE")

# 2.2.5 Ensure 'Allow log on locally' is set to 'Administrators, Users'
Update-SecurityPolicy -SettingName "SeInteractiveLogonRight" -Accounts @("Administrators", "Users")

# 2.2.6 - Allow log on through Remote Desktop Services - Administrators, Remote Desktop Users
Update-SecurityPolicy -SettingName "SeRemoteInteractiveLogonRight" -Accounts @("Administrators", "Remote Desktop Users")

# 2.2.7 Ensure 'Back up files and directories' is set to 'Administrators'
Update-SecurityPolicy -SettingName "SeBackupPrivilege" -Accounts @("Administrators")

# 2.2.8 - Change the system time - Administrators, LOCAL SERVICE
Update-SecurityPolicy -SettingName "SeSystemtimePrivilege" -Accounts @("Administrators", "LOCAL SERVICE")

# 2.2.9 - Change the time zone - Administrators, LOCAL SERVICE, Users
Update-SecurityPolicy -SettingName "SeTimeZonePrivilege" -Accounts @("Administrators", "LOCAL SERVICE", "Users")

# 2.2.10 - Create a pagefile - Administrators
Update-SecurityPolicy -SettingName "SeCreatePagefilePrivilege" -Accounts @("Administrators")

# 2.2.11 - Create a token object - No One
Update-SecurityPolicy -SettingName "SeCreateTokenPrivilege" -Accounts @()

# 2.2.12 - Create global objects - Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
Update-SecurityPolicy -SettingName "SeCreateGlobalPrivilege" -Accounts @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")

# 2.2.13 - Create permanent shared objects - No One
Update-SecurityPolicy -SettingName "SeCreatePermanentPrivilege" -Accounts @()

# 2.2.14 - Create symbolic links - Administrators
Update-SecurityPolicy -SettingName "SeCreateSymbolicLinkPrivilege" -Accounts @("Administrators")

# 2.2.15 - Debug programs - Administrators
Update-SecurityPolicy -SettingName "SeDebugPrivilege" -Accounts @("Administrators")

# 2.2.16 Ensure 'Deny access to this computer from the network' includes 'Guests, Local account'
Update-SecurityPolicy -SettingName "SeDenyNetworkLogonRight" -Accounts @("Guests", "Local account")

# 2.2.17 - Deny log on as a batch job - Guests
Update-SecurityPolicy -SettingName "SeDenyBatchLogonRight" -Accounts @("Guests")

# 2.2.18 - Deny log on as a service - Guests
Update-SecurityPolicy -SettingName "SeDenyServiceLogonRight" -Accounts @("Guests")

# 2.2.19 Ensure 'Deny log on locally' includes 'Guests'
Update-SecurityPolicy -SettingName "SeDenyInteractiveLogonRight" -Accounts @("Guests")

# 2.2.20 - Deny log on through Remote Desktop Services - Guests, Local account
Update-SecurityPolicy -SettingName "SeDenyRemoteInteractiveLogonRight" -Accounts @("Guests", "Local account")

# 2.2.21 - Enable computer and user accounts to be trusted for delegation - No One
Update-SecurityPolicy -SettingName "SeEnableDelegationPrivilege" -Accounts @()

# 2.2.22 - Force shutdown from a remote system - Administrators
Update-SecurityPolicy -SettingName "SeRemoteShutdownPrivilege" -Accounts @("Administrators")

# 2.2.23 - Generate security audits - LOCAL SERVICE, NETWORK SERVICE
Update-SecurityPolicy -SettingName "SeAuditPrivilege" -Accounts @("LOCAL SERVICE", "NETWORK SERVICE")

# 2.2.24 Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
Update-SecurityPolicy -SettingName "SeImpersonatePrivilege" -Accounts @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")

# 2.2.25 - Increase scheduling priority - Administrators, Window Manager\Window Manager Group
Update-SecurityPolicy -SettingName "SeIncreaseBasePriorityPrivilege" -Accounts @("Administrators", "Window Manager\Window Manager Group")

# 2.2.26 - Load and unload device drivers - Administrators
Update-SecurityPolicy -SettingName "SeLoadDriverPrivilege" -Accounts @("Administrators")

# 2.2.27 - Lock pages in memory - No One
Update-SecurityPolicy -SettingName "SeLockMemoryPrivilege" -Accounts @()

# 2.2.28 - Log on as a batch job - Administrators
Update-SecurityPolicy -SettingName "SeBatchLogonRight" -Accounts @("Administrators")

# 2.2.29 - Log on as a service - (Defined per environment - add manually if required)

# 2.2.30 - Manage auditing and security log - Administrators
Update-SecurityPolicy -SettingName "SeSecurityPrivilege" -Accounts @("Administrators")

# 2.2.31 - Modify an object label - No One
Update-SecurityPolicy -SettingName "SeRelabelPrivilege" -Accounts @()

# 2.2.32 - Modify firmware environment values - Administrators
Update-SecurityPolicy -SettingName "SeSystemEnvironmentPrivilege" -Accounts @("Administrators")

# 2.2.33 - Perform volume maintenance tasks - Administrators
Update-SecurityPolicy -SettingName "SeManageVolumePrivilege" -Accounts @("Administrators")

# 2.2.34 - Profile single process - Administrators
Update-SecurityPolicy -SettingName "SeProfileSingleProcessPrivilege" -Accounts @("Administrators")

# 2.2.35 - Profile system performance - Administrators, NT SERVICE\WdiServiceHost
Update-SecurityPolicy -SettingName "SeSystemProfilePrivilege" -Accounts @("Administrators", "NT SERVICE\WdiServiceHost")

# 2.2.36 - Replace a process level token - LOCAL SERVICE, NETWORK SERVICE
Update-SecurityPolicy -SettingName "SeAssignPrimaryTokenPrivilege" -Accounts @("LOCAL SERVICE", "NETWORK SERVICE")

# 2.2.37 Ensure 'Restore files and directories' is set to 'Administrators'
Update-SecurityPolicy -SettingName "SeRestorePrivilege" -Accounts @("Administrators")

# 2.2.38 Ensure 'Shut down the system' is set to 'Administrators, Users'
Update-SecurityPolicy -SettingName "SeShutdownPrivilege" -Accounts @("Administrators", "Users")

# 2.2.39 - Take ownership of files or other objects - Administrators
Update-SecurityPolicy -SettingName "SeTakeOwnershipPrivilege" -Accounts @("Administrators")

Write-Host "Security policy update process is complete!" -ForegroundColor Green

# Force a Group Policy update to ensure changes take effect
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Group Policy update complete." -ForegroundColor Cyan
#>
#############################################################################################################

# ==============================
# CIS Benchmark - User Rights Assignment & Registry Hardening
# ==============================

# Define file paths
$SecPolPath       = "C:\LOGS\Scripts\secpol.cfg"
$SecPolTextPath   = "C:\LOGS\Scripts\secpol.txt"
$SecPolDb         = "C:\Windows\security\local.sdb"
$DeploySecPolPath = "C:\Program Files (x86)\ossec-agent\secpol.txt" # this was meant for testing out with my deployagent script

# Ensure the export directory exists
if (-Not (Test-Path "C:\LOGS\Scripts")) {
    New-Item -ItemType Directory -Path "C:\LOGS\Scripts" -Force | Out-Null
}

# Step 1: Export current security policy
Write-Host "Exporting current security policy..."
secedit /export /cfg $SecPolPath /quiet

# Verify export
if (!(Test-Path $SecPolPath)) {
    Write-Error "Exported secpol.cfg not found. Export may have failed."
    exit 1
}

# Rename the exported file to .txt for processing
try {
    Move-Item -Path $SecPolPath -Destination $SecPolTextPath -Force
    Write-Host "Renamed exported file to: $SecPolTextPath"
}
catch {
    Write-Error "Failed to rename exported file: $($_.Exception.Message)"
    exit 1
}

# Read the policy file content as an array of lines
$SecPolContent = Get-Content $SecPolTextPath

# Step 2: Define required Privilege Rights block (CIS benchmark settings)
$CIS_PrivilegeRights = @"
[Privilege Rights]
SeMachineAccountPrivilege = *S-1-5-32-544
SeTrustedCredManAccessPrivilege = 
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeTcbPrivilege = 
SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeBackupPrivilege = *S-1-5-32-544
SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19
SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-32-545
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateTokenPrivilege = 
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeCreatePermanentPrivilege = 
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-113
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113
SeEnableDelegationPrivilege = 
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeLoadDriverPrivilege = *S-1-5-32-544
SeLockMemoryPrivilege = 
SeBatchLogonRight = *S-1-5-32-544
SeSecurityPrivilege = *S-1-5-32-544
SeRelabelPrivilege = 
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeTakeOwnershipPrivilege = *S-1-5-32-544
"@

# Step 3: Replace or append [Privilege Rights] section
$sectionIndex = $SecPolContent.IndexOf("[Privilege Rights]")
if ($sectionIndex -ge 0) {
    $nextSectionLine = ($SecPolContent | Select-String "^\[" | Where-Object { $_.LineNumber -gt ($sectionIndex + 1) } | Select-Object -First 1).LineNumber
    if ($nextSectionLine) {
        $SecPolContent = $SecPolContent[0..($sectionIndex - 1)] + ($CIS_PrivilegeRights -split "`r`n") + $SecPolContent[$nextSectionLine..($SecPolContent.Count - 1)]
    } else {
        $SecPolContent = $SecPolContent[0..($sectionIndex - 1)] + ($CIS_PrivilegeRights -split "`r`n")
    }
} else {
    $SecPolContent += "`r`n$CIS_PrivilegeRights"
}

# Step 4: Save the updated policy file (UTF-8 with BOM)
$SecPolContentString = $SecPolContent -join "`r`n"
$utf8WithBom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($SecPolTextPath, $SecPolContentString, $utf8WithBom)
Write-Host "Updated policy file saved: $SecPolTextPath"

<#
# Step 5: Overwrite deployment file
try {
    Copy-Item -Path $SecPolTextPath -Destination $DeploySecPolPath -Force
    Write-Host "Deployment file updated: $DeploySecPolPath"
}
catch {
    Write-Error "Failed to update deployment file: $($_.Exception.Message)"
    exit 1
}
#>

# Step 5: Overwrite deployment file only if Wazuh agent path exists
$deployDir = "C:\Program Files (x86)\ossec-agent"
if (Test-Path $deployDir) {
    try {
        Copy-Item -Path $SecPolTextPath -Destination $DeploySecPolPath -Force
        Write-Host "Deployment file updated: $DeploySecPolPath"
    }
    catch {
        Write-Error "Failed to update deployment file: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "Wazuh agent not installed. Skipping deployment copy to $DeploySecPolPath"
}

# Step 6: Rename modified .txt back to .cfg for policy application
try {
    Rename-Item -Path $SecPolTextPath -NewName $SecPolPath -Force
    Write-Host "Renamed processed file back to: $SecPolPath"
}
catch {
    Write-Error "Failed to rename processed file: $($_.Exception.Message)"
    exit 1
}

# Step 7: Apply updated security policy
Write-Host "Applying updated security policy..."
secedit /configure /db $SecPolDb /cfg $SecPolPath /quiet

# Wait for changes to take effect
Start-Sleep -Seconds 3

# Step 8: Cleanup - REMOVE ONLY the .cfg (keep .txt for inspection)
try {
    Remove-Item -Path $SecPolPath -Force
    Write-Host "Cleanup complete: secpol.cfg removed (secpol.txt retained for review)"
}
catch {
    Write-Warning "Cleanup failed (secpol.cfg): $($_.Exception.Message)"
}

# Apply GP update
gpupdate /force
Write-Host "Security policy applied successfully!" -ForegroundColor Green

####################################################################################################################

# CIS Benchmark 2.3 Security Options
Write-Host "Configuring Security Options..."

# CIS Benchmark 2.3.1 Accounts
Write-Host "Configuring Accounts settings..."

# CIS Benchmark 2.3.1.1 - Accounts: Block Microsoft accounts
Write-Host "Setting 'Accounts: Block Microsoft accounts' to 'Users can't add or log on with Microsoft accounts'..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3

# CIS Benchmark 2.3.1.2 - Accounts: Guest account status
Write-Host "Disabling 'Guest account status'..."
net user Guest /active:no

# CIS Benchmark 2.3.1.2.1 - Accounts: Administrator account Status
Write-Host "Disabling 'Administrator account status'..."
net user Administrator /active:no

# CIS Benchmark 2.3.1.3 - Accounts: Limit local account use of blank passwords to console logon only
Write-Host "Ensuring 'Limit local account use of blank passwords to console logon only' is enabled..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# !!! These you should choose your own custom name for both administrator and guest accounts !!!
# CIS Benchmark 2.3.1.4 - Accounts: Rename administrator account
Write-Host "Renaming 'Administrator' account to 'Renamed-Admin' and setting a secure password..." # <-- Change Here

# Generate a secure password
$adminPassword = -join ((33..126) | Get-Random -Count 25 | ForEach-Object {[char]$_})
$secureAdminPassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force

# Export security settings
secedit /export /cfg C:\Windows\Temp\secpol.cfg /quiet

# Update administrator account rename setting
((Get-Content C:\Windows\Temp\secpol.cfg) -replace 'NewAdministratorName =.*', 'NewAdministratorName = Renamed-Admin') | Set-Content C:\Windows\Temp\secpol.cfg # <-- Change Here

# Apply the new security policy
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\secpol.cfg /quiet

# Set the password for the new Administrator account
net user Renamed-Admin $adminPassword # <-- Change Here

Write-Host "Administrator account renamed to 'Renamed-Admin' and secured." # <-- Change Here

# CIS Benchmark 2.3.1.5 - Accounts: Rename guest account
Write-Host "Renaming 'Guest' account to 'Renamed-Guest' and setting a secure password..." # <-- Change Here

# Generate a secure password for Guest
$guestPassword = -join ((33..126) | Get-Random -Count 25 | ForEach-Object {[char]$_})
$secureGuestPassword = ConvertTo-SecureString $guestPassword -AsPlainText -Force

# Update guest account rename setting
((Get-Content C:\Windows\Temp\secpol.cfg) -replace 'NewGuestName =.*', 'NewGuestName = Renamed-Guest') | Set-Content C:\Windows\Temp\secpol.cfg # <-- Change Here

# Apply the updated policy
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\secpol.cfg /quiet

# Set the password for the new Guest account
net user Renamed-Guest $guestPassword # <-- Change Here

Write-Host "Guest account renamed to 'Renamed-Guest' and secured." # <-- Change Here

####################################################################################################################

# CIS Benchmark 2.3.2 Audit
Write-Host "Configuring Audit settings..."

# CIS Benchmark 2.3.2.1 - Audit: Force audit policy subcategory settings
Write-Host "Setting 'Audit: Force audit policy subcategory settings' to 'Enabled'..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1

# CIS Benchmark 2.3.2.2 - Audit: Shut down system immediately if unable to log security audits
Write-Host "Disabling 'Shut down system immediately if unable to log security audits'..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -Value 0

####################################################################################################################

# CIS Benchmark - Ensure 'Point and Print Restrictions: Users can only point and print to machines in their forest' is set to 'Enabled'

# Define the registry path and value name
$registryPath = "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
$valueName = "AddPrinterDrivers"
$expectedValue = 1

# Check if the registry path exists
if (-not (Test-Path $registryPath)) {
    Write-Host "Registry path does not exist. Creating path: $registryPath"
    New-Item -Path $registryPath -Force | Out-Null
}

# Get the current value of AddPrinterDrivers
$currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

# If the value does not exist or is incorrect, set it
if ($null -eq $currentValue -or $currentValue -ne $expectedValue) {
    Write-Host "Updating $valueName to $expectedValue at $registryPath"
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $expectedValue -Type DWord -Force
} else {
    Write-Host "$valueName is already set to $expectedValue. No changes needed."
}

####################################################################################################################

#
# CIS Benchmark 2.3.6 - Domain Member Policies
Write-Host "Configuring Domain Member Policies..." -ForegroundColor Cyan

# Define registry path
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    Write-Host "Creating missing registry path: $regPath" -ForegroundColor Yellow
    New-Item -Path $regPath -Force | Out-Null
}

# Define required settings in a hashtable
$domainMemberSettings = @{
    "RequireSignOrSeal"     = 1  # CIS Benchmark 2.3.6.1
    "SealSecureChannel"     = 1  # CIS Benchmark 2.3.6.2
    "SignSecureChannel"     = 1  # CIS Benchmark 2.3.6.3
    "DisablePasswordChange" = 0  # CIS Benchmark 2.3.6.4
    "MaximumPasswordAge"    = 30 # CIS Benchmark 2.3.6.5
    "RequireStrongKey"      = 1  # CIS Benchmark 2.3.6.6
}

# Loop through settings and apply only if needed
foreach ($setting in $domainMemberSettings.Keys) {
    $expectedValue = $domainMemberSettings[$setting]
    $currentValue = (Get-ItemProperty -Path $regPath -Name $setting -ErrorAction SilentlyContinue).$setting

    if ($currentValue -ne $expectedValue) {
        Write-Host "Updating '$setting' to $expectedValue..."
        Set-ItemProperty -Path $regPath -Name $setting -Value $expectedValue -Type DWord -Force
    } else {
        Write-Host "'$setting' is already set to $expectedValue. Skipping..." -ForegroundColor Green
    }
}

Write-Host "Domain Member Policies successfully configured!" -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan
#>
#################################################################################################################

# CIS Benchmark - 2.3.7.1 - 2.3.7.9
Write-Host "Starting configurations for Interactive Logon - CIS Benchmark 2.3.7.1 - 2.3.7.9"

# Define security policy export path
$secpolPath = "C:\LOGS\Scripts\secpol.cfg"
$secpolTxtPath = $secpolPath -replace '\.cfg$', '.txt'

# Ensure directory exists
if (-Not (Test-Path "C:\LOGS\Scripts")) {
    New-Item -ItemType Directory -Path "C:\LOGS\Scripts" -Force | Out-Null
}

# ==============================
# Step 1: Apply & Verify Registry Settings Before Moving to Secedit
# ==============================

# Interactive Logon Registry Settings
$logonSettings = @(
    @{ Name = "DisableCAD"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = 0; Type = "DWord" }
    @{ Name = "DontDisplayLastUserName"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = 1; Type = "DWord" }
    @{ Name = "InactivityTimeoutSecs"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = 900; Type = "DWord" }
    @{ Name = "ScRemoveOption"; Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value = 1; Type = "String"; Enforce = $true }
    @{ Name = "PromptOnSecureDesktop"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = 14; Type = "DWord" }
	@{ Name = "MaxDevicePasswordFailedAttempts"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = 10; Type = "DWord" }
)

# Windows 11-Only Settings
if ($isWindows11) {
    $logonSettings += @(
        @{ Name = "CachedLogonsCount"; Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value = "4"; Type = "String" }
        @{ Name = "MaxCachedLogonCount"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Value = 10; Type = "DWord" }
    )
}

# Fixing Legal Notice Text & Caption (Explicitly Required)
$logonMessageText = "Unauthorized access is prohibited. By logging in, you agree to company policies."
$logonMessageTitle = "Security Notice"

$logonSettings += @(
    @{ Name = "legalnoticetext"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = $logonMessageText; Type = "String" }
    @{ Name = "legalnoticecaption"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Value = $logonMessageTitle; Type = "String" }
)

# Apply Interactive Logon Registry Settings
Write-Host "Applying Interactive Logon registry settings..."
foreach ($setting in $logonSettings) {
    # Ensure registry path exists
    if (-not (Test-Path $setting.Path)) {
        Write-Host "Creating registry path: $($setting.Path)"
        New-Item -Path $setting.Path -Force | Out-Null
    }
    # Apply the setting
    Write-Host "Setting $($setting.Name) to $($setting.Value)..."
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
}

# ==============================
# Step 1b: Apply Machine Account Lockout Threshold
# ==============================
$lockoutPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$lockoutName = "MaxDevicePasswordFailedAttempts"
$expectedLockoutValue = 10  # Recommended: 10 or fewer invalid logon attempts, but not 0

Write-Host "Applying Machine Account Lockout Threshold..."
if (-not (Test-Path $lockoutPath)) {
    Write-Host "Creating registry path: $lockoutPath"
    New-Item -Path $lockoutPath -Force | Out-Null
}

$currentLockoutValue = (Get-ItemProperty -Path $lockoutPath -Name $lockoutName -ErrorAction SilentlyContinue).$lockoutName

if ($null -eq $currentLockoutValue -or $currentLockoutValue -eq 0 -or $currentLockoutValue -gt 30) {
    Write-Host "Setting $lockoutName to $expectedLockoutValue..."
    Set-ItemProperty -Path $lockoutPath -Name $lockoutName -Value $expectedLockoutValue -Type DWord -Force
} else {
    Write-Host "$lockoutName is already set to $currentLockoutValue. No changes needed."
}

# ==============================
# Step 2: Verify Registry Settings Before Secedit
# ==============================

Write-Host "Verifying registry settings before proceeding..."
foreach ($setting in $logonSettings) {
    $regValue = (Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue).$($setting.Name)
    if ($regValue -eq $setting.Value) {
        Write-Host "Verified: $($setting.Name) is correctly set to $($setting.Value)" -ForegroundColor Green
    } else {
        Write-Host "WARNING: $($setting.Name) is incorrect! Expected: $($setting.Value), Found: $regValue" -ForegroundColor Red
    }
}

# Verify Machine Account Lockout Threshold
$verifiedLockoutValue = (Get-ItemProperty -Path $lockoutPath -Name $lockoutName -ErrorAction SilentlyContinue).$lockoutName
if ($verifiedLockoutValue -eq $expectedLockoutValue) {
    Write-Host "Verified: $lockoutName is correctly set to $expectedLockoutValue" -ForegroundColor Green
} else {
    Write-Host "WARNING: $lockoutName is incorrect! Expected: $expectedLockoutValue, Found: $verifiedLockoutValue" -ForegroundColor Red
}

# Apply registry modifications before moving to secpol settings
Write-Host "Updating Group Policy..."
gpupdate /force

# ==============================
# Step 3: Iterate Through Benchmarks - Export, Modify, and Apply secpol.cfg
# ==============================

# Define the security benchmarks to check in secpol.cfg
$secpolBenchmarks = @(
    @{ Path = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext"; Value = "7,$logonMessageText" }
    @{ Path = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticecaption"; Value = "1,$logonMessageTitle" }
    @{ Path = "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption"; Value = "1,1" }
	@{ Path = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts"; Value = "4,10" }
)

foreach ($benchmark in $secpolBenchmarks) {
    Write-Host "Processing benchmark: $($benchmark.Path)"

    # (A) Export current security policies
    Write-Host "Exporting current security policies..."
    secedit /export /cfg $secpolPath /quiet

    if (!(Test-Path $secpolPath)) {
        Write-Host "ERROR: Failed to export security policy!" -ForegroundColor Red
        continue
    }
    Write-Host "Exported secpol.cfg: $secpolPath"

    # (B) Rename .cfg to .txt for modification
    if (Test-Path $secpolTxtPath) { Remove-Item -Path $secpolTxtPath -Force }
    Rename-Item -Path $secpolPath -NewName $secpolTxtPath -Force
    Write-Host "Renamed secpol.cfg to secpol.txt: $secpolTxtPath"

    # (C) Modify secpol.txt (Ensure benchmark is correctly set)
    $secpolContent = Get-Content $secpolTxtPath
    $benchmarkPath = [regex]::Escape($benchmark.Path) # Properly escape for regex
    $benchmarkValue = $benchmark.Value

    # Check if the path exists in the [Registry Values] section
    if ($secpolContent -match "^$benchmarkPath\s*=") {
        # Path exists, check the value
        $currentValue = $null  # Default to null in case the match fails
        foreach ($line in $secpolContent) {
            if ($line -match "^$benchmarkPath\s*=\s*""?(.+?)""?$") {
                $currentValue = $matches[1] -replace '"', ''  # Remove all extra quotes added by secedit
                break
            }
        }

        # Normalize benchmark values by stripping quotes for accurate comparison
        $normalizedBenchmarkValue = $benchmark.Value -replace '"', ''

        if ($currentValue -eq $normalizedBenchmarkValue) {
            Write-Host "Verified: $benchmarkPath is correctly set." -ForegroundColor Green
        } else {
            Write-Host "Updating: $benchmarkPath (Old Value: $currentValue, New Value: $normalizedBenchmarkValue)"

            # Ensure proper value formatting before replacing in secpol.cfg
            $correctedValue = if ($normalizedBenchmarkValue -match '^\d+,') { $normalizedBenchmarkValue } else { "1,$normalizedBenchmarkValue" }

            $secpolContent = $secpolContent -replace "^$benchmarkPath\s*=\s*.+$", "$benchmarkPath=$correctedValue"
        }

    } else {
        # Path does not exist, append it to [Registry Values]
        Write-Host "Appending missing entry: $benchmarkPath=$benchmarkValue"

        # Ensure correct value formatting before appending
        $correctedValue = if ($benchmarkValue -match '^\d+,') { $benchmarkValue } else { "1,$benchmarkValue" }

        $secpolContent += "`r`n$benchmarkPath=$correctedValue"
    }

    # (D) Save the modified secpol.txt
    Set-Content -Path $secpolTxtPath -Value $secpolContent
    Write-Host "Saved modified secpol.txt"

    # (E) Rename .txt back to .cfg
    if (Test-Path $secpolPath) { Remove-Item -Path $secpolPath -Force }
    Rename-Item -Path $secpolTxtPath -NewName $secpolPath -Force
    Write-Host "Renamed secpol.txt to secpol.cfg: $secpolPath"

    # (F) Apply the updated security policy
    Write-Host "Applying updated security policies..."
    secedit /configure /db c:\windows\security\local.sdb /cfg $secpolPath /quiet

    # (G) Wait 5 seconds
    Start-Sleep -Seconds 5

    # (H) Delete secpol.cfg
    Remove-Item -Path $secpolPath -Force
    Write-Host "Cleanup complete. Proceeding to next benchmark..."
}

# ==============================
# Step 4: Final Verification & Policy Update
# ==============================

# Run final gpupdate
Write-Host "Applying Group Policy updates..."
gpupdate /force

# Perform final secpol export for verification
Write-Host "Final security policy verification..."
secedit /export /cfg $secpolPath /quiet

if (!(Test-Path $secpolPath)) {
    Write-Host "ERROR: Failed to export final security policy!" -ForegroundColor Red
    exit 1
}

# Read the final exported secpol.cfg
$finalSecpolContent = Get-Content $secpolPath

foreach ($benchmark in $secpolBenchmarks) {
    # Normalize benchmark values by stripping quotes for accurate comparison
    $normalizedBenchmarkValue = $benchmark.Value -replace '"', ''

    # Extract the value from secpol.cfg, strip quotes, and compare
    $matchedValue = $null
    foreach ($line in $finalSecpolContent) {
        if ($line -match "^$([regex]::Escape($benchmark.Path))\s*=\s*""?(.+?)""?$") {
            $matchedValue = $matches[1] -replace '"', ''  # Remove quotes
            break
        }
    }

    if ($matchedValue -eq $normalizedBenchmarkValue) {
        Write-Host "Final Verification: $($benchmark.Path) is correctly set." -ForegroundColor Green
    } else {
        Write-Host "WARNING: $($benchmark.Path) is missing or incorrect in secpol.cfg!" -ForegroundColor Red
    }
}

# Cleanup final exported secpol.cfg
Remove-Item -Path $secpolPath -Force

Write-Host "Interactive logon security settings applied and verified successfully!" -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

###########################################################################################################################
#
# ==============================
# CIS Benchmark 2.3.8 - Microsoft Network Client
# ==============================

Write-Host "Configuring Microsoft network client settings..."

# Define registry settings
$networkClientSettings = @(
    @{ Name = "RequireSecuritySignature"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Value = 1; Description = "Microsoft network client: Digitally sign communications (always)" }
    @{ Name = "EnableSecuritySignature"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Value = 1; Description = "Microsoft network client: Digitally sign communications (if server agrees)" } # Uncomment if needed
    @{ Name = "EnablePlainTextPassword"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Value = 0; Description = "Microsoft network client: Send unencrypted password to third-party SMB servers" }
)

# Apply settings
foreach ($setting in $networkClientSettings) {
    Write-Host "Applying: $($setting.Description)..."

    # Ensure registry path exists
    if (-not (Test-Path $setting.Path)) {
        Write-Host "Creating registry path: $($setting.Path)"
        New-Item -Path $setting.Path -Force | Out-Null
    }

    # Apply registry setting
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force

    # Verify setting
    $currentValue = (Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue).$($setting.Name)
    if ($currentValue -eq $setting.Value) {
        Write-Host "Verified: $($setting.Description) is correctly set to $($setting.Value)" -ForegroundColor Green
    } else {
        Write-Host "WARNING: $($setting.Description) is incorrect! Expected: $($setting.Value), Found: $currentValue" -ForegroundColor Red
    }
}

Write-Host "Microsoft network client settings have been configured successfully!" -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

##########################################################################################################

# ==============================
# CIS Benchmark 2.3.9 - Microsoft Network Server
# ==============================

Write-Host "Configuring Microsoft Network Server settings..."

# Define registry settings
$networkServerSettings = @(
    @{ Name = "AutoDisconnect"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = 15; Description = "Microsoft network server: Amount of idle time required before suspending session" }
    @{ Name = "EnableSecuritySignature"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = 1; Description = "Microsoft network server: Digitally sign communications (always)" }
    @{ Name = "RequireSecuritySignature"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = 1; Description = "Microsoft network server: Digitally sign communications (if client agrees)" }
    @{ Name = "EnableForcedLogoff"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = 1; Description = "Microsoft network server: Disconnect clients when logon hours expire" }
    @{ Name = "SmbServerNameHardeningLevel"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = 1; Description = "Microsoft network server: Server SPN target name validation level" }
)

# Apply settings
foreach ($setting in $networkServerSettings) {
    Write-Host "Applying: $($setting.Description)..."

    # Ensure registry path exists
    if (-not (Test-Path $setting.Path)) {
        Write-Host "Creating registry path: $($setting.Path)"
        New-Item -Path $setting.Path -Force | Out-Null
    }

    # Apply registry setting
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force

    # Verify setting
    $currentValue = (Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue).$($setting.Name)
    if ($currentValue -eq $setting.Value) {
        Write-Host "Verified: $($setting.Description) is correctly set to $($setting.Value)" -ForegroundColor Green
    } else {
        Write-Host "WARNING: $($setting.Description) is incorrect! Expected: $($setting.Value), Found: $currentValue" -ForegroundColor Red
    }
}

Write-Host "Microsoft network server settings have been configured successfully!" -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

################################################################################################################

# ==============================
# CIS Benchmark 2.3.10 - Network Access
# ==============================

Write-Host "Configuring Network Access settings..."

# Define registry settings
$networkAccessSettings = @(
    @{ Name = "LSAAnonymousNameLookup"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = 0; Description = "Network access: Allow anonymous SID/Name translation" }
    @{ Name = "RestrictAnonymousSAM"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = 1; Description = "Network access: Do not allow anonymous enumeration of SAM accounts" }
    @{ Name = "RestrictAnonymous"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = 1; Description = "Network access: Do not allow anonymous enumeration of SAM accounts and shares" }
    @{ Name = "DisableDomainCreds"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = 1; Description = "Network access: Do not allow storage of passwords and credentials for network authentication" }
    @{ Name = "EveryoneIncludesAnonymous"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = 0; Description = "Network access: Let Everyone permissions apply to anonymous users" }
    @{ Name = "NullSessionPipes"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = @(); Description = "Network access: Named Pipes that can be accessed anonymously"; Type = "MultiString" }
    @{ Name = "Machine"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths"; Value = @("System\CurrentControlSet\Control\ProductOptions", "System\CurrentControlSet\Control\Server Applications", "Software\Microsoft\Windows NT\CurrentVersion"); Description = "Network access: Remotely accessible registry paths"; Type = "MultiString" }
    @{ Name = "Machine"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths"; Value = @("System\CurrentControlSet\Control\Print\Printers", "System\CurrentControlSet\Services\Eventlog", "Software\Microsoft\OLAP Server", "Software\Microsoft\Windows NT\CurrentVersion\Print", "Software\Microsoft\Windows NT\CurrentVersion\Windows", "System\CurrentControlSet\Control\ContentIndex", "System\CurrentControlSet\Control\Terminal Server", "System\CurrentControlSet\Control\Terminal Server\UserConfig", "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration", "Software\Microsoft\Windows NT\CurrentVersion\Perflib", "System\CurrentControlSet\Services\SysmonLog"); Description = "Network access: Remotely accessible registry paths and sub-paths"; Type = "MultiString" }
    @{ Name = "RestrictNullSessAccess"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = 1; Description = "Network access: Restrict anonymous access to Named Pipes and Shares" }
    @{ Name = "NullSessionShares"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Value = @(); Description = "Network access: Shares that can be accessed anonymously"; Type = "MultiString" }
    @{ Name = "ForceGuest"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Value = 0; Description = "Network access: Sharing and security model for local accounts" }
)

# Apply registry settings
foreach ($setting in $networkAccessSettings) {
    Write-Host "Applying: $($setting.Description)..."

    # Ensure registry path exists
    if (-not (Test-Path $setting.Path)) {
        Write-Host "Creating registry path: $($setting.Path)"
        New-Item -Path $setting.Path -Force | Out-Null
    }

    # Apply registry setting
    if ($setting.ContainsKey("Type") -and $setting.Type -eq "MultiString") {
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type MultiString -Force
    } else {
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
    }

    # Verify setting
    $currentValue = (Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue).$($setting.Name)

    # Fix for MultiString values
    if ($setting.ContainsKey("Type") -and $setting.Type -eq "MultiString") {
        $expectedValue = ($setting.Value -join " ")
        $currentValue = ($currentValue -join " ")

        # If both are empty, treat as equal
        if (($expectedValue -eq "") -and ($currentValue -eq "")) {
            Write-Host "Verified: $($setting.Description) is correctly set to empty (None)" -ForegroundColor Green
            continue
        }
    }
    # Fix for DWord values - ensure comparison is valid
    elseif ($currentValue -eq $setting.Value) {
        Write-Host "Verified: $($setting.Description) is correctly set to $($setting.Value)" -ForegroundColor Green
    } else {
        Write-Host "WARNING: $($setting.Description) is incorrect! Expected: $($setting.Value), Found: $currentValue" -ForegroundColor Red
    }
}

# ==============================
# CIS Benchmark 2.3.10.10 - Network access: Restrict clients allowed to make remote calls to SAM
# ==============================

Write-Host "Configuring 'Network access: Restrict clients allowed to make remote calls to SAM'..."

# Define registry path
$restrictRemoteSAMPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# Ensure registry path exists
if (-not (Test-Path $restrictRemoteSAMPath)) {
    Write-Host "Creating registry path: $restrictRemoteSAMPath"
    New-Item -Path $restrictRemoteSAMPath -Force | Out-Null
}

# Set correct SDDL string for restricting SAM remote calls
$restrictRemoteSAMValue = "O:BAG:BAD:(A;;RC;;;BA)"

# Apply setting and verify
Set-ItemProperty -Path $restrictRemoteSAMPath -Name "RestrictRemoteSAM" -Value $restrictRemoteSAMValue -Type String -Force

# Verify SAM restriction setting
$currentSAMValue = (Get-ItemProperty -Path $restrictRemoteSAMPath -Name "RestrictRemoteSAM" -ErrorAction SilentlyContinue).RestrictRemoteSAM
if ($currentSAMValue -eq $restrictRemoteSAMValue) {
    Write-Host "Verified: Network access: Restrict clients allowed to make remote calls to SAM is correctly set." -ForegroundColor Green
} else {
    Write-Host "WARNING: Network access: Restrict clients allowed to make remote calls to SAM is incorrect!" -ForegroundColor Red
}

Write-Host "Network Access settings have been configured successfully!" -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#######################################################################################################################

# ==============================
# CIS Benchmark 2.3.11 - Network Security Policies (Windows 10 & 11)
# ==============================

Write-Host "Applying Network Security Policies..." -ForegroundColor Cyan

# Define registry paths (Adjusted Kerberos path to match secpol export)
$registryPaths = @{
    Kerberos = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    NTLM     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    LSA      = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    PKU2U    = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
    LDAP     = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
}

# Ensure registry paths exist (create parent paths recursively)
foreach ($path in $registryPaths.Values) {
    $pathParts = $path -replace '^HKLM:\\', '' -split '\\'
    $currentPath = 'HKLM:'
    foreach ($part in $pathParts) {
        $currentPath = Join-Path $currentPath $part
        if (-not (Test-Path $currentPath)) {
            New-Item -Path $currentPath -Force | Out-Null
        }
    }
}

# Define security policies
$securityPolicies = @(
    @{ Name = "UseMachineId";               Path = $registryPaths.LSA;     Value = 1;         Type = "DWord"; Description = "Allow Local System to use computer identity for NTLM" }
    @{ Name = "AllowNullSessionFallback";     Path = $registryPaths.NTLM;    Value = 0;         Type = "DWord"; Description = "Disable LocalSystem NULL session fallback" }
    @{ Name = "AllowOnlineID";                Path = $registryPaths.PKU2U;   Value = 0;         Type = "DWord"; Description = "Disable PKU2U authentication requests" }
    @{ Name = "SupportedEncryptionTypes";     Path = $registryPaths.Kerberos; Value = 2147483640; Type = "DWord"; Description = "Configure Kerberos encryption types" } # OR value = 2147483644
    @{ Name = "NoLMHash";                     Path = $registryPaths.LSA;     Value = 1;         Type = "DWord"; Description = "Do not store LAN Manager hash on next password change" }
    @{ Name = "ForceLogoffWhenHourExpire";    Path = $registryPaths.LSA;     Value = 1;         Type = "DWord"; Description = "Force logoff when logon hours expire" }
    @{ Name = "LmCompatibilityLevel";         Path = $registryPaths.LSA;     Value = 5;         Type = "DWord"; Description = "Set LAN Manager authentication level to NTLMv2 only" }
    @{ Name = "LDAPClientIntegrity";          Path = $registryPaths.LDAP;    Value = 1;         Type = "DWord"; Description = "Set LDAP client signing requirements to 'Negotiate signing'" }
    @{ Name = "NTLMMinClientSec";             Path = $registryPaths.NTLM;    Value = 537395200; Type = "DWord"; Description = "NTLM SSP Minimum Security for Clients" }
    @{ Name = "NTLMMinServerSec";             Path = $registryPaths.NTLM;    Value = 537395200; Type = "DWord"; Description = "NTLM SSP Minimum Security for Servers" }
    @{ Name = "AuditReceivingNTLMTraffic";    Path = $registryPaths.NTLM;    Value = 2;         Type = "DWord"; Description = "Restrict NTLM: Audit Incoming NTLM Traffic" }
    @{ Name = "RestrictSendingNTLMTraffic";     Path = $registryPaths.NTLM;    Value = 1;         Type = "DWord"; Description = "Restrict NTLM: Outgoing NTLM Traffic to Remote Servers" }
)

# Apply security policies (create if not exists, update otherwise)
foreach ($policy in $securityPolicies) {
    Write-Host "Applying: $($policy.Description)..."
    try {
        # Check if the property exists
        $null = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction Stop
        Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.Value -Force
    }
    catch {
        New-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.Value -PropertyType $policy.Type -Force
    }
}

# ==============================
# Step 3: Iterate Through Benchmarks - Export, Modify, and Apply secpol.cfg
# ==============================

# Define security policy file paths
$secpolPath = "C:\LOGS\Scripts\secpol.cfg"
$secpolTxtPath = $secpolPath -replace '\.cfg$', '.txt'

# Ensure logs directory exists
if (-Not (Test-Path "C:\LOGS\Scripts")) {
    New-Item -ItemType Directory -Path "C:\LOGS\Scripts" -Force | Out-Null
}

# Define the security benchmarks to check in secpol.cfg
$secpolBenchmarks = @(
    @{ Path = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes"; Value = "4,2147483640" } # 2.3.11.4 OR 2147483644
    @{ Path = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec"; Value = "4,537395200" }                   # 2.3.11.9
    @{ Path = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec"; Value = "4,537395200" }                   # 2.3.11.10
    @{ Path = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic"; Value = "4,2" }                  # 2.3.11.11
    @{ Path = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic"; Value = "4,1" }                 # 2.3.11.12
)

foreach ($benchmark in $secpolBenchmarks) {
    Write-Host "Processing benchmark: $($benchmark.Path)"

    # (A) Export current security policies
    Write-Host "Exporting current security policies..."
    secedit /export /cfg $secpolPath /quiet

    if (!(Test-Path $secpolPath)) {
        Write-Host "ERROR: Failed to export security policy! Skipping $($benchmark.Path)" -ForegroundColor Red
        continue
    }
    Write-Host "Exported secpol.cfg: $secpolPath"

    # (B) Rename .cfg to .txt for modification
    if (Test-Path $secpolTxtPath) { Remove-Item -Path $secpolTxtPath -Force }
    Rename-Item -Path $secpolPath -NewName $secpolTxtPath -Force
    Write-Host "Renamed secpol.cfg to secpol.txt: $secpolTxtPath"

    # (C) Modify secpol.txt (ensure benchmark is correctly set)
    $secpolContent = Get-Content $secpolTxtPath
    if ($secpolContent -eq $null -or $secpolContent.Count -eq 0) {
        Write-Host "ERROR: secpol.txt is empty! Skipping $($benchmark.Path)" -ForegroundColor Red
        continue
    }

    $benchmarkPath = [regex]::Escape($benchmark.Path)  # Properly escape for regex
    $benchmarkValue = $benchmark.Value

    # Check if the path exists in the [Registry Values] section
    $found = $false
    for ($i = 0; $i -lt $secpolContent.Count; $i++) {
        if ($secpolContent[$i] -match "^$benchmarkPath\s*=\s*""?(.+?)""?$") {
            $found = $true
            $currentValue = $matches[1] -replace '"', ''  # Remove quotes
            $normalizedBenchmarkValue = $benchmarkValue -replace '"', ''
            if ($currentValue -eq $normalizedBenchmarkValue) {
                Write-Host "Verified: $benchmarkPath is correctly set." -ForegroundColor Green
            } else {
                Write-Host "Updating: $benchmarkPath (Old Value: $currentValue, New Value: $normalizedBenchmarkValue)"
                $secpolContent[$i] = "$benchmarkPath=$normalizedBenchmarkValue"
            }
            break
        }
    }

    if (-not $found) {
        Write-Host "Appending missing entry: $benchmarkPath=$benchmarkValue"
        # Find the [Registry Values] section using [Array]::IndexOf
        $registrySection = $secpolContent | Where-Object { $_ -match "^\[Registry Values\]" }
        $registrySectionIndex = [Array]::IndexOf($secpolContent, $registrySection)
        if ($registrySectionIndex -ge 0) {
            # Insert the new entry right after the [Registry Values] header
            $insertIndex = $registrySectionIndex + 1
            $before = $secpolContent[0..($insertIndex - 1)]
            $after = $secpolContent[$insertIndex..($secpolContent.Count - 1)]
            $secpolContent = $before + "$benchmarkPath=$benchmarkValue" + $after
        }
        else {
            # If the section is missing, append it along with the entry
            $secpolContent += "[Registry Values]"
            $secpolContent += "$benchmarkPath=$benchmarkValue"
        }
    }

    # (D) Save the modified secpol.txt
    Set-Content -Path $secpolTxtPath -Value $secpolContent
    Write-Host "Saved modified secpol.txt"

    # (E) Rename .txt back to .cfg
    if (Test-Path $secpolPath) { Remove-Item -Path $secpolPath -Force }
    Rename-Item -Path $secpolTxtPath -NewName $secpolPath -Force
    Write-Host "Renamed secpol.txt to secpol.cfg: $secpolPath"

    # (F) Apply the updated security policy
    Write-Host "Applying updated security policies..."
    secedit /configure /db c:\windows\security\local.sdb /cfg $secpolPath /quiet

    # (G) Wait 5 seconds
    Start-Sleep -Seconds 5

    # (H) Delete secpol.cfg
    Remove-Item -Path $secpolPath -Force
    Write-Host "Cleanup complete. Proceeding to next benchmark..."
}

Write-Host "Security policies applied successfully!" -ForegroundColor Green

Write-Host "Applying Group Policy updates..."
gpupdate /force

Write-Host "Final security policy verification..."
secedit /export /cfg $secpolPath /quiet

if (!(Test-Path $secpolPath)) {
    Write-Host "ERROR: Failed to export final security policy!" -ForegroundColor Red
    exit 1
}

$finalSecpolContent = Get-Content $secpolPath

foreach ($benchmark in $secpolBenchmarks) {
    $normalizedBenchmarkValue = $benchmark.Value -replace '"', ''
    $matchedValue = $null
    foreach ($line in $finalSecpolContent) {
        if ($line -match "^$([regex]::Escape($benchmark.Path))\s*=\s*""?(.+?)""?$") {
            $matchedValue = $matches[1] -replace '"', ''
            break
        }
    }
    if ($matchedValue -eq $normalizedBenchmarkValue) {
        Write-Host "Final Verification: $($benchmark.Path) is correctly set." -ForegroundColor Green
    } else {
        Write-Host "WARNING: $($benchmark.Path) is missing or incorrect in secpol.cfg!" -ForegroundColor Red
    }
}

Remove-Item -Path $secpolPath -Force

Write-Host "Network security settings applied and verified successfully!" -ForegroundColor Green

Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#############################################################################################################################

# APPLIES TO WINDOWS 11 - NOT TESTED, BUT WILL VERIFY ON A WINDOWS 11 SYSTEM
# ==============================
# CIS Benchmark 2.3.14.1 (Windows 11 Only) - System Cryptography: Force strong key protection for user keys stored on the computer
# ==============================

if ($isWindows11) {
    Write-Host "Configuring System Cryptography: Force strong key protection for user keys (Windows 11)..." -ForegroundColor Cyan

    # Define registry path and expected value
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $regName = "ForceKeyProtection"
    $expectedValue = 1  # 'User is prompted when the key is first used'

    # Ensure registry path exists
    if (-not (Test-Path $regPath)) {
        Write-Host "Creating missing registry path: $regPath..."
        New-Item -Path $regPath -Force | Out-Null
    }

    # Retrieve current registry value
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

    if ($currentValue -eq $expectedValue) {
        Write-Host "Verified: $regName is correctly set to $expectedValue." -ForegroundColor Green
    } else {
        Write-Host "Updating $regName (Old Value: $currentValue, New Value: $expectedValue)..."
        Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -Type DWord -Force
    }

    # Final verification
    $verifiedValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    if ($verifiedValue -eq $expectedValue) {
        Write-Host "Final Verification: $regName is correctly set to $expectedValue." -ForegroundColor Green
    } else {
        Write-Host "WARNING: $regName is incorrect! Expected: $expectedValue, Found: $verifiedValue" -ForegroundColor Red
    }

    Write-Host "System cryptography policy has been applied successfully for Windows 11!" -ForegroundColor Green
} else {
    Write-Host "Skipping CIS Benchmark 2.3.14.1: This setting applies only to Windows 11." -ForegroundColor Yellow
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

##############################################################################################################################

# ==============================
# CIS Benchmark 2.3.15 - System Objects Configuration
# ==============================

Write-Host "Applying System Objects security policies..." -ForegroundColor Cyan

# Define registry paths and settings
$systemObjectsPolicies = @(
    @{ Name = "ObCaseInsensitive"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Value = 1; Type = "DWord"; Description = "Require case insensitivity for non-Windows subsystems" }
    @{ Name = "ProtectionMode"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Value = 1; Type = "DWord"; Description = "Strengthen default permissions of internal system objects (e.g., Symbolic Links)" }
)

# Apply settings
foreach ($policy in $systemObjectsPolicies) {
    Write-Host "Applying: $($policy.Description)..."
    Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.Value -Type $policy.Type -Force
}

Write-Host "System Objects security policies have been applied successfully!" -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

###############################################################################################################################

# ==============================
# CIS Benchmark 2.3.17 - User Account Control (UAC)
# Windows 10 & Windows 11
# ==============================
Write-Host "Configuring User Account Control (UAC) settings..." -ForegroundColor Cyan

# Define registry path for UAC settings
$uacRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Ensure registry path exists before applying settings
if (-not (Test-Path $uacRegPath)) {
    Write-Host "Creating missing registry path: $uacRegPath..."
    New-Item -Path $uacRegPath -Force | Out-Null
}

# Define UAC policies
$uacPolicies = @(
    @{ Name = "FilterAdministratorToken";       Value = 1; Type = "DWord"; Description = "Admin Approval Mode for Built-in Administrator account" } # 2.3.17.1
    @{ Name = "ConsentPromptBehaviorAdmin";       Value = 2; Type = "DWord"; Description = "Elevation prompt for administrators: Prompt for consent on secure desktop" } # 2.3.17.2
    @{ Name = "ConsentPromptBehaviorUser";        Value = 2; Type = "DWord"; Description = "Elevation prompt for standard users: Automatically deny elevation requests" } # 2.3.17.3 Change this to '0' instead so that it will pass under the user!
    @{ Name = "EnableInstallerDetection";         Value = 1; Type = "DWord"; Description = "Detect application installations and prompt for elevation" } # 2.3.17.4
    @{ Name = "EnableSecureUIAPaths";              Value = 1; Type = "DWord"; Description = "Only elevate UIAccess applications from secure locations" } # 2.3.17.5
    @{ Name = "EnableLUA";                         Value = 1; Type = "DWord"; Description = "Run all administrators in Admin Approval Mode" } # 2.3.17.6
    @{ Name = "PromptOnSecureDesktop";             Value = 1; Type = "DWord"; Description = "Switch to secure desktop when prompting for elevation" } # 2.3.17.7
    @{ Name = "EnableVirtualization";              Value = 1; Type = "DWord"; Description = "Virtualize file and registry write failures" } # 2.3.17.8
)

# Apply UAC policies
foreach ($policy in $uacPolicies) {
    Write-Host "Applying: $($policy.Description)..."
    try {
        # If the property exists, update it.
        $null = Get-ItemProperty -Path $uacRegPath -Name $policy.Name -ErrorAction Stop
        Set-ItemProperty -Path $uacRegPath -Name $policy.Name -Value $policy.Value -Force
    }
    catch {
        # Otherwise, create the property.
        New-ItemProperty -Path $uacRegPath -Name $policy.Name -Value $policy.Value -PropertyType $policy.Type -Force
    }
}

# ==============================
# Final Verification & Enforcement
# ==============================

Write-Host "Applying Group Policy updates..."
gpupdate /force

# Verify applied settings
Write-Host "Final verification of UAC settings..."
$uacResults = Get-ItemProperty -Path $uacRegPath

foreach ($policy in $uacPolicies) {
    $currentValue = $uacResults.($policy.Name)
    if ($currentValue -eq $policy.Value) {
        Write-Host "Verified: $($policy.Description) is correctly set to $($policy.Value)." -ForegroundColor Green
    } else {
        Write-Host "WARNING: $($policy.Description) is incorrect! Expected: $($policy.Value), Found: $currentValue" -ForegroundColor Red
    }
}

Write-Host "User Account Control (UAC) settings applied and verified successfully!" -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan
#
########################################################################################################################


# ALL TESTS PASSED IN WINDOWS 10 - STILL NEED TO TEST IN WINDOWS 11
# ==============================
# CIS Benchmark 5 - System Services
# ==============================

#
# --- Functions ---

function Configure-ServicesWin10 {
    Write-Host "Configuring Windows 10 System Services..." -ForegroundColor Cyan

    # Define the Windows 10 services (ordered as per benchmark order)
    $servicesWin10 = @{
        # Benchmark 5.3: Computer Browser
        "Browser"        = @{ Name = "Computer Browser"; Action = "Disable" }
        # Benchmark 5.6: IIS Admin Service
        "IISADMIN"       = @{ Name = "IIS Admin Service"; Action = "Disable" }
        # Benchmark 5.7: Infrared Monitor Service
        "irmon"          = @{ Name = "Infrared Monitor Service"; Action = "Disable" }
        # Benchmark 5.8: Internet Connection Sharing (ICS)
        "SharedAccess"   = @{ Name = "Internet Connection Sharing (ICS)"; Action = "Disable" }
        # Benchmark 5.10: LxssManager
        "LxssManager"    = @{ Name = "LxssManager"; Action = "Disable" }
        # Benchmark 5.11: Microsoft FTP Service
        "FTPSVC"         = @{ Name = "Microsoft FTP Service"; Action = "Disable" }
        # Benchmark 5.13: OpenSSH SSH Server
        "sshd"           = @{ Name = "OpenSSH SSH Server"; Action = "Disable" }
        # Benchmark 5.24: RPC Locator
        "RpcLocator"     = @{ Name = "Remote Procedure Call (RPC) Locator"; Action = "Disable" }
        # Benchmark 5.26: Routing and Remote Access
        "RemoteAccess"   = @{ Name = "Routing and Remote Access"; Action = "Disable" }
        # Benchmark 5.28: Simple TCP/IP Services
        "simptcp"        = @{ Name = "Simple TCP/IP Services"; Action = "Disable" }
        # Benchmark 5.30: Special Administration Console Helper
        "sacsvr"         = @{ Name = "Special Administration Console Helper"; Action = "Disable" }
        # Benchmark 5.31: SSDP Discovery
        "SSDPSRV"        = @{ Name = "SSDP Discovery"; Action = "Disable" }
        # Benchmark 5.32: UPnP Device Host
        "upnphost"       = @{ Name = "UPnP Device Host"; Action = "Disable" }
        # Benchmark 5.33: Web Management Service
        "WMSvc"          = @{ Name = "Web Management Service"; Action = "Disable" }
        # Benchmark 5.36: Windows Media Player Network Sharing Service
        "WMPNetworkSvc"  = @{ Name = "Windows Media Player Network Sharing Service"; Action = "Disable" }
        # Benchmark 5.37: Windows Mobile Hotspot Service
        "icssvc"         = @{ Name = "Windows Mobile Hotspot Service"; Action = "Disable" }
        # Benchmark 5.41: World Wide Web Publishing Service
        "W3SVC"          = @{ Name = "World Wide Web Publishing Service"; Action = "Disable" }
        # Benchmark 5.42: Xbox Accessory Management Service
        "XboxGipSvc"     = @{ Name = "Xbox Accessory Management Service"; Action = "Disable" }
        # Benchmark 5.43: Xbox Live Auth Manager
        "XblAuthManager" = @{ Name = "Xbox Live Auth Manager"; Action = "Disable" }
        # Benchmark 5.44: Xbox Live Game Save
        "XblGameSave"    = @{ Name = "Xbox Live Game Save"; Action = "Disable" }
        # Benchmark 5.45: Xbox Live Networking Service
        "XboxNetApiSvc"  = @{ Name = "Xbox Live Networking Service"; Action = "Disable" }
    }

    foreach ($key in $servicesWin10.Keys) {
        $service = $servicesWin10[$key]
        Write-Host "Disabling '$($service.Name)' ($key)..."
        # Use sc.exe to set the startup type to disabled.
        sc.exe config $key start= disabled | Out-Null
    }

    Write-Host "Windows 10 System Services configuration completed!" -ForegroundColor Green
    
    Write-Host "Applying Group Policy update..."
    gpupdate /force
    Write-Host "Group Policy update completed." -ForegroundColor Cyan
}


function Configure-ServicesWin11 {
    Write-Host "Configuring Windows 11 System Services..." -ForegroundColor Cyan

    # Define the Windows 11 services (all 44 benchmarks)
    $servicesWin11 = @{
        # L2 Benchmarks and L1 benchmarks as defined
        "BTAGService"    = @{ Name = "Bluetooth Audio Gateway Service";           RegPath = "SYSTEM\CurrentControlSet\Services\BTAGService";    Value = 4 }
        "bthserv"        = @{ Name = "Bluetooth Support Service";                 RegPath = "SYSTEM\CurrentControlSet\Services\bthserv";        Value = 4 }
        "Browser"        = @{ Name = "Computer Browser";                          RegPath = "SYSTEM\CurrentControlSet\Services\Browser";        Value = 4 }
        "MapsBroker"     = @{ Name = "Downloaded Maps Manager";                   RegPath = "SYSTEM\CurrentControlSet\Services\MapsBroker";     Value = 4 }
        "lfsvc"          = @{ Name = "Geolocation Service";                       RegPath = "SYSTEM\CurrentControlSet\Services\lfsvc";          Value = 4 }
        "IISADMIN"       = @{ Name = "IIS Admin Service";                         RegPath = "SYSTEM\CurrentControlSet\Services\IISADMIN";       Value = 4 }
        "irmon"          = @{ Name = "Infrared Monitor Service";                  RegPath = "SYSTEM\CurrentControlSet\Services\irmon";          Value = 4 }
        "lltdsvc"        = @{ Name = "Link-Layer Topology Discovery Mapper";      RegPath = "SYSTEM\CurrentControlSet\Services\lltdsvc";        Value = 4 }
        "LxssManager"    = @{ Name = "LxssManager";                               RegPath = "SYSTEM\CurrentControlSet\Services\LxssManager";    Value = 4 }
        "FTPSVC"         = @{ Name = "Microsoft FTP Service";                     RegPath = "SYSTEM\CurrentControlSet\Services\FTPSVC";         Value = 4 }
        "MSiSCSI"        = @{ Name = "Microsoft iSCSI Initiator Service";         RegPath = "SYSTEM\CurrentControlSet\Services\MSiSCSI";        Value = 4 }
        "sshd"           = @{ Name = "OpenSSH SSH Server";                        RegPath = "SYSTEM\CurrentControlSet\Services\sshd";           Value = 4 }
        "PNRPsvc"        = @{ Name = "Peer Name Resolution Protocol";             RegPath = "SYSTEM\CurrentControlSet\Services\PNRPsvc";        Value = 4 }
        "p2psvc"         = @{ Name = "Peer Networking Grouping";                  RegPath = "SYSTEM\CurrentControlSet\Services\p2psvc";         Value = 4 }
        "p2pimsvc"       = @{ Name = "Peer Networking Identity Manager";          RegPath = "SYSTEM\CurrentControlSet\Services\p2pimsvc";       Value = 4 }
        "PNRPAutoReg"    = @{ Name = "PNRP Machine Name Publication Service";     RegPath = "SYSTEM\CurrentControlSet\Services\PNRPAutoReg";    Value = 4 }
        "Spooler"        = @{ Name = "Print Spooler";                             RegPath = "SYSTEM\CurrentControlSet\Services\Spooler";        Value = 4 }
        "wercplsupport"  = @{ Name = "Problem Reports and Solutions Control Panel Support"; RegPath = "SYSTEM\CurrentControlSet\Services\wercplsupport"; Value = 4 }
        "RasAuto"        = @{ Name = "Remote Access Auto Connection Manager";     RegPath = "SYSTEM\CurrentControlSet\Services\RasAuto";        Value = 4 }
        "SessionEnv"     = @{ Name = "Remote Desktop Configuration";              RegPath = "SYSTEM\CurrentControlSet\Services\SessionEnv";     Value = 4 }
        "TermService"    = @{ Name = "Remote Desktop Services";                   RegPath = "SYSTEM\CurrentControlSet\Services\TermService";    Value = 4 }
        "UmRdpService"   = @{ Name = "Remote Desktop Services UserMode Port Redirector"; RegPath = "SYSTEM\CurrentControlSet\Services\UmRdpService"; Value = 4 }
        "RpcLocator"     = @{ Name = "Remote Procedure Call (RPC) Locator";         RegPath = "SYSTEM\CurrentControlSet\Services\RpcLocator";     Value = 4 }
        "RemoteRegistry" = @{ Name = "Remote Registry";                           RegPath = "SYSTEM\CurrentControlSet\Services\RemoteRegistry"; Value = 4 }
        "RemoteAccess"   = @{ Name = "Routing and Remote Access";                 RegPath = "SYSTEM\CurrentControlSet\Services\RemoteAccess";   Value = 4 }
        "LanmanServer"   = @{ Name = "Server";                                    RegPath = "SYSTEM\CurrentControlSet\Services\LanmanServer";   Value = 4 }
        "simptcp"        = @{ Name = "Simple TCP/IP Services";                    RegPath = "SYSTEM\CurrentControlSet\Services\simptcp";        Value = 4 }
        "SNMP"           = @{ Name = "SNMP Service";                              RegPath = "SYSTEM\CurrentControlSet\Services\SNMP";           Value = 4 }
        "sacsvr"         = @{ Name = "Special Administration Console Helper";     RegPath = "SYSTEM\CurrentControlSet\Services\sacsvr";         Value = 4 }
        "SSDPSRV"        = @{ Name = "SSDP Discovery";                            RegPath = "SYSTEM\CurrentControlSet\Services\SSDPSRV";        Value = 4 }
        "upnphost"       = @{ Name = "UPnP Device Host";                          RegPath = "SYSTEM\CurrentControlSet\Services\upnphost";       Value = 4 }
        "WMSvc"          = @{ Name = "Web Management Service";                    RegPath = "SYSTEM\CurrentControlSet\Services\WMSvc";          Value = 4 }
        "WerSvc"         = @{ Name = "Windows Error Reporting Service";           RegPath = "SYSTEM\CurrentControlSet\Services\WerSvc";         Value = 4 }
        "Wecsvc"         = @{ Name = "Windows Event Collector";                   RegPath = "SYSTEM\CurrentControlSet\Services\Wecsvc";         Value = 4 }
        "WMPNetworkSvc"  = @{ Name = "Windows Media Player Network Sharing Service"; RegPath = "SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"; Value = 4 }
        "icssvc"         = @{ Name = "Windows Mobile Hotspot Service";            RegPath = "SYSTEM\CurrentControlSet\Services\icssvc";         Value = 4 }
        "WpnService"     = @{ Name = "Windows Push Notifications System Service";   RegPath = "SYSTEM\CurrentControlSet\Services\WpnService";     Value = 4 }
        "PushToInstall"  = @{ Name = "Windows PushToInstall Service";             RegPath = "SYSTEM\CurrentControlSet\Services\PushToInstall";  Value = 4 }
        "WinRM"          = @{ Name = "Windows Remote Management";                 RegPath = "SYSTEM\CurrentControlSet\Services\WinRM";          Value = 4 }
        "W3SVC"          = @{ Name = "World Wide Web Publishing Service";         RegPath = "SYSTEM\CurrentControlSet\Services\W3SVC";          Value = 4 }
        "XboxGipSvc"     = @{ Name = "Xbox Accessory Management Service";         RegPath = "SYSTEM\CurrentControlSet\Services\XboxGipSvc";     Value = 4 }
        "XblAuthManager" = @{ Name = "Xbox Live Auth Manager";                    RegPath = "SYSTEM\CurrentControlSet\Services\XblAuthManager"; Value = 4 }
        "XblGameSave"    = @{ Name = "Xbox Live Game Save";                       RegPath = "SYSTEM\CurrentControlSet\Services\XblGameSave";    Value = 4 }
        "XboxNetApiSvc"  = @{ Name = "Xbox Live Networking Service";              RegPath = "SYSTEM\CurrentControlSet\Services\XboxNetApiSvc";  Value = 4 }
    }

    foreach ($key in $servicesWin11.Keys) {
        $svc = $servicesWin11[$key]
        $regPath = "HKLM:\$($svc.RegPath)"
        Write-Host "Disabling '$($svc.Name)' ($key)..."
        # If the registry path does not exist, create it.
        if (-not (Test-Path $regPath)) {
            Write-Host "Registry path $regPath not found. Creating..."
            New-Item -Path $regPath -Force | Out-Null
        }
        # Set the 'Start' value to disable the service (4 = Disabled)
        try {
            Set-ItemProperty -Path $regPath -Name "Start" -Value $svc.Value -Force
        }
        catch {
            Write-Host "Failed to set 'Start' for $($svc.Name) at $regPath" -ForegroundColor Red
        }
    }

    Write-Host "Windows 11 System Services configuration completed!" -ForegroundColor Green

    Write-Host "Applying Group Policy update..."
    gpupdate /force
    Write-Host "Group Policy update completed." -ForegroundColor Cyan
}

# --- Main Execution ---

# (Assumes that $isWindows10 and $isWindows11 are set appropriately)
if ($isWindows10) {
    Configure-ServicesWin10
}

if ($isWindows11) {
    Configure-ServicesWin11
}

Write-Host "All System Services configurations have been applied!" -ForegroundColor Green

#########################################################################################################################

# Define the audit settings as an array of hashtables.
$auditSettings = @(
    @{ Subcategory = "Credential Validation";               Success = $true;  Failure = $true  },
    @{ Subcategory = "Application Group Management";        Success = $true;  Failure = $true  },
    @{ Subcategory = "Security Group Management";           Success = $true;  Failure = $false },
    @{ Subcategory = "User Account Management";             Success = $true;  Failure = $true  },
    @{ Subcategory = "Plug and Play Events";                Success = $true; Failure = $false },
    @{ Subcategory = "Process Creation";                    Success = $true;  Failure = $false },
    @{ Subcategory = "Account Lockout";                     Success = $false; Failure = $true  },
    @{ Subcategory = "Group Membership";                    Success = $true;  Failure = $false },
    @{ Subcategory = "Logoff";                              Success = $true;  Failure = $false },
    @{ Subcategory = "Logon";                               Success = $true;  Failure = $true  },
    @{ Subcategory = "Other Logon/Logoff Events";           Success = $true;  Failure = $true  },
    @{ Subcategory = "Special Logon";                       Success = $true;  Failure = $false },
    @{ Subcategory = "Detailed File Share";                 Success = $false; Failure = $true  },
    @{ Subcategory = "File Share";                          Success = $true;  Failure = $true  },
    @{ Subcategory = "Other Object Access Events";          Success = $true;  Failure = $true  },
    @{ Subcategory = "Removable Storage";                   Success = $true;  Failure = $true  },
    @{ Subcategory = "Audit Policy Change";                 Success = $true;  Failure = $false },
    @{ Subcategory = "Authentication Policy Change";        Success = $true;  Failure = $false },
    @{ Subcategory = "Authorization Policy Change";         Success = $true;  Failure = $false },
    @{ Subcategory = "MPSSVC Rule-Level Policy Change";     Success = $true;  Failure = $true  },
    @{ Subcategory = "Other Policy Change Events";          Success = $false; Failure = $true  },
    @{ Subcategory = "Sensitive Privilege Use";             Success = $true;  Failure = $true  },
    @{ Subcategory = "IPsec Driver";                        Success = $true;  Failure = $true  },
    @{ Subcategory = "Other System Events";                 Success = $true;  Failure = $true  },
    @{ Subcategory = "Security State Change";               Success = $true;  Failure = $false },
    @{ Subcategory = "Security System Extension";           Success = $true;  Failure = $false },
    @{ Subcategory = "System Integrity";                    Success = $true;  Failure = $true  }
)

# Loop through each setting, apply it, and verify it.
foreach ($setting in $auditSettings) {
    $subcategory = $setting.Subcategory

    # Build the success and failure parameters.
    $successParam = if ($setting.Success) { "/success:enable" } else { "" }
    $failureParam = if ($setting.Failure) { "/failure:enable" } else { "" }
    
    Write-Host "-----------------------------------------------"
    Write-Host "Configuring audit for: $subcategory" -ForegroundColor Yellow
    
    # Set the audit policy using auditpol.
    $setCommand = "auditpol /set /subcategory:`"$subcategory`" $successParam $failureParam"
    Write-Host "Executing: $setCommand" -ForegroundColor Cyan
    Invoke-Expression $setCommand | Out-Null

    # Display a success message.
    Write-Host "The command was successfully executed." -ForegroundColor Magenta
    
    # Verify the configuration.
    Write-Host "Verifying setting for: $subcategory"
    auditpol /get /subcategory:"$subcategory"
    Write-Host ""
}

Write-Host "Audit policy configuration complete." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################
# CIS Benchmark 18 - Administrative Templates
#########################################################################################################################

Write-Host "Configuring Administrative Templates Policies..."

# CIS Benchmark 18.1 - Control Panel
Write-Host "Configuring Control Panel Policies..."

# CIS Benchmark 18.1.1 - Personalization
Write-Host "Configuring Personalization settings..."

# Define the base registry path for Personalization settings
$personalizationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"

# Ensure the registry path exists
if (-not (Test-Path $personalizationPath)) {
    New-Item -Path $personalizationPath -Force | Out-Null
    Write-Host "Created registry path: $personalizationPath"
}

# Define the personalization policies
$personalizationPolicies = @(
    @{ Name = "NoLockScreenCamera";    Value = 1; Description = "Prevent enabling lock screen camera" },
    @{ Name = "NoLockScreenSlideshow"; Value = 1; Description = "Prevent enabling lock screen slide show" }
)

# Loop through each policy and apply it
foreach ($policy in $personalizationPolicies) {
    Write-Host "Ensuring '$($policy.Description)' is set to 'Enabled'..."
    Set-ItemProperty -Path $personalizationPath -Name $policy.Name -Value $policy.Value -Type DWord -Force
    Write-Host "'$($policy.Description)' has been set to 'Enabled'."
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

#
# CIS Benchmark 18.1.2.2 - Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'
Write-Host "Ensuring 'Allow users to enable online speech recognition services' is set to 'Disabled'..."

# Define the registry path (exactly as specified)
$speechPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"

# Ensure the registry path exists
if (-not (Test-Path $speechPath)) {
    Write-Host "Registry path $speechPath does not exist. Creating it..."
    try {
        New-Item -Path $speechPath -Force | Out-Null
    } catch {
        Write-Host "ERROR: Failed to create registry path $speechPath. $_" -ForegroundColor Red
        exit 1
    }
}

# Apply the setting (0 = Disabled) using the correct key name
try {
    Set-ItemProperty -Path $speechPath -Name "AllowInputPersonalization" -Value 0 -Type DWord -Force -ErrorAction Stop
    Write-Host "'Allow users to enable online speech recognition services' has been set to 'Disabled'." -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to set 'AllowInputPersonalization' to Disabled. $_" -ForegroundColor Red
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.1.3 - Ensure 'Allow Online Tips' is set to 'Disabled'
Write-Host "Ensuring 'Allow Online Tips' is set to 'Disabled'..."

# Define the registry path (exactly as specified)
$onlineTipsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure the registry path exists
if (-not (Test-Path $onlineTipsPath)) {
    Write-Host "Registry path $onlineTipsPath does not exist. Creating it..."
    try {
        New-Item -Path $onlineTipsPath -Force | Out-Null
    } catch {
        Write-Host "ERROR: Failed to create registry path $onlineTipsPath. $_" -ForegroundColor Red
        exit 1
    }
}

# Apply the setting (0 = Disabled) using the correct key name
try {
    Set-ItemProperty -Path $onlineTipsPath -Name "AllowOnlineTips" -Value 0 -Type DWord -Force -ErrorAction Stop
    Write-Host "'Allow Online Tips' has been set to 'Disabled'." -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to set 'AllowOnlineTips' to Disabled. $_" -ForegroundColor Red
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Online Tips policy configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.4 - MS Security Guide
Write-Host "Configuring MS Security Guide Policies..." -ForegroundColor Yellow

# Define registry settings in an array for efficiency
$registrySettings = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "LocalAccountTokenFilterPolicy"; Value = 0; Type = "DWord"; Desc = "Apply UAC restrictions to local accounts on network logons" }
    @{ Path = "HKLM:\System\CurrentControlSet\Control\Print"; Name = "RpcAuthnLevelPrivacyEnabled"; Value = 1; Type = "DWord"; Desc = "Configure RPC packet level privacy setting for incoming connections" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"; Name = "Start"; Value = 4; Type = "DWord"; Desc = "Configure SMB v1 client driver (Disable driver)" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "SMB1"; Value = 0; Type = "DWord"; Desc = "Configure SMB v1 server (Disabled)" }
    @{ Path = "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"; Name = "EnableCertPaddingCheck"; Value = 1; Type = "DWord"; Desc = "Enable Certificate Padding" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Name = "DisableExceptionChainValidation"; Value = 0; Type = "DWord"; Desc = "Enable Structured Exception Handling Overwrite Protection (SEHOP)" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name = "NodeType"; Value = 2; Type = "DWord"; Desc = "NetBT NodeType configuration (Enabled: P-node recommended)" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; Value = 0; Type = "DWord"; Desc = "WDigest Authentication (Disabled)" }
)

# Iterate through settings and apply them efficiently
foreach ($setting in $registrySettings) {
    if (-not (Test-Path $setting.Path)) {
        Write-Host "Registry path $($setting.Path) does not exist. Creating it..."
        New-Item -Path $setting.Path -Force | Out-Null
    }
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Type $setting.Type -Value $setting.Value -Force
    Write-Host "18.4.x: '$($setting.Desc)' configured." -ForegroundColor Cyan
}

# 18.4.7 - Ensure LSA Protection (RunAsPPL) is enabled
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $lsaPath)) {
    Write-Host "Registry path $lsaPath does not exist. Creating it..."
    New-Item -Path $lsaPath -Force | Out-Null
}

# Fix incorrect registry type for RunAsPPL if necessary
$runAsPPL = Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
if ($runAsPPL -and $runAsPPL.RunAsPPL -is [string]) {
    Write-Host "Incorrect type detected for RunAsPPL. Removing incorrect entry..."
    Remove-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
}

# Set RunAsPPL to REG_DWORD 1 (Enabled)
Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Type DWord -Value 1 -Force
Write-Host "18.4.7: 'LSA Protection (RunAsPPL)' has been correctly set to REG_DWORD:1" -ForegroundColor Cyan

# 18.4.9 - Ensure 'WDigest Authentication' is Disabled (Only for Windows 10)
if ($isWindows10) {
    Write-Host "Applying CIS Benchmark 18.4.9 for Windows 10: Ensure 'WDigest Authentication' is Disabled..."
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    if (-not (Test-Path $wdigestPath)) {
        Write-Host "Registry path $wdigestPath does not exist. Creating it..."
        New-Item -Path $wdigestPath -Force | Out-Null
    }
    Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Type DWord -Value 0 -Force
    Write-Host "CIS Benchmark 18.4.9: 'WDigest Authentication' configured for Windows 10." -ForegroundColor Cyan
} else {
    Write-Host "CIS Benchmark 18.4.9: Not applied. This benchmark only applies to Windows 10 systems." -ForegroundColor Yellow
}

Write-Host "Registry settings applied successfully. Forcing Group Policy update..."

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.4 - MS Security Guide
Write-Host "Configuring MS Security Guide Policies..." -ForegroundColor Yellow

# 18.4.1 - Apply UAC restrictions to local accounts on network logons
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $uacPath)) {
    Write-Host "Registry path $uacPath does not exist. Creating it..."
    New-Item -Path $uacPath -Force | Out-Null
}
Set-ItemProperty -Path $uacPath -Name "LocalAccountTokenFilterPolicy" -Type DWord -Value 0 -Force
Write-Host "18.4.1: 'Apply UAC restrictions to local accounts on network logons' configured." -ForegroundColor Cyan

# 18.4.2 - Configure RPC packet level privacy setting for incoming connections
$printPath = "HKLM:\System\CurrentControlSet\Control\Print"
if (-not (Test-Path $printPath)) {
    Write-Host "Registry path $printPath does not exist. Creating it..."
    New-Item -Path $printPath -Force | Out-Null
}
# Ensure RpcAuthnLevelPrivacyEnabled is set to 1 (Enabled)
Set-ItemProperty -Path $printPath -Name "RpcAuthnLevelPrivacyEnabled" -Type DWord -Value 1 -Force
Write-Host "18.4.2: 'Configure RPC packet level privacy setting for incoming connections' configured." -ForegroundColor Cyan

# 18.4.3 - Configure SMB v1 client driver (Disable driver)
$smbv1ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
if (-not (Test-Path $smbv1ClientPath)) {
    Write-Host "Registry path $smbv1ClientPath does not exist. Creating it..."
    New-Item -Path $smbv1ClientPath -Force | Out-Null
}
Set-ItemProperty -Path $smbv1ClientPath -Name "Start" -Type DWord -Value 4 -Force
Write-Host "18.4.3: 'Configure SMB v1 client driver' configured." -ForegroundColor Cyan

# 18.4.4 - Configure SMB v1 server (Disabled)
$smbv1ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $smbv1ServerPath)) {
    Write-Host "Registry path $smbv1ServerPath does not exist. Creating it..."
    New-Item -Path $smbv1ServerPath -Force | Out-Null
}
Set-ItemProperty -Path $smbv1ServerPath -Name "SMB1" -Type DWord -Value 0 -Force
Write-Host "18.4.4: 'Configure SMB v1 server' configured." -ForegroundColor Cyan

# 18.4.5 - Enable Certificate Padding
$certPadPath = "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"
if (-not (Test-Path $certPadPath)) {
    Write-Host "Registry path $certPadPath does not exist. Creating it..."
    New-Item -Path $certPadPath -Force | Out-Null
}
# Ensure EnableCertPaddingCheck is set to 1 (Enabled)
Set-ItemProperty -Path $certPadPath -Name "EnableCertPaddingCheck" -Type DWord -Value 1 -Force
Write-Host "18.4.5: 'Enable Certificate Padding' configured." -ForegroundColor Cyan

# 18.4.6 - Enable Structured Exception Handling Overwrite Protection (SEHOP)
$sehPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
if (-not (Test-Path $sehPath)) {
    Write-Host "Registry path $sehPath does not exist. Creating it..."
    New-Item -Path $sehPath -Force | Out-Null
}
Set-ItemProperty -Path $sehPath -Name "DisableExceptionChainValidation" -Type DWord -Value 0 -Force
Write-Host "18.4.6: 'Enable SEHOP' configured." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

# ==============================
# Fix for CIS Benchmark 18.4.7 - Ensure 'RunAsPPL' is set to 'Enabled'
# ==============================

Write-Host "Ensuring 'RunAsPPL' is correctly set to '1' with type REG_DWORD..." -ForegroundColor Yellow

# Define registry path
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# Ensure registry path exists
if (-not (Test-Path $lsaPath)) {
    Write-Host "Registry path $lsaPath does not exist. Creating it..."
    New-Item -Path $lsaPath -Force | Out-Null
}

# Check existing value and type
$existingValue = Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue

if ($existingValue) {
    if ($existingValue.RunAsPPL -is [string]) {
        Write-Host "Incorrect type detected for 'RunAsPPL' (REG_SZ). Removing incorrect entry..."
        Remove-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
    }
}

# Set 'RunAsPPL' to REG_DWORD 1 (Enabled)
Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Type DWord -Value 1 -Force
Write-Host "18.4.7: 'RunAsPPL' has been successfully set to '1' (REG_DWORD)." -ForegroundColor Cyan

# Apply Group Policy update
gpupdate /force | Out-Null
Write-Host "Group policy update applied."

Write-Host "Configuration complete." -ForegroundColor Green

# 18.4.8 - WDigest Authentication (Disabled)
$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $wdigestPath)) {
    Write-Host "Registry path $wdigestPath does not exist. Creating it..."
    New-Item -Path $wdigestPath -Force | Out-Null
}
Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Type DWord -Value 0 -Force
Write-Host "18.4.8: 'WDigest Authentication' configured." -ForegroundColor Cyan

if ($isWindows10) {
    Write-Host "Applying CIS Benchmark 18.4.9 for Windows 10: Ensure 'WDigest Authentication' is Disabled..."
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    if (-not (Test-Path $wdigestPath)) {
        Write-Host "Registry path $wdigestPath does not exist. Creating it..."
        New-Item -Path $wdigestPath -Force | Out-Null
    }
    Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Type DWord -Value 0 -Force
    Write-Host "CIS Benchmark 18.4.9: 'WDigest Authentication' configured for Windows 10." -ForegroundColor Cyan
} else {
    Write-Host "CIS Benchmark 18.4.9: Not applied. This benchmark only applies to Windows 10 systems." -ForegroundColor Yellow
}

Write-Host "Registry settings applied successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ALL TESTS PASSED
# CIS Benchmark 18.5 - MSS (Legacy)
Write-Host "Configuring MSS (Legacy) Policies..." -ForegroundColor Yellow

# Define registry settings for CIS 18.5 benchmarks
$registrySettings = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "AutoAdminLogon"; Value = "0"; Type = "String" } # 18.5.1
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "DisableIPSourceRouting"; Value = 2; Type = "DWord" } # 18.5.2
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableIPSourceRouting"; Value = 2; Type = "DWord" } # 18.5.3
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"; Name = "DisableSavePassword"; Value = 1; Type = "DWord" } # 18.5.4
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableICMPRedirect"; Value = 0; Type = "DWord" } # 18.5.5
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "KeepAliveTime"; Value = 300000; Type = "DWord" } # 18.5.6
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name = "NoNameReleaseOnDemand"; Value = 1; Type = "DWord" } # 18.5.7
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "PerformRouterDiscovery"; Value = 0; Type = "DWord" } # 18.5.8
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name = "SafeDllSearchMode"; Value = 1; Type = "DWord" } # 18.5.9
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"; Name = "WarningLevel"; Value = 90; Type = "DWord" } # 18.5.13
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "TcpMaxDataRetransmissions"; Value = 3; Type = "DWord" } # 18.5.11
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpMaxDataRetransmissions"; Value = 3; Type = "DWord" } # 18.5.12
)

# Apply each registry setting
foreach ($setting in $registrySettings) {
    if (-not (Test-Path $setting.Path)) {
        Write-Host "Registry path $($setting.Path) does not exist. Creating it..."
        try {
            New-Item -Path $setting.Path -Force | Out-Null
        } catch {
            Write-Host "ERROR: Failed to create registry path $($setting.Path). $_" -ForegroundColor Red
            continue
        }
    }
    try {
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force -ErrorAction Stop
        Write-Host "Configured $($setting.Name) in $($setting.Path) to $($setting.Value)" -ForegroundColor Cyan
    } catch {
        Write-Host "ERROR: Failed to configure $($setting.Name) in $($setting.Path). $_" -ForegroundColor Red
    }
}

# CIS Benchmark 18.5.10 - Ensure 'ScreenSaverGracePeriod' is set to '5 seconds or fewer'
$gracePeriodPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $gracePeriodPath)) {
    Write-Host "Registry path $gracePeriodPath does not exist. Creating it..."
    try {
        New-Item -Path $gracePeriodPath -Force | Out-Null
    } catch {
        Write-Host "ERROR: Failed to create registry path $gracePeriodPath. $_" -ForegroundColor Red
    }
}
try {
    Set-ItemProperty -Path $gracePeriodPath -Name "ScreenSaverGracePeriod" -Type String -Value "5" -Force -ErrorAction Stop
    Write-Host "Configured ScreenSaverGracePeriod to 5 seconds" -ForegroundColor Cyan
} catch {
    Write-Host "ERROR: Failed to set ScreenSaverGracePeriod. $_" -ForegroundColor Red
}

Write-Host "MSS (Legacy) Policies configured." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ALL TESTS PASSED
# ==============================
# CIS Benchmark 18.6.4 - Name Resolution Policies
# ==============================

Write-Host "Configuring Name Resolution Policies..." -ForegroundColor Yellow

# Define the registry path
$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

# Ensure the registry path exists
if (-not (Test-Path $dnsClientPath)) {
    Write-Host "Registry path $dnsClientPath does not exist. Creating it..."
    New-Item -Path $dnsClientPath -Force | Out-Null
}

# 18.6.4.1 - Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH'
# Set the DoHPolicy DWORD to 2 (or 3 if you prefer a higher level)
Set-ItemProperty -Path $dnsClientPath -Name "DoHPolicy" -Type DWord -Value 2 -Force
Write-Host "18.6.4.1: 'Configure DNS over HTTPS (DoH)' is set to 'Enabled: Allow DoH' (DoHPolicy=2)." -ForegroundColor Cyan

# 18.6.4.2 - Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'
Set-ItemProperty -Path $dnsClientPath -Name "EnableNetbios" -Type DWord -Value 0 -Force
Write-Host "18.6.4.2: 'Disable NetBIOS name resolution on public networks' has been set (EnableNetbios=0)." -ForegroundColor Cyan

# 18.6.4.3 - Ensure 'Turn off multicast name resolution (LLMNR)' is set to 'Enabled'
Set-ItemProperty -Path $dnsClientPath -Name "EnableMulticast" -Type DWord -Value 0 -Force
Write-Host "18.6.4.3: 'Turn off multicast name resolution (LLMNR)' has been set (EnableMulticast=0)." -ForegroundColor Cyan

Write-Host "Name Resolution Policies configured." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Group Policy update completed." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.6.5.1 - Ensure 'Enable Font Providers' is set to 'Disabled'
Write-Host "Ensuring 'Enable Font Providers' is set to 'Disabled'..."

# Define the registry path (exactly as specified)
$fontProvidersPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

# Ensure the registry path exists
if (-not (Test-Path $fontProvidersPath)) {
    Write-Host "Registry path $fontProvidersPath does not exist. Creating it..."
    try {
        New-Item -Path $fontProvidersPath -Force | Out-Null
    } catch {
        Write-Host "ERROR: Failed to create registry path $fontProvidersPath. $_" -ForegroundColor Red
        exit 1
    }
}

# Apply the setting (0 = Disabled) using the correct key name
try {
    Set-ItemProperty -Path $fontProvidersPath -Name "EnableFontProviders" -Value 0 -Type DWord -Force -ErrorAction Stop
    Write-Host "'Enable Font Providers' has been set to 'Disabled'." -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to set 'EnableFontProviders' to Disabled. $_" -ForegroundColor Red
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Font Providers policy configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# THIS TEST PASSED
# ==============================
# CIS Benchmark 18.6.8.1 - Ensure 'Enable insecure guest logons' is set to 'Disabled'
# ==============================

Write-Host "Ensuring 'Enable insecure guest logons' is set to 'Disabled'..." -ForegroundColor Yellow

# Define the registry paths
$guestLogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"

# Ensure the registry path exists for effective settings
if (-not (Test-Path $guestLogonPath)) {
    Write-Host "Registry path $guestLogonPath does not exist. Creating it..."
    New-Item -Path $guestLogonPath -Force | Out-Null
}

# Ensure the registry path exists for the policy settings
if (-not (Test-Path $policyPath)) {
    Write-Host "Registry path $policyPath does not exist. Creating it..."
    New-Item -Path $policyPath -Force | Out-Null
}

# Check if 'AllowInsecureGuestAuth' exists and is an incorrect type in both locations
$existingGuestLogonValue = Get-ItemProperty -Path $guestLogonPath -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
$existingPolicyValue = Get-ItemProperty -Path $policyPath -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue

if ($existingGuestLogonValue -and $existingGuestLogonValue.AllowInsecureGuestAuth -isnot [int]) {
    Write-Host "Incorrect type detected for 'AllowInsecureGuestAuth' in $guestLogonPath. Removing incorrect entry..."
    Remove-ItemProperty -Path $guestLogonPath -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
}

if ($existingPolicyValue -and $existingPolicyValue.AllowInsecureGuestAuth -isnot [int]) {
    Write-Host "Incorrect type detected for 'AllowInsecureGuestAuth' in $policyPath. Removing incorrect entry..."
    Remove-ItemProperty -Path $policyPath -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
}

# Set 'AllowInsecureGuestAuth' to 0 (Disabled) in both locations
Set-ItemProperty -Path $guestLogonPath -Name "AllowInsecureGuestAuth" -Type DWord -Value 0 -Force
Set-ItemProperty -Path $policyPath -Name "AllowInsecureGuestAuth" -Type DWord -Value 0 -Force

Write-Host "18.6.8.1: 'Enable insecure guest logons' has been successfully set to 'Disabled' in both effective and policy locations." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.6.10.2 - Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
Write-Host "Ensuring 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'..."

# Define the registry path (exactly as specified)
$peernetPath = "HKLM:\Software\Policies\Microsoft\Peernet"

# Ensure the registry path exists
if (-not (Test-Path $peernetPath)) {
    Write-Host "Registry path $peernetPath does not exist. Creating it..."
    try {
        New-Item -Path $peernetPath -Force | Out-Null
    } catch {
        Write-Host "ERROR: Failed to create registry path $peernetPath. $_" -ForegroundColor Red
        exit 1
    }
}

# Apply the setting (1 = Enabled/Disabled = Peer-to-Peer Networking is turned OFF)
try {
    Set-ItemProperty -Path $peernetPath -Name "Disabled" -Value 1 -Type DWord -Force -ErrorAction Stop
    Write-Host "'Turn off Microsoft Peer-to-Peer Networking Services' has been set to 'Enabled'." -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to set 'Disabled' to 1. $_" -ForegroundColor Red
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Peer-to-Peer Networking Services policy configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.6.11 - Network Connections Policies
# ==============================

Write-Host "Configuring Network Connections Policies..." -ForegroundColor Yellow

# Define the registry path
$netConnectionsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"

# Ensure the registry path exists
if (-not (Test-Path $netConnectionsPath)) {
    Write-Host "Registry path $netConnectionsPath does not exist. Creating it..."
    New-Item -Path $netConnectionsPath -Force | Out-Null
}

# 18.6.11.2 - Prohibit installation and configuration of Network Bridge on your DNS domain network (Enabled)
Set-ItemProperty -Path $netConnectionsPath -Name "NC_AllowNetBridge_NLA" -Type DWord -Value 0 -Force
Write-Host "18.6.11.2: 'Prohibit installation and configuration of Network Bridge on your DNS domain network' configured." -ForegroundColor Cyan

# 18.6.11.3 - Prohibit use of Internet Connection Sharing on your DNS domain network (Enabled)
Set-ItemProperty -Path $netConnectionsPath -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0 -Force
Write-Host "18.6.11.3: 'Prohibit use of Internet Connection Sharing on your DNS domain network' configured." -ForegroundColor Cyan

# 18.6.11.4 - Require domain users to elevate when setting a network's location (Enabled)
Set-ItemProperty -Path $netConnectionsPath -Name "NC_StdDomainUserSetLocation" -Type DWord -Value 1 -Force
Write-Host "18.6.11.4: 'Require domain users to elevate when setting a network's location' configured." -ForegroundColor Cyan

Write-Host "Network Connections Policies configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.6.14.1 - Hardened UNC Paths
# ==============================

Write-Host "Configuring Hardened UNC Paths..." -ForegroundColor Yellow

# Define the registry path
$hardenedPathsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

# Ensure the registry path exists
if (-not (Test-Path $hardenedPathsKey)) {
    Write-Host "Registry path $hardenedPathsKey does not exist. Creating it..."
    New-Item -Path $hardenedPathsKey -Force | Out-Null
}

# Define required values for NETLOGON and SYSVOL
$hardenedValue = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"

# 18.6.14.1 - Ensure 'Hardened UNC Paths' is set to 'Enabled' with all required flags
Set-ItemProperty -Path $hardenedPathsKey -Name "\\*\NETLOGON" -Type String -Value $hardenedValue -Force
Write-Host "18.6.14.1: Hardened UNC Path for NETLOGON configured." -ForegroundColor Cyan

Set-ItemProperty -Path $hardenedPathsKey -Name "\\*\SYSVOL" -Type String -Value $hardenedValue -Force
Write-Host "18.6.14.1: Hardened UNC Path for SYSVOL configured." -ForegroundColor Cyan

Write-Host "Hardened UNC Paths configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.6.19.2.1 - Disable IPv6 by setting 'DisabledComponents' to 0xFF (255)
Write-Host "Ensuring 'DisabledComponents' is set to 0xFF (255) to disable IPv6..."

$ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"

# Ensure the registry path exists
if (-not (Test-Path $ipv6Path)) {
    Write-Host "Registry path '$ipv6Path' not found. Creating it..."
    try {
        New-Item -Path $ipv6Path -Force | Out-Null
    }
    catch {
        Write-Error "Failed to create registry path '$ipv6Path'. Error: $($_.Exception.Message)"
        exit 1
    }
}

# Check if the property is already set to 255
$currentValue = (Get-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents

if ($currentValue -eq 255) {
    Write-Host "IPv6 is already disabled (DisabledComponents = 255)."
}
else {
    try {
        Set-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -Value 255 -Type DWord -Force -ErrorAction Stop
        Write-Host "DisabledComponents successfully set to 255."
    }
    catch {
        Write-Error "Failed to set DisabledComponents. Error: $($_.Exception.Message)"
        exit 1
    }
}

# Force a Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "IPv6 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# 18.6.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'

# Define the registry key path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"

# If the registry key doesn't exist, create it
if (!(Test-Path $regPath)) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN" -Name "Registrars" -Force | Out-Null
}

# Set each of the specified registry DWORD values to 0
New-ItemProperty -Path $regPath -Name "EnableRegistrars" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $regPath -Name "DisableUPnPRegistrar" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $regPath -Name "DisableInBand802DOT11Registrar" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $regPath -Name "DisableFlashConfigRegistrar" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $regPath -Name "DisableWPDRegistrar" -Value 0 -PropertyType DWORD -Force | Out-Null

Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "18.6.20.1 CIS Benchmarks complete." -Foreground Cyan

#########################################################################################################################

# 18.6.20.2 (L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'

# Define the registry key path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"

# If the registry key doesn't exist, create it
if (!(Test-Path $regPath)) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN" -Name "UI" -Force | Out-Null
}

# Set the registry DWORD value DisableWcnUi to 1
New-ItemProperty -Path $regPath -Name "DisableWcnUi" -Value 1 -PropertyType DWORD -Force | Out-Null

Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "18.6.20.2 CIS Benchmarks complete." -Foreground Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.6.21 - Network Connection Policies
# ==============================

Write-Host "Configuring Network Connection Policies..." -ForegroundColor Yellow

# Define the registry path
$wcmSvcKey = "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"

# Ensure the registry path exists
if (-not (Test-Path $wcmSvcKey)) {
    Write-Host "Registry path $wcmSvcKey does not exist. Creating it..."
    New-Item -Path $wcmSvcKey -Force | Out-Null
}

# 18.6.21.1 - Minimize the number of simultaneous connections to the Internet or a Windows Domain
Set-ItemProperty -Path $wcmSvcKey -Name "fMinimizeConnections" -Type DWord -Value 3 -Force
Write-Host "18.6.21.1: 'Minimize simultaneous connections' configured to '3 - Prevent Wi-Fi when on Ethernet'." -ForegroundColor Cyan

# 18.6.21.2 - Prohibit connection to non-domain networks when connected to domain authenticated network
Set-ItemProperty -Path $wcmSvcKey -Name "fBlockNonDomain" -Type DWord -Value 1 -Force
Write-Host "18.6.21.2: 'Prohibit connection to non-domain networks' configured to 'Enabled'." -ForegroundColor Cyan

Write-Host "Network Connection Policies configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.6.23.2.1 - Disable Auto-Connect to Open/Shared Hotspots
# ==============================

Write-Host "Ensuring 'AutoConnectAllowedOEM' is set to '0' (Disabled)..." -ForegroundColor Yellow

# Define registry path
$wifiConfigPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"

# Ensure registry path exists
if (-not (Test-Path $wifiConfigPath)) {
    Write-Host "Registry path $wifiConfigPath does not exist. Creating it..."
    New-Item -Path $wifiConfigPath -Force | Out-Null
}

# Set 'AutoConnectAllowedOEM' to 0 (Disabled)
Set-ItemProperty -Path $wifiConfigPath -Name "AutoConnectAllowedOEM" -Type DWord -Value 0 -Force
Write-Host "18.6.23.2.1: 'AutoConnectAllowedOEM' has been successfully set to '0' (Disabled)." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ALL TESTS PASSED UNTIL EVENT LOG POLICIES SECTION
# ==============================
# CIS Benchmark 18.7 - Printers
# ==============================

Write-Host "Configuring Printer security settings..." -ForegroundColor Cyan

# Define required registry paths
$printersPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$rpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
$deviceInstallPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverInstallation"
$pointAndPrintPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# Ensure all registry paths exist before applying settings
$paths = @($printersPath, $rpcPath, $deviceInstallPath, $pointAndPrintPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..."
        New-Item -Path $path -Force | Out-Null
    }
}

### CIS 18.7.1 - Allow Print Spooler to Accept Client Connections (DISABLED)
Set-ItemProperty -Path $printersPath -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord -Force
Write-Host "18.7.1 - Disabled Print Spooler remote client connections."

### CIS 18.7.2 - Configure Redirection Guard (ENABLED)
Set-ItemProperty -Path $printersPath -Name "RedirectionGuardPolicy" -Value 1 -Type DWord -Force
Write-Host "18.7.2 - Enabled Redirection Guard."

### CIS 18.7.3 - Configure RPC Connection Settings: Protocol to Use for Outgoing RPC Connections
Set-ItemProperty -Path $printersPath -Name "RpcUseNamedPipeProtocol" -Value 0 -Type DWord -Force
Write-Host "18.7.3 - Configured RPC outgoing connections to use 'RPC over TCP'."

### CIS 18.7.4 - Configure RPC Connection Settings: Use Authentication for Outgoing RPC Connections
Set-ItemProperty -Path $printersPath -Name "RpcAuthentication" -Value 0 -Type DWord -Force
Write-Host "18.7.4 - Set outgoing RPC authentication to 'Default'."

### CIS 18.7.5 - Configure RPC Listener Settings: Protocols to Allow for Incoming RPC Connections
Set-ItemProperty -Path $printersPath -Name "RpcProtocols" -Value 5 -Type DWord -Force
Write-Host "18.7.5 - Set incoming RPC protocol to 'RPC over TCP'."

### CIS 18.7.6 - Configure RPC Listener Settings: Authentication Protocol for Incoming RPC Connections
# Ensure ForceKerberosForRpc is set correctly (Negotiate authentication)
Set-ItemProperty -Path $printersPath -Name "ForceKerberosForRpc" -Value 1 -Type DWord -Force
Write-Host "18.7.6 - Configured 'ForceKerberosForRpc' for Negotiate authentication."

### CIS 18.7.7 - Configure RPC Over TCP Port (SET TO 0)
Set-ItemProperty -Path $printersPath -Name "RpcTcpPort" -Value 0 -Type DWord -Force
Write-Host "18.7.7 - RPC over TCP port set to '0'."

### CIS 18.7.8 - Limit print driver installation to Administrators
Set-ItemProperty -Path $pointAndPrintPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -Force
Write-Host "18.7.8 - Limited print driver installation to Administrators."

### CIS 18.7.9 - Manage Processing of Queue-Specific Files
Set-ItemProperty -Path $printersPath -Name "CopyFilesPolicy" -Value 1 -Type DWord -Force
Write-Host "18.7.9 - Limited Queue-specific files to Color profiles."

### CIS 18.7.10 - Point and Print Restrictions: When Installing Drivers for a New Connection
Set-ItemProperty -Path $pointAndPrintPath -Name "NoWarningNoElevationOnInstall" -Value 0 -Type DWord -Force
Write-Host "18.7.10 - Configured 'Point and Print Restrictions' for new driver installations."

### CIS 18.7.11 - Point and Print Restrictions: When Updating Drivers for an Existing Connection
Set-ItemProperty -Path $pointAndPrintPath -Name "UpdatePromptSettings" -Value 0 -Type DWord -Force
Write-Host "18.7.11 - Configured 'Point and Print Restrictions' for updating drivers."

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# 18.8.1.1 (L2) Ensure 'Turn off notifications network usage' is set to 'Enabled'

# Define the registry key path
$pushNotificationsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $pushNotificationsPath)) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion" -Name "PushNotifications" -Force | Out-Null
}

# Set the registry DWORD value 'NoCloudApplicationNotification' to 1
New-ItemProperty -Path $pushNotificationsPath -Name "NoCloudApplicationNotification" -Value 1 -PropertyType DWORD -Force | Out-Null

# 18.8.2 (L2) Ensure 'Remove Personalized Website Recommendations from the Recommended section in the Start Menu' is set to 'Enabled'

# Define the registry key path
$explorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $explorerPath)) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Explorer" -Force | Out-Null
}

# Set the registry DWORD value 'HideRecommendedPersonalizedSites' to 1
New-ItemProperty -Path $explorerPath -Name "HideRecommendedPersonalizedSites" -Value 1 -PropertyType DWORD -Force | Out-Null

gpupdate /Force
Write-Host "Group Policy updated for Benchmark 18.8.1-2." -Foreground Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.3.1 - Audit Process Creation
# ==============================
Write-Host "Starting CIS Benchmark 18.9.3 - Audit Process Creation ..."

# ==============================
# Ensure 'Include command line in process creation events' is set to 'Enabled'
# ==============================

Write-Host "Ensuring 'Include command line in process creation events' is set to 'Enabled'..." -ForegroundColor Yellow

# Define registry path
$auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

# Ensure the registry path exists
if (-not (Test-Path $auditPath)) {
    Write-Host "Registry path $auditPath does not exist. Creating it..."
    New-Item -Path $auditPath -Force | Out-Null
}

# Check if 'ProcessCreationIncludeCmdLine_Enabled' exists and is an incorrect type
$existingValue = Get-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue

if ($existingValue -and $existingValue.ProcessCreationIncludeCmdLine_Enabled -isnot [int]) {
    Write-Host "Incorrect type detected for 'ProcessCreationIncludeCmdLine_Enabled'. Removing incorrect entry..."
    Remove-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
}

# Set 'ProcessCreationIncludeCmdLine_Enabled' to 1 (Enabled)
Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 -Force
Write-Host "18.9.3.1: 'Include command line in process creation events' has been successfully set to 'Enabled'." -ForegroundColor Cyan

Write-Host "Configuration complete." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.4 - Credentials Delegation
# ==============================

Write-Host "Configuring Credentials Delegation settings..." -ForegroundColor Yellow

# Define registry paths
$credSSPPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
$credDelegationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"

# Ensure registry paths exist
$paths = @($credSSPPath, $credDelegationPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..."
        New-Item -Path $path -Force | Out-Null
    }
}

# CIS 18.9.4.1 - Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'
Write-Host "Ensuring 'Encryption Oracle Remediation' is set to 'Force Updated Clients'..."
Set-ItemProperty -Path $credSSPPath -Name "AllowEncryptionOracle" -Type DWord -Value 0 -Force
Write-Host "18.9.4.1: 'Encryption Oracle Remediation' successfully set to 'Force Updated Clients'." -ForegroundColor Cyan

# CIS 18.9.4.2 - Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'
Write-Host "Ensuring 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'..."
Set-ItemProperty -Path $credDelegationPath -Name "AllowProtectedCreds" -Type DWord -Value 1 -Force
Write-Host "18.9.4.2: 'Remote host allows delegation of non-exportable credentials' successfully set to 'Enabled'." -ForegroundColor Cyan

Write-Host "Credentials Delegation settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.5 - Device Guard (Windows 11 Only)
# ==============================

Write-Host "Configuring Device Guard Policies for Windows 11..." -ForegroundColor Yellow

# Ensure we are running on Windows 11; if not, exit this section.
if (-not $isWindows11) {
    Write-Host "Skipping Device Guard configurations. These settings apply only to Windows 11." -ForegroundColor Yellow
    return
}

# Define registry paths using the Policies branch
$deviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$hypervisorPath  = "$deviceGuardPath\Scenarios\HypervisorEnforcedCodeIntegrity"

# Ensure the registry paths exist
foreach ($path in @($deviceGuardPath, $hypervisorPath)) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..."
        New-Item -Path $path -Force | Out-Null
    }
}

# 18.9.5.1 - Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'
Write-Host "Ensuring 'Turn On Virtualization Based Security' is set to 'Enabled'..."
Set-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 1 -Force
Write-Host "18.9.5.1: 'Turn On Virtualization Based Security' set to Enabled." -ForegroundColor Cyan

# 18.9.5.2 - Ensure 'Select Platform Security Level' is set to 'Secure Boot' or higher
Write-Host "Ensuring 'Select Platform Security Level' is set to 'Secure Boot' or higher..."
Set-ItemProperty -Path $deviceGuardPath -Name "RequirePlatformSecurityFeatures" -Type DWord -Value 3 -Force
Write-Host "18.9.5.2: 'Select Platform Security Level' set." -ForegroundColor Cyan

# 18.9.5.3 - Ensure 'Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'
Write-Host "Ensuring 'Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'..."
Set-ItemProperty -Path $deviceGuardPath -Name "HypervisorEnforcedCodeIntegrity" -Type DWord -Value 1 -Force
Write-Host "18.9.5.3: 'Virtualization Based Protection of Code Integrity' set." -ForegroundColor Cyan

# 18.9.5.4 - Ensure 'Require UEFI Memory Attributes Table' is set to 'True (checked)'
Write-Host "Ensuring 'Require UEFI Memory Attributes Table' is set to 'True'..."
Set-ItemProperty -Path $deviceGuardPath -Name "HVCIMATRequired" -Type DWord -Value 1 -Force
Write-Host "18.9.5.4: 'Require UEFI Memory Attributes Table' set." -ForegroundColor Cyan

# 18.9.5.5 - Ensure 'Credential Guard Configuration' is set to 'Enabled with UEFI lock'
Write-Host "Ensuring 'Credential Guard Configuration' is set to 'Enabled with UEFI lock'..."
Set-ItemProperty -Path $deviceGuardPath -Name "LsaCfgFlags" -Type DWord -Value 1 -Force
Write-Host "18.9.5.5: 'Credential Guard Configuration' set." -ForegroundColor Cyan

# 18.9.5.6 - Ensure 'Secure Launch Configuration' is set to 'Enabled'
Write-Host "Ensuring 'Secure Launch Configuration' is set to 'Enabled'..."
Set-ItemProperty -Path $deviceGuardPath -Name "ConfigureSystemGuardLaunch" -Type DWord -Value 1 -Force
Write-Host "18.9.5.6: 'Secure Launch Configuration' set." -ForegroundColor Cyan

# 18.9.5.7 - Ensure 'Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled in enforcement mode'
Write-Host "Ensuring 'Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled in enforcement mode'..."
Set-ItemProperty -Path $deviceGuardPath -Name "ConfigureKernelShadowStacksLaunch" -Type DWord -Value 1 -Force
Write-Host "18.9.5.7: 'Kernel-mode Hardware-enforced Stack Protection' set." -ForegroundColor Cyan

Write-Host "Device Guard Policies configured successfully for Windows 11." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Group Policy update completed." -ForegroundColor Cyan

#########################################################################################################################
<#
# CIS Benchmarks 18.9.7.1.1-7

# Define the base key for DeviceInstall restrictions
$baseKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall"
$restrictionsKey = "$baseKey\Restrictions"

# Ensure the parent key exists
if (-not (Test-Path $baseKey)) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall" -Force | Out-Null
}

# Ensure the Restrictions key exists
if (-not (Test-Path $restrictionsKey)) {
    New-Item -Path $baseKey -Name "Restrictions" -Force | Out-Null
}

### 18.9.7.1.1: Enable DenyDeviceIDs (DWORD = 1)
New-ItemProperty -Path $restrictionsKey -Name "DenyDeviceIDs" -Value 1 -PropertyType DWORD -Force | Out-Null

### 18.9.7.1.2: Under DenyDeviceIDs, add a rule (subkey "1") with the device ID "PCI\CC_0C0A"
$denyDeviceIDsSubKey = "$restrictionsKey\DenyDeviceIDs\1"
if (-not (Test-Path $denyDeviceIDsSubKey)) {
    # Creating the subkey and setting its default value
    New-Item -Path "$restrictionsKey\DenyDeviceIDs" -Name "1" -Force -Value "PCI\CC_0C0A" | Out-Null
} else {
    # Update the default value if the subkey already exists
    Set-ItemProperty -Path $denyDeviceIDsSubKey -Name "(default)" -Value "PCI\CC_0C0A" -Force | Out-Null
}

### 18.9.7.1.3: Enable DenyDeviceIDsRetroactive (DWORD = 1)
New-ItemProperty -Path $restrictionsKey -Name "DenyDeviceIDsRetroactive" -Value 1 -PropertyType DWORD -Force | Out-Null

### 18.9.7.1.4: Enable DenyDeviceClasses (DWORD = 1)
New-ItemProperty -Path $restrictionsKey -Name "DenyDeviceClasses" -Value 1 -PropertyType DWORD -Force | Out-Null

### 18.9.7.1.5: Under DenyDeviceClasses, add a rule (subkey "1") with the regex "\w+"
$denyDeviceClassesSubKey = "$restrictionsKey\DenyDeviceClasses\1"
if (-not (Test-Path $denyDeviceClassesSubKey)) {
    New-Item -Path "$restrictionsKey\DenyDeviceClasses" -Name "1" -Force -Value "\w+" | Out-Null
} else {
    Set-ItemProperty -Path $denyDeviceClassesSubKey -Name "(default)" -Value "\w+" -Force | Out-Null
}

### 18.9.7.1.6: Set DenyDeviceClassesRetroactive to the regex "\w+" (as a string value)
New-ItemProperty -Path $restrictionsKey -Name "DenyDeviceClassesRetroactive" -Value "\w+" -PropertyType String -Force | Out-Null

gpupdate /force
Write-Host "DeviceInstall restrictions have been configured."
#>

# CIS Benchmarks 18.9.7.1.1-7

# Define the base key for DeviceInstall restrictions
$baseKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall"
$restrictionsKey = "$baseKey\Restrictions"

# Ensure the parent key exists
if (-not (Test-Path $baseKey)) {
    New-Item -Path $baseKey -Force | Out-Null
}

# Ensure the Restrictions key exists
if (-not (Test-Path $restrictionsKey)) {
    New-Item -Path $restrictionsKey -Force | Out-Null
}

### 18.9.7.1.1: Enable DenyDeviceIDs (DWORD = 1)
New-ItemProperty -Path $restrictionsKey -Name "DenyDeviceIDs" -Value 1 -PropertyType DWORD -Force | Out-Null

### 18.9.7.1.2: Under DenyDeviceIDs, add a rule (subkey "1") with the device ID "PCI\CC_0C0A"
$denyDeviceIDsRuleKey = "$restrictionsKey\DenyDeviceIDs\1"
if (-not (Test-Path $denyDeviceIDsRuleKey)) {
    New-Item -Path "$restrictionsKey\DenyDeviceIDs" -Name "1" -Force | Out-Null
}
Set-ItemProperty -Path $denyDeviceIDsRuleKey -Name "(default)" -Value "PCI\CC_0C0A" -Force

### 18.9.7.1.3: Enable DenyDeviceIDsRetroactive (DWORD = 1)
New-ItemProperty -Path $restrictionsKey -Name "DenyDeviceIDsRetroactive" -Value 1 -PropertyType DWORD -Force | Out-Null

### 18.9.7.1.4: Enable DenyDeviceClasses (DWORD = 1)
New-ItemProperty -Path $restrictionsKey -Name "DenyDeviceClasses" -Value 1 -PropertyType DWORD -Force | Out-Null

### 18.9.7.1.5: Under DenyDeviceClasses, add a rule (subkey "1") with the regex "\w+"
$denyDeviceClassesRuleKey = "$restrictionsKey\DenyDeviceClasses\1"
if (-not (Test-Path $denyDeviceClassesRuleKey)) {
    New-Item -Path "$restrictionsKey\DenyDeviceClasses" -Name "1" -Force | Out-Null
}
Set-ItemProperty -Path $denyDeviceClassesRuleKey -Name "(default)" -Value "\w+" -Force

### 18.9.7.1.6: Set DenyDeviceClassesRetroactive to the regex "\w+" (as a string value)
New-ItemProperty -Path $restrictionsKey -Name "DenyDeviceClassesRetroactive" -Value "\w+" -PropertyType String -Force | Out-Null

gpupdate /force
Write-Host "DeviceInstall restrictions have been configured." -ForegroundColor Green

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.7.2 - Prevent Device Metadata Retrieval from the Internet
# ==============================

Write-Host "Configuring 'Prevent device metadata retrieval from the Internet'..." -ForegroundColor Cyan

# Define registry path
$deviceMetadataPath = "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata"

# Ensure the registry path exists
if (-not (Test-Path $deviceMetadataPath)) {
    Write-Host "Registry path $deviceMetadataPath does not exist. Creating it..."
    New-Item -Path $deviceMetadataPath -Force | Out-Null
}

# Set 'PreventDeviceMetadataFromNetwork' to 1 (Enabled)
Set-ItemProperty -Path $deviceMetadataPath -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force
Write-Host "18.9.7.2: 'Prevent device metadata retrieval from the Internet' has been successfully set to 'Enabled'." -ForegroundColor Cyan

Write-Host "Configuration complete." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.13.1 - Boot-Start Driver Initialization Policy
# ==============================

Write-Host "Configuring 'Boot-Start Driver Initialization Policy'..." -ForegroundColor Cyan

# Define registry path
$earlyLaunchPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"

# Ensure the registry path exists
if (-not (Test-Path $earlyLaunchPath)) {
    Write-Host "Registry path $earlyLaunchPath does not exist. Creating it..."
    New-Item -Path $earlyLaunchPath -Force | Out-Null
}

# Set 'DriverLoadPolicy' to 3 (Enabled: Good, unknown, and bad but critical)
Set-ItemProperty -Path $earlyLaunchPath -Name "DriverLoadPolicy" -Value 3 -Type DWord -Force
Write-Host "18.9.13.1: 'Boot-Start Driver Initialization Policy' has been successfully set to 'Enabled: Good, unknown, and bad but critical'." -ForegroundColor Cyan

Write-Host "Configuration complete." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.19 - Logging and Tracing
# ==============================

Write-Host "Configuring Logging and Tracing Policies..." -ForegroundColor Cyan

# Define registry paths based on confirmed locations
$gpBasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"
$gpProcessingPath = "$gpBasePath\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$securityPolicyPath = "$gpBasePath\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
$systemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$disableGpRefreshPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Ensure registry paths exist
$paths = @($gpProcessingPath, $securityPolicyPath, $systemPath, $disableGpRefreshPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..."
        New-Item -Path $path -Force | Out-Null
    }
}

# ==============================
# Updated Registry Settings
# ==============================

# 18.9.19.2 - Configure registry policy processing: Do not apply during periodic background processing
Set-ItemProperty -Path $gpProcessingPath -Name "NoBackgroundPolicy" -Type DWord -Value 0 -Force
Write-Host "18.9.19.2 - 'Do not apply during periodic background processing' set to Disabled (0)." -ForegroundColor Cyan

# 18.9.19.3 - Configure registry policy processing: Process even if the Group Policy objects have not changed
Set-ItemProperty -Path $gpProcessingPath -Name "NoGPOListChanges" -Type DWord -Value 0 -Force
Write-Host "18.9.19.3 - 'Process even if the Group Policy objects have not changed' set to Enabled (0)." -ForegroundColor Cyan

# 18.9.19.4 - Configure security policy processing: Do not apply during periodic background processing
Set-ItemProperty -Path $securityPolicyPath -Name "NoBackgroundPolicy" -Type DWord -Value 0 -Force
Write-Host "18.9.19.4 - 'Do not apply during periodic background processing' set to Disabled (0)." -ForegroundColor Cyan

# 18.9.19.5 - Configure security policy processing: Process even if the Group Policy objects have not changed
Set-ItemProperty -Path $securityPolicyPath -Name "NoGPOListChanges" -Type DWord -Value 0 -Force
Write-Host "18.9.19.5 - 'Process even if the Group Policy objects have not changed' set to Enabled (0)." -ForegroundColor Cyan

# 18.9.19.6 - Continue experiences on this device (DISABLED)
Set-ItemProperty -Path $systemPath -Name "EnableCdp" -Type DWord -Value 0 -Force
Write-Host "18.9.19.6 - Disabled 'Continue experiences on this device' (0)." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

# ==============================
# CIS Benchmark 18.9.19.7 - Turn off background refresh of Group Policy (Not Configured)
# ==============================

Write-Host "Ensuring 'Turn off background refresh of Group Policy' is set to 'Not Configured'..." -ForegroundColor Yellow

$disableGpRefreshPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$registryName = "DisableBkGndGroupPolicy"

# Check if the registry key exists
if (Test-Path $disableGpRefreshPath) {
    $existingValue = Get-ItemProperty -Path $disableGpRefreshPath -Name $registryName -ErrorAction SilentlyContinue
    if ($existingValue) {
        Write-Host "Removing 'DisableBkGndGroupPolicy' to set it to 'Not Configured'..."
        Remove-ItemProperty -Path $disableGpRefreshPath -Name $registryName -Force
        Write-Host "18.9.19.7: Successfully removed 'DisableBkGndGroupPolicy'. It is now 'Not Configured'." -ForegroundColor Green
    } else {
        Write-Host "18.9.19.7: 'DisableBkGndGroupPolicy' is already 'Not Configured'." -ForegroundColor Cyan
    }
} else {
    Write-Host "18.9.19.7: Registry path does not exist, no changes needed." -ForegroundColor Cyan
}

Write-Host "Configuration complete for 'Turn off background refresh of Group Policy'." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.20.1 - Internet Communication Settings
# ==============================

Write-Host "Configuring Internet Communication Settings..." -ForegroundColor Cyan

# Define required registry paths
$printersPath                   = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
$explorerPath                   = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$tabletPCPath                   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
$handwritingErrorReportsPath    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
$internetConnectionWizardPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
$registrationWizardControlPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
$searchCompanionPath            = "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"
$messengerClientPath            = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
$sqmClientPath                  = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
$windowsErrorReportingPath      = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"

# Ensure registry paths exist before applying settings
$paths = @(
    $printersPath,
    $explorerPath,
    $tabletPCPath,
    $handwritingErrorReportsPath,
    $internetConnectionWizardPath,
    $registrationWizardControlPath,
    $searchCompanionPath,
    $messengerClientPath,
    $sqmClientPath,
    $windowsErrorReportingPath
)

foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $path -Force | Out-Null
    }
}

# ==============================
# CIS Benchmark 18.9.20.1.1 - Ensure 'Turn off access to the Store' is set to 'Enabled'
# ==============================

$storePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"

# Ensure the registry path exists
if (-not (Test-Path $storePolicyPath)) {
    New-Item -Path $storePolicyPath -Force | Out-Null
}

# Set NoUseStoreOpenWith = 1
Set-ItemProperty -Path $storePolicyPath -Name "NoUseStoreOpenWith" -Value 1 -Type DWord -Force
Write-Host "CIS 18.9.20.1.1: 'NoUseStoreOpenWith' set to 1 (Enabled)" -ForegroundColor Green

# 18.9.20.1.2 - Turn off downloading of print drivers over HTTP (Enabled)
Set-ItemProperty -Path $printersPath -Name "DisableWebPnPDownload" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.2 - 'Turn off downloading of print drivers over HTTP' has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.3 - Prevent Handwriting Data Sharing (Enabled)
Set-ItemProperty -Path $tabletPCPath -Name "PreventHandwritingDataSharing" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.3 - 'Prevent Handwriting Data Sharing' has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.4 - Prevent Handwriting Error Reports (Enabled)
Set-ItemProperty -Path $handwritingErrorReportsPath -Name "PreventHandwritingErrorReports" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.4 - 'Prevent Handwriting Error Reports' has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.5 - Exit on MSI Connection Wizard (Enabled)
Set-ItemProperty -Path $internetConnectionWizardPath -Name "ExitOnMSICW" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.5 - 'Exit on MSI Connection Wizard' has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.6 - Turn off Internet download for Web publishing and online ordering wizards (Enabled)
Set-ItemProperty -Path $explorerPath -Name "NoWebServices" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.6 - 'Turn off Internet download for Web publishing and online ordering wizards' has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.7 - Disable HTTP Printing (Enabled)
Set-ItemProperty -Path $printersPath -Name "DisableHTTPPrinting" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.7 - 'Disable HTTP Printing' has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.8 - No Registration in Registration Wizard Control (Enabled)
Set-ItemProperty -Path $registrationWizardControlPath -Name "NoRegistration" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.8 - 'No Registration' in Registration Wizard Control has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.9 - Disable Content File Updates for Search Companion (Enabled)
Set-ItemProperty -Path $searchCompanionPath -Name "DisableContentFileUpdates" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.9 - 'Disable Content File Updates' for Search Companion has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.10 - No Online Prints Wizard (Enabled)
Set-ItemProperty -Path $explorerPath -Name "NoOnlinePrintsWizard" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.10 - 'No Online Prints Wizard' has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.11 - No Publishing Wizard (Enabled)
Set-ItemProperty -Path $explorerPath -Name "NoPublishingWizard" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.11 - 'No Publishing Wizard' has been set to 'Enabled'." -ForegroundColor Cyan

# 18.9.20.1.12 - Messenger CEIP (Set to 2)
Set-ItemProperty -Path $messengerClientPath -Name "CEIP" -Type DWord -Value 2 -Force
Write-Host "18.9.20.1.12 - 'Messenger CEIP' has been set to '2'." -ForegroundColor Cyan

# 18.9.20.1.13 - SQM Client CEIP Enable (Set to 0)
Set-ItemProperty -Path $sqmClientPath -Name "CEIPEnable" -Type DWord -Value 0 -Force
Write-Host "18.9.20.1.13 - 'SQM Client CEIP Enable' has been set to '0'." -ForegroundColor Cyan

# 18.9.20.1.14 - Windows Error Reporting Disabled (Enabled)
Set-ItemProperty -Path $windowsErrorReportingPath -Name "Disabled" -Type DWord -Value 1 -Force
Write-Host "18.9.20.1.14 - 'Windows Error Reporting Disabled' has been set to 'Enabled'." -ForegroundColor Cyan

Write-Host "Internet Communication Settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.23.1 - Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'
# ==============================

$kerberosPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"

# Ensure the registry path exists
if (-not (Test-Path $kerberosPath)) {
    New-Item -Path $kerberosPath -Force | Out-Null
}

# Set DevicePKInitBehavior = 0 and DevicePKInitEnabled = 1
Set-ItemProperty -Path $kerberosPath -Name "DevicePKInitBehavior" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $kerberosPath -Name "DevicePKInitEnabled" -Value 1 -Type DWord -Force

Write-Host "CIS 18.9.23.1: 'DevicePKInitBehavior=0' and 'DevicePKInitEnabled=1' applied successfully." -ForegroundColor Green

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.24.1 - Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'
# ==============================

$dmaPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"

# Ensure the registry path exists
if (-not (Test-Path $dmaPolicyPath)) {
    New-Item -Path $dmaPolicyPath -Force | Out-Null
}

# Set DeviceEnumerationPolicy = 0
Set-ItemProperty -Path $dmaPolicyPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord -Force
Write-Host "CIS 18.9.24.1: 'DeviceEnumerationPolicy' set to 0 (Block All)" -ForegroundColor Green

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.25 - LAPS Configuration
# ==============================

Write-Host "Configuring LAPS (Local Administrator Password Solution) settings..." -ForegroundColor Cyan

# Define required registry path
$lapsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

# Ensure the registry path exists before applying settings
if (-not (Test-Path $lapsPath)) {
    Write-Host "Registry path $lapsPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $lapsPath -Force | Out-Null
}

### CIS 18.9.25.1 - Configure Password Backup Directory
# Set BackupDirectory to 1 (Active Directory)
Set-ItemProperty -Path $lapsPath -Name "BackupDirectory" -Type DWord -Value 1 -Force
Write-Host "18.9.25.1 - 'Configure password backup directory' set to 'Active Directory'." -ForegroundColor Cyan

# Uncomment if you need to enable Azure Active Directory backup instead
# Set-ItemProperty -Path $lapsPath -Name "BackupDirectory" -Type DWord -Value 2 -Force
# Write-Host "18.9.25.1 - 'Configure password backup directory' set to 'Azure Active Directory'." -ForegroundColor Cyan

### CIS 18.9.25.2 - Do not allow password expiration time longer than required by policy
Set-ItemProperty -Path $lapsPath -Name "PwdExpirationProtectionEnabled" -Type DWord -Value 1 -Force
Write-Host "18.9.25.2 - 'Do not allow password expiration time longer than required by policy' set to 'Enabled'." -ForegroundColor Cyan

### CIS 18.9.25.3 - Enable Password Encryption
Set-ItemProperty -Path $lapsPath -Name "ADPasswordEncryptionEnabled" -Type DWord -Value 1 -Force
Write-Host "18.9.25.3 - 'Enable password encryption' set to 'Enabled'." -ForegroundColor Cyan

### CIS 18.9.25.4 - Password Complexity (Large + Small Letters + Numbers + Special Characters)
Set-ItemProperty -Path $lapsPath -Name "PasswordComplexity" -Type DWord -Value 4 -Force
Write-Host "18.9.25.4 - 'Password Complexity' set to 'Large letters + Small letters + Numbers + Special Characters'." -ForegroundColor Cyan

### CIS 18.9.25.5 - Password Length (15 or more)
Set-ItemProperty -Path $lapsPath -Name "PasswordLength" -Type DWord -Value 15 -Force
Write-Host "18.9.25.5 - 'Password Length' set to '15 or more characters'." -ForegroundColor Cyan

### CIS 18.9.25.6 - Password Age (30 or fewer days)
Set-ItemProperty -Path $lapsPath -Name "PasswordAgeDays" -Type DWord -Value 30 -Force
Write-Host "18.9.25.6 - 'Password Age' set to '30 days or fewer'." -ForegroundColor Cyan

### CIS 18.9.25.7 - Post-authentication Actions: Grace Period (8 or fewer hours, but not 0)
Set-ItemProperty -Path $lapsPath -Name "PostAuthenticationResetDelay" -Type DWord -Value 8 -Force
Write-Host "18.9.25.7 - 'Post-authentication grace period' set to '8 hours'." -ForegroundColor Cyan

### CIS 18.9.25.8 - Post-authentication Actions: Reset Password and Logoff
# Set PostAuthenticationActions to 3 (Reset password and logoff managed account)
Set-ItemProperty -Path $lapsPath -Name "PostAuthenticationActions" -Type DWord -Value 3 -Force
Write-Host "18.9.25.8 - 'Post-authentication actions' set to 'Reset the password and logoff the managed account'." -ForegroundColor Cyan

# Uncomment if you need to set it to 5 instead
# Set-ItemProperty -Path $lapsPath -Name "PostAuthenticationActions" -Type DWord -Value 5 -Force
# Write-Host "18.9.25.8 - 'Post-authentication actions' set to 'Reset the password and enforce account disablement'." -ForegroundColor Cyan

Write-Host "LAPS configuration applied successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.26 - Local Security Authority (LSASS)
# ==============================

Write-Host "Configuring Local Security Authority (LSASS) settings..." -ForegroundColor Cyan

# Define required registry paths
$lsaSystemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$lsaControlPath = "HKLM:\System\CurrentControlSet\Control\Lsa"

# Ensure the registry paths exist before applying settings
$paths = @($lsaSystemPath, $lsaControlPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $path -Force | Out-Null
    }
}

# CIS 18.9.26.1 - Allow Custom SSPs and APs to be loaded into LSASS (DISABLED)
Set-ItemProperty -Path $lsaSystemPath -Name "AllowCustomSSPsAPs" -Type DWord -Value 0 -Force
Write-Host "18.9.26.1 - 'Allow Custom SSPs and APs to be loaded into LSASS' set to 'Disabled'." -ForegroundColor Cyan

# CIS 18.9.26.2 - Configures LSASS to run as a protected process (Windows 11 ONLY)
if ($isWindows11) {
    Write-Host "Windows 11 detected. Ensuring 'Configures LSASS to run as a protected process' is set correctly..."
    
    $runAsPPLValue = (Get-ItemProperty -Path $lsaControlPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL

    if ($runAsPPLValue -ne 1) {
        Write-Host "18.9.26.2 - 'RunAsPPL' is not set correctly. Updating to 'Enabled with UEFI Lock'..."
        Set-ItemProperty -Path $lsaControlPath -Name "RunAsPPL" -Type DWord -Value 1 -Force
        Write-Host "18.9.26.2 - 'RunAsPPL' successfully set to 'Enabled with UEFI Lock'." -ForegroundColor Cyan
    } else {
        Write-Host "18.9.26.2 - 'RunAsPPL' is already set correctly." -ForegroundColor Green
    }
} else {
    Write-Host "Windows 10 detected. Skipping 'RunAsPPL' configuration as it is not required." -ForegroundColor Yellow
}

Write-Host "Local Security Authority (LSASS) configuration applied successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.9.27.1

# Define the registry path for International settings
$intlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $intlPath)) {
    Write-Host "Registry path $intlPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel" -Name "International" -Force | Out-Null
}

# Set the registry DWORD value 'BlockUserInputMethodsForSignIn' to 1
New-ItemProperty -Path $intlPath -Name "BlockUserInputMethodsForSignIn" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.9.27.1 - 'BlockUserInputMethodsForSignIn' has been set to '1'." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.28 - Logon
# ==============================

Write-Host "Configuring Logon settings..." -ForegroundColor Cyan

# Define registry path
$logonPath = "HKLM:\Software\Policies\Microsoft\Windows\System"

# Ensure the registry path exists before applying settings
if (-not (Test-Path $logonPath)) {
    Write-Host "Registry path $logonPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $logonPath -Force | Out-Null
}

# Define registry settings for CIS compliance
$logonSettings = @(
    @{ Name = "BlockUserFromShowingAccountDetailsOnSignin"; Value = 1; Description = "Block user from showing account details on sign-in" }
    @{ Name = "DontDisplayNetworkSelectionUI"; Value = 1; Description = "Do not display network selection UI" }
    @{ Name = "DontEnumerateConnectedUsers"; Value = 1; Description = "Do not enumerate connected users on domain-joined computers" }
    @{ Name = "EnumerateLocalUsers"; Value = 0; Description = "Enumerate local users on domain-joined computers (Disabled)" }
    @{ Name = "DisableLockScreenAppNotifications"; Value = 1; Description = "Turn off app notifications on the lock screen" }
    @{ Name = "BlockDomainPicturePassword"; Value = 1; Description = "Turn off picture password sign-in" }
    @{ Name = "AllowDomainPINLogon"; Value = 0; Description = "Turn on convenience PIN sign-in (Disabled)" }
)

# Apply each setting
foreach ($setting in $logonSettings) {
    Write-Host "Ensuring '$($setting.Description)' is set correctly..."
    Set-ItemProperty -Path $logonPath -Name $setting.Name -Type DWord -Value $setting.Value -Force
    Write-Host "18.9.28 - '$($setting.Description)' has been successfully set." -ForegroundColor Cyan
}

Write-Host "Logon settings configuration completed successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Bencmark 18.9.31.1 - 2

# Define the registry path for System settings
$systemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $systemPath)) {
    Write-Host "Registry path $systemPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -Force | Out-Null
}

# 18.9.31.1 - Set AllowCrossDeviceClipboard to 0
New-ItemProperty -Path $systemPath -Name "AllowCrossDeviceClipboard" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.9.31.1 - 'AllowCrossDeviceClipboard' has been set to '0'." -ForegroundColor Cyan

# 18.9.31.2 - Set UploadUserActivities to 0
New-ItemProperty -Path $systemPath -Name "UploadUserActivities" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.9.31.2 - 'UploadUserActivities' has been set to '0'." -ForegroundColor Cyan

gpupdate /force
Write-Host "Benchmarks 18.9.31.1-2 have been updated." -Foreground Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.33.6 - Sleep Settings
# ==============================

Write-Host "Configuring Sleep Settings..." -ForegroundColor Cyan

# Define registry paths
$sleepSettings = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"; Name = "DCSettingIndex"; Value = 0; Description = "Allow network connectivity during connected-standby (on battery) - Disabled" }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"; Name = "ACSettingIndex"; Value = 0; Description = "Allow network connectivity during connected-standby (plugged in) - Disabled" }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name = "DCSettingIndex"; Value = 1; Description = "Require a password when a computer wakes (on battery) - Enabled" }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name = "ACSettingIndex"; Value = 1; Description = "Require a password when a computer wakes (plugged in) - Enabled" }
)

# Ensure registry paths exist before applying settings
foreach ($setting in $sleepSettings) {
    if (-not (Test-Path $setting.Path)) {
        Write-Host "Registry path $($setting.Path) does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $setting.Path -Force | Out-Null
    }
    
    # Apply the registry setting
    Write-Host "Ensuring '$($setting.Description)' is set correctly..."
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Type DWord -Value $setting.Value -Force
    Write-Host "18.9.33.6 - '$($setting.Description)' has been successfully set." -ForegroundColor Cyan
}

# More sleep settings according to Wazuh

# Define the full registry path for the specified power settings GUID
$guidKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"

# Ensure the parent keys exist
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Power" -Force | Out-Null
}
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power" -Name "PowerSettings" -Force | Out-Null
}
if (-not (Test-Path $guidKey)) {
    Write-Host "Registry path $guidKey does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings" -Name "abfc2519-3608-4c2a-94ea-171b0ed546ab" -Force | Out-Null
}

# Set DCSettingIndex to 0
New-ItemProperty -Path $guidKey -Name "DCSettingIndex" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.9.33.6.3 - 'DCSettingIndex' set to '0'." -ForegroundColor Cyan

# Set ACSettingIndex to 0
New-ItemProperty -Path $guidKey -Name "ACSettingIndex" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.9.33.6.4 - 'ACSettingIndex' set to '0'." -ForegroundColor Cyan

Write-Host "Sleep settings configuration completed successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.35 - Remote Assistance
# ==============================

Write-Host "Configuring Remote Assistance settings..." -ForegroundColor Cyan

# Define registry path
$remoteAssistancePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure registry path exists before applying settings
if (-not (Test-Path $remoteAssistancePath)) {
    Write-Host "Registry path $remoteAssistancePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $remoteAssistancePath -Force | Out-Null
}

# Define settings
$remoteAssistanceSettings = @(
    @{ Name = "fAllowUnsolicited"; Value = 0; Description = "Configure Offer Remote Assistance - Disabled" }
    @{ Name = "fAllowToGetHelp"; Value = 0; Description = "Configure Solicited Remote Assistance - Disabled" }
)

# Apply settings
foreach ($setting in $remoteAssistanceSettings) {
    Write-Host "Ensuring '$($setting.Description)' is set correctly..."
    Set-ItemProperty -Path $remoteAssistancePath -Name $setting.Name -Type DWord -Value $setting.Value -Force
    Write-Host "18.9.35 - '$($setting.Description)' has been successfully set." -ForegroundColor Cyan
}

Write-Host "Remote Assistance settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.9.36 - Remote Procedure Call (RPC)
# ==============================

Write-Host "Configuring Remote Procedure Call (RPC) settings..." -ForegroundColor Cyan

# Define registry path
$rpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"

# Ensure registry path exists before applying settings
if (-not (Test-Path $rpcPath)) {
    Write-Host "Registry path $rpcPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $rpcPath -Force | Out-Null
}

# Define settings
$rpcSettings = @(
    @{ Name = "EnableAuthEpResolution"; Value = 1; Description = "Enable RPC Endpoint Mapper Client Authentication - Enabled" }
    @{ Name = "RestrictRemoteClients"; Value = 1; Description = "Restrict Unauthenticated RPC Clients - Enabled: Authenticated" }
)

# Apply settings
foreach ($setting in $rpcSettings) {
    Write-Host "Ensuring '$($setting.Description)' is set correctly..."
    Set-ItemProperty -Path $rpcPath -Name $setting.Name -Type DWord -Value $setting.Value -Force
    Write-Host "18.9.36 - '$($setting.Description)' has been successfully set." -ForegroundColor Cyan
}

Write-Host "Remote Procedure Call (RPC) settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.9.47.5.1

# Define the registry path for ScriptedDiagnosticsProvider Policy settings
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $policyPath)) {
    Write-Host "Registry path $policyPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider" -Name "Policy" -Force | Out-Null
}

# Set the registry DWORD value 'DisableQueryRemoteServer' to 0
New-ItemProperty -Path $policyPath -Name "DisableQueryRemoteServer" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.9.47.5.1 - 'DisableQueryRemoteServer' has been set to 0." -ForegroundColor Cyan

gpupdate /Force
Write-Host "CIS Benchmark 18.9.47.5.1 completed." -Foreground Cyan

#########################################################################################################################

# CIS Benchmark 18.9.47.11.1

# Define the registry path for WDI settings with the specific GUID
$wdiKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $wdiKey)) {
    Write-Host "Registry path $wdiKey does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI" -Name "{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Force | Out-Null
}

# Set the registry DWORD value 'ScenarioExecutionEnabled' to 0
New-ItemProperty -Path $wdiKey -Name "ScenarioExecutionEnabled" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.9.47.11.1 - 'ScenarioExecutionEnabled' has been set to 0." -ForegroundColor Cyan

gpupdate /Force
Write-Host "CIS Benchmark 18.9.47.11.1 completed." -Foreground Cyan

#########################################################################################################################

# CIS Benchmark 18.9.49.1

# Define the registry path for AdvertisingInfo settings
$advInfoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $advInfoPath)) {
    Write-Host "Registry path $advInfoPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AdvertisingInfo" -Force | Out-Null
}

# Set the registry DWORD value 'DisabledByGroupPolicy' to 1
New-ItemProperty -Path $advInfoPath -Name "DisabledByGroupPolicy" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.9.49.1 - 'DisabledByGroupPolicy' has been set to 1." -ForegroundColor Cyan

gpupdate /Force
Write-Host "CIS Benchmark 18.9.49.1 completed." -Foreground Cyan

#########################################################################################################################
# ==============================
# CIS Benchmark 18.9.51.1 - Time Providers
# ==============================

Write-Host "Configuring Time Providers settings..." -ForegroundColor Cyan

# Define registry paths
$ntpClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient"
$ntpServerPath = "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer"

# Ensure registry paths exist before applying settings
$paths = @($ntpClientPath, $ntpServerPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $path -Force | Out-Null
    }
}

# Define time provider settings
$timeProviderSettings = @(
    @{ Path = $ntpClientPath; Name = "Enabled"; Value = 1; Description = "Enable Windows NTP Client - Enabled" }
    @{ Path = $ntpServerPath; Name = "Enabled"; Value = 0; Description = "Enable Windows NTP Server - Disabled" }
)

# Apply settings
foreach ($setting in $timeProviderSettings) {
    Write-Host "Ensuring '$($setting.Description)' is set correctly..."
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Type DWord -Value $setting.Value -Force
    Write-Host "18.9.51.1 - '$($setting.Description)' has been successfully set." -ForegroundColor Cyan
}

Write-Host "Time Providers settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.3.2 - App Package Deployment
# ==============================

Write-Host "Configuring App Package Deployment settings..." -ForegroundColor Cyan

# Define registry path
$appxPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"

# Ensure registry path exists before applying settings
if (-not (Test-Path $appxPath)) {
    Write-Host "Registry path $appxPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $appxPath -Force | Out-Null
}

# Apply the required setting
Set-ItemProperty -Path $appxPath -Name "BlockNonAdminUserInstall" -Type DWord -Value 1 -Force
Write-Host "18.10.3.2 - 'Prevent non-admin users from installing packaged Windows apps' has been successfully set to 'Enabled'." -ForegroundColor Cyan

Write-Host "App Package Deployment settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Bencmark 18.10.4.1
# ==============================

Write-Host "Configuring 'Let Windows apps activate with voice while the system is locked'..." -ForegroundColor Cyan

# Define registry path
$appPrivacyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"

# Ensure the registry path exists
if (-not (Test-Path $appPrivacyPath)) {
    Write-Host "Registry path $appPrivacyPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $appPrivacyPath -Force | Out-Null
}

# Set the policy to 'Force Deny' (CIS Recommended)
Set-ItemProperty -Path $appPrivacyPath -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2 -Force
Write-Host "Policy 'Let Windows apps activate with voice while the system is locked' has been set to 'Force Deny'." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.5.1 - Allow Microsoft accounts to be optional
# ==============================

Write-Host "Configuring 'Allow Microsoft accounts to be optional'..." -ForegroundColor Cyan

# Define registry path
$systemPolicyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

# Ensure the registry path exists
if (-not (Test-Path $systemPolicyPath)) {
    Write-Host "Registry path $systemPolicyPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $systemPolicyPath -Force | Out-Null
}

# Set 'MSAOptional' to 1 (Enabled)
Set-ItemProperty -Path $systemPolicyPath -Name "MSAOptional" -Type DWord -Value 1 -Force
Write-Host "18.10.5.1 - 'Allow Microsoft accounts to be optional' has been set to 'Enabled'." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.5.2

# Define the registry path for System policies
$systemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $systemPolicyPath)) {
    Write-Host "Registry path $systemPolicyPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "System" -Force | Out-Null
}

# Set the registry DWORD value 'BlockHostedAppAccessWinRT' to 1
New-ItemProperty -Path $systemPolicyPath -Name "BlockHostedAppAccessWinRT" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.5.2 - 'BlockHostedAppAccessWinRT' has been set to 1." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.5.2 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.7 - AutoPlay Policies
# ==============================

Write-Host "Configuring AutoPlay Policies..." -ForegroundColor Cyan

# Define required registry paths
$explorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$policyExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure registry paths exist before applying settings
$paths = @($explorerPath, $policyExplorerPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $path -Force | Out-Null
    }
}

# CIS 18.10.7.1 - Disallow Autoplay for non-volume devices (Enabled)
Set-ItemProperty -Path $explorerPath -Name "NoAutoplayfornonVolume" -Type DWord -Value 1 -Force
Write-Host "18.10.7.1 - 'Disallow Autoplay for non-volume devices' set to 'Enabled'." -ForegroundColor Cyan

# CIS 18.10.7.2 - Set the default behavior for AutoRun (Enabled: Do not execute any autorun commands)
Set-ItemProperty -Path $policyExplorerPath -Name "NoAutorun" -Type DWord -Value 1 -Force
Write-Host "18.10.7.2 - 'Set the default behavior for AutoRun' set to 'Do not execute any autorun commands'." -ForegroundColor Cyan

# CIS 18.10.7.3 - Turn off Autoplay (Enabled: All drives)
Set-ItemProperty -Path $policyExplorerPath -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 -Force
Write-Host "18.10.7.3 - 'Turn off Autoplay' set to 'Enabled: All drives'." -ForegroundColor Cyan

Write-Host "AutoPlay Policies configuration applied successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################


# ==============================
# CIS Benchmark - 18.10.8.1.1 - Configure Enhanced Anti-Spoofing
# ==============================

Write-Host "Configuring Enhanced Anti-Spoofing for Windows Hello Face Authentication..." -ForegroundColor Cyan

# Define required registry path
$biometricPath = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"

# Ensure the registry path exists before applying settings
if (-not (Test-Path $biometricPath)) {
    Write-Host "Registry path $biometricPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $biometricPath -Force | Out-Null
}

# Configure Enhanced Anti-Spoofing (Enabled)
Set-ItemProperty -Path $biometricPath -Name "EnhancedAntiSpoofing" -Type DWord -Value 1 -Force
Write-Host "Enhanced Anti-Spoofing has been successfully set to 'Enabled'." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark - 18.10.8.1.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.9.1.1 - 10

# Define the base registry path for FVE policies
$fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Ensure the base registry key exists
if (-not (Test-Path $fvePath)) {
    Write-Host "Registry path $fvePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force | Out-Null
}

# 18.10.9.1.1 - Ensure 'FDVDiscoveryVolumeType' exists but has no assigned value (blank string)

# Define the base registry path
$fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Ensure the base key exists
if (-not (Test-Path $fvePath)) {
    New-Item -Path $fvePath -Force | Out-Null
    Write-Host "Created registry path: $fvePath"
}

# Set the value to an empty string (ensures value exists, but nothing is assigned)
$currentValue = (Get-ItemProperty -Path $fvePath -Name "FDVDiscoveryVolumeType" -ErrorAction SilentlyContinue).FDVDiscoveryVolumeType

if ($null -ne $currentValue -and $currentValue -ne "") {
    Write-Host "FDVDiscoveryVolumeType is currently set to a non-empty value: '$currentValue'. Resetting to blank..." -ForegroundColor Yellow
    Set-ItemProperty -Path $fvePath -Name "FDVDiscoveryVolumeType" -Value "" -Type String -Force
    Write-Host "18.10.9.1.1 - 'FDVDiscoveryVolumeType' has been set to an empty value (compliant)." -ForegroundColor Cyan
}
elseif ($null -eq $currentValue) {
    Set-ItemProperty -Path $fvePath -Name "FDVDiscoveryVolumeType" -Value "" -Type String -Force
    Write-Host "18.10.9.1.1 - 'FDVDiscoveryVolumeType' did not exist. Created with blank value (compliant)." -ForegroundColor Cyan
}
else {
    Write-Host "18.10.9.1.1 - 'FDVDiscoveryVolumeType' already exists and is empty (compliant)." -ForegroundColor Green
}

# 18.10.9.1.2: Set FDVRecovery to 1 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVRecovery" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.2 - 'FDVRecovery' set to 1." -ForegroundColor Cyan

# 18.10.9.1.3: Set FDVManageDRA to 1 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVManageDRA" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.3 - 'FDVManageDRA' set to 1." -ForegroundColor Cyan

# 18.10.9.1.4: Set FDVRecoveryPassword to 1 (DWORD)
# Allowed values are "1" or "2"; here we set it to 1.
New-ItemProperty -Path $fvePath -Name "FDVRecoveryPassword" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.4 - 'FDVRecoveryPassword' set to 1." -ForegroundColor Cyan

# 18.10.9.1.5: Set FDVRecoveryKey to 1 (DWORD)
# Allowed values are "1" or "2"; here we set it to 1.
New-ItemProperty -Path $fvePath -Name "FDVRecoveryKey" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.5 - 'FDVRecoveryKey' set to 1." -ForegroundColor Cyan

# 18.10.9.1.6: Set FDVHideRecoveryPage to 1 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVHideRecoveryPage" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.6 - 'FDVHideRecoveryPage' set to 1." -ForegroundColor Cyan

# 18.10.9.1.7: Set FDVActiveDirectoryBackup to 1 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVActiveDirectoryBackup" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.7 - 'FDVActiveDirectoryBackup' set to 1." -ForegroundColor Cyan

# 18.10.9.1.8: Set FDVActiveDirectoryInfoToStore to 1 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVActiveDirectoryInfoToStore" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.8 - 'FDVActiveDirectoryInfoToStore' set to 1." -ForegroundColor Cyan

# 18.10.9.1.9: Set FDVRequireActiveDirectoryBackup to 0 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVRequireActiveDirectoryBackup" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.9 - 'FDVRequireActiveDirectoryBackup' set to 0." -ForegroundColor Cyan

# 18.10.9.1.10: Set FDVHardwareEncryption to 0 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVHardwareEncryption" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.10 - 'FDVHardwareEncryption' set to 0." -ForegroundColor Cyan

# 18.10.9.1.11: Set FDVPassphrase to 0 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVPassphrase" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.11 - 'FDVPassphrase' set to 0." -ForegroundColor Cyan

# 18.10.9.1.12: Set FDVAllowUserCert to 1 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVAllowUserCert" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.12 - 'FDVAllowUserCert' set to 1." -ForegroundColor Cyan

# 18.10.9.1.13: Set FDVEnforceUserCert to 1 (DWORD)
New-ItemProperty -Path $fvePath -Name "FDVEnforceUserCert" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.1.13 - 'FDVEnforceUserCert' set to 1." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark - 18.10.9.1.1 - 13 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.9.2.1 - 18

# Define the base registry path for FVE policies
$fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Ensure the base registry key exists
if (-not (Test-Path $fvePath)) {
    Write-Host "Registry path $fvePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $fvePath -Force | Out-Null
}

# Define the FVE settings as an array of hashtables
$settings = @(
    @{ Name = "UseEnhancedPin"; Value = 1; Description = "18.10.9.2.1 - UseEnhancedPin set to 1" },
    @{ Name = "OSAllowSecureBootForIntegrity"; Value = 1; Description = "18.10.9.2.2 - OSAllowSecureBootForIntegrity set to 1" },
    @{ Name = "OSRecovery"; Value = 1; Description = "18.10.9.2.3 - OSRecovery set to 1" },
    @{ Name = "OSManageDRA"; Value = 1; Description = "18.10.9.2.4 - OSManageDRA set to 1" },
    @{ Name = "OSRecoveryPassword"; Value = 1; Description = "18.10.9.2.5 - OSRecoveryPassword set to 1" },
    @{ Name = "OSRecoveryKey"; Value = 0; Description = "18.10.9.2.6 - OSRecoveryKey set to 0" },
    @{ Name = "OSHideRecoveryPage"; Value = 1; Description = "18.10.9.2.7 - OSHideRecoveryPage set to 1" },
    @{ Name = "OSActiveDirectoryBackup"; Value = 1; Description = "18.10.9.2.8 - OSActiveDirectoryBackup set to 1" },
    @{ Name = "OSActiveDirectoryInfoToStore"; Value = 1; Description = "18.10.9.2.9 - OSActiveDirectoryInfoToStore set to 1" },
    @{ Name = "OSRequireActiveDirectoryBackup"; Value = 1; Description = "18.10.9.2.10 - OSRequireActiveDirectoryBackup set to 1" },
    @{ Name = "OSHardwareEncryption"; Value = 0; Description = "18.10.9.2.11 - OSHardwareEncryption set to 0" },
    @{ Name = "OSPassphrase"; Value = 0; Description = "18.10.9.2.12 - OSPassphrase set to 0" },
    @{ Name = "UseAdvancedStartup"; Value = 1; Description = "18.10.9.2.13 - UseAdvancedStartup set to 1" },
    @{ Name = "EnableBDEWithNoTPM"; Value = 0; Description = "18.10.9.2.14 - EnableBDEWithNoTPM set to 0" },
    @{ Name = "UseTPM"; Value = 0; Description = "18.10.9.2.15 - UseTPM set to 0" },
    @{ Name = "UseTPMPIN"; Value = 1; Description = "18.10.9.2.16 - UseTPMPIN set to 1" },
    @{ Name = "UseTPMKey"; Value = 0; Description = "18.10.9.2.17 - UseTPMKey set to 0" },
    @{ Name = "UseTPMKeyPIN"; Value = 0; Description = "18.10.9.2.18 - UseTPMKeyPIN set to 0" }
)

# Apply each setting
foreach ($setting in $settings) {
    New-ItemProperty -Path $fvePath -Name $setting.Name -Value $setting.Value -PropertyType DWORD -Force | Out-Null
    Write-Host $setting.Description -ForegroundColor Cyan
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark - 18.10.9.2.1 - 18 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.9.3.1 - 15

# Define the base registry path for FVE policies
$fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Ensure the base registry key exists
if (-not (Test-Path $fvePath)) {
    Write-Host "Registry path $fvePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $fvePath -Force | Out-Null
}

# 18.10.9.3.1 - Ensure 'RDVDiscoveryVolumeType' value name exists but has no data

# Ensure base key exists
$fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if (-not (Test-Path $fvePath)) {
    New-Item -Path $fvePath -Force | Out-Null
    Write-Host "Created registry path: $fvePath"
}

# Set RDVDiscoveryVolumeType to an empty string (value exists, but has no data)
$currentValue = (Get-ItemProperty -Path $fvePath -Name "RDVDiscoveryVolumeType" -ErrorAction SilentlyContinue).RDVDiscoveryVolumeType

if ($null -ne $currentValue -and $currentValue -ne "") {
    Write-Host "RDVDiscoveryVolumeType is set to a non-empty value '$currentValue'. Resetting to empty..." -ForegroundColor Yellow
    Set-ItemProperty -Path $fvePath -Name "RDVDiscoveryVolumeType" -Value "" -Type String -Force
    Write-Host "18.10.9.3.1 - 'RDVDiscoveryVolumeType' set to empty (compliant)." -ForegroundColor Cyan
}
elseif ($null -eq $currentValue) {
    Set-ItemProperty -Path $fvePath -Name "RDVDiscoveryVolumeType" -Value "" -Type String -Force
    Write-Host "18.10.9.3.1 - 'RDVDiscoveryVolumeType' was missing. Created with empty value (compliant)." -ForegroundColor Cyan
}
else {
    Write-Host "18.10.9.3.1 - 'RDVDiscoveryVolumeType' already exists and is blank (compliant)." -ForegroundColor Green
}

# Define the RDV settings as an array of hashtables for the remaining items
$rdvSettings = @(
    @{ Name = "RDVRecovery"; Value = 1; Description = "18.10.9.3.2 - RDVRecovery set to 1" },
    @{ Name = "RDVManageDRA"; Value = 1; Description = "18.10.9.3.3 - RDVManageDRA set to 1" },
    @{ Name = "RDVRecoveryPassword"; Value = 0; Description = "18.10.9.3.4 - RDVRecoveryPassword set to 0" },
    @{ Name = "RDVRecoveryKey"; Value = 0; Description = "18.10.9.3.5 - RDVRecoveryKey set to 0" },
    @{ Name = "RDVHideRecoveryPage"; Value = 1; Description = "18.10.9.3.6 - RDVHideRecoveryPage set to 1" },
    @{ Name = "RDVActiveDirectoryBackup"; Value = 0; Description = "18.10.9.3.7 - RDVActiveDirectoryBackup set to 0" },
    @{ Name = "RDVActiveDirectoryInfoToStore"; Value = 1; Description = "18.10.9.3.8 - RDVActiveDirectoryInfoToStore set to 1" },
    @{ Name = "RDVRequireActiveDirectoryBackup"; Value = 0; Description = "18.10.9.3.9 - RDVRequireActiveDirectoryBackup set to 0" },
    @{ Name = "RDVHardwareEncryption"; Value = 0; Description = "18.10.9.3.10 - RDVHardwareEncryption set to 0" },
    @{ Name = "RDVPassphrase"; Value = 0; Description = "18.10.9.3.11 - RDVPassphrase set to 0" },
    @{ Name = "RDVAllowUserCert"; Value = 1; Description = "18.10.9.3.12 - RDVAllowUserCert set to 1" },
    @{ Name = "RDVEnforceUserCert"; Value = 1; Description = "18.10.9.3.13 - RDVEnforceUserCert set to 1" },
    @{ Name = "RDVDenyWriteAccess"; Value = 1; Description = "18.10.9.3.14 - RDVDenyWriteAccess set to 1" },
    @{ Name = "RDVDenyCrossOrg"; Value = 0; Description = "18.10.9.3.15 - RDVDenyCrossOrg set to 0" }
)

# Apply each RDV setting
foreach ($setting in $rdvSettings) {
    New-ItemProperty -Path $fvePath -Name $setting.Name -Value $setting.Value -PropertyType DWORD -Force | Out-Null
    Write-Host $setting.Description -ForegroundColor Cyan
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark - 18.10.9.3.1 - 15 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.9.4

# Define the registry path for FVE policies
$fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Ensure the base registry key exists
if (-not (Test-Path $fvePath)) {
    Write-Host "Registry path $fvePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $fvePath -Force | Out-Null
}

# Set the registry DWORD value 'DisableExternalDMAUnderLock' to 1
New-ItemProperty -Path $fvePath -Name "DisableExternalDMAUnderLock" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.9.4 - 'DisableExternalDMAUnderLock' has been set to 1." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark - 18.10.9.3.1 - 15 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.10.1

# Define the registry path for Camera policies
$cameraPath = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $cameraPath)) {
    Write-Host "Registry path $cameraPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Camera" -Force | Out-Null
}

# Set the registry DWORD value 'AllowCamera' to 0
New-ItemProperty -Path $cameraPath -Name "AllowCamera" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.10.1 - 'AllowCamera' has been set to 0." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark - 18.10.10.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.12 - Cloud Content
# ==============================

Write-Host "Configuring Cloud Content Policies..." -ForegroundColor Cyan

# Define required registry path
$cloudContentPath = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"

# Ensure the registry path exists before applying settings
if (-not (Test-Path $cloudContentPath)) {
    Write-Host "Registry path $cloudContentPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $cloudContentPath -Force | Out-Null
}

# CIS 18.10.12.1 - Turn off cloud consumer account state content (Enabled)
Set-ItemProperty -Path $cloudContentPath -Name "DisableConsumerAccountStateContent" -Type DWord -Value 1 -Force
Write-Host "18.10.12.1 - 'Turn off cloud consumer account state content' has been set to 'Enabled'." -ForegroundColor Green

# CIS 18.10.12.2 - Disable cloud optimized content (Enabled)
Set-ItemProperty -Path $cloudContentPath -Name "DisableCloudOptimizedContent" -Type DWord -Value 1 -Force
Write-Host "18.10.12.2 - 'Disable cloud optimized content' has been set to 'Enabled'." -ForegroundColor Green

# CIS 18.10.12.3 - Turn off Microsoft consumer experiences (Enabled)
Set-ItemProperty -Path $cloudContentPath -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -Force
Write-Host "18.10.12.3 - 'Turn off Microsoft consumer experiences' has been set to 'Enabled'." -ForegroundColor Green

Write-Host "Cloud Content Policies configured successfully." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark - 18.10.12.1-3 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.13 - Connect
# ==============================

Write-Host "Configuring Connect Policies..." -ForegroundColor Cyan

# Define required registry path
$connectPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"

# Ensure the registry path exists before applying settings
if (-not (Test-Path $connectPath)) {
    Write-Host "Registry path $connectPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $connectPath -Force | Out-Null
}

# CIS 18.10.13.1 - Require pin for pairing (Enabled: First Time or Always)
Set-ItemProperty -Path $connectPath -Name "RequirePinForPairing" -Type DWord -Value 1 -Force
Write-Host "18.10.13.1 - 'Require pin for pairing' has been set to 'Enabled: First Time'." -ForegroundColor Green

Write-Host "Connect Policies configured successfully." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.14 - Credential User Interface
# ==============================

Write-Host "Configuring Credential User Interface settings..." -ForegroundColor Cyan

# Define registry paths
$credUIPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
$credUIPoliciesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$systemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

# Ensure registry paths exist before applying settings
$paths = @($credUIPath, $credUIPoliciesPath, $systemPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $path -Force | Out-Null
    }
}

# 18.10.14.1 - Do not display the password reveal button (ENABLED)
Set-ItemProperty -Path $credUIPath -Name "DisablePasswordReveal" -Type DWord -Value 1 -Force
Write-Host "18.10.14.1 - 'Do not display the password reveal button' set to 'Enabled'." -ForegroundColor Cyan

# 18.10.14.2 - Enumerate administrator accounts on elevation (DISABLED)
Set-ItemProperty -Path $credUIPoliciesPath -Name "EnumerateAdministrators" -Type DWord -Value 0 -Force
Write-Host "18.10.14.2 - 'Enumerate administrator accounts on elevation' set to 'Disabled'." -ForegroundColor Cyan

# 18.10.14.3 - Prevent the use of security questions for local accounts (ENABLED)
Set-ItemProperty -Path $systemPath -Name "NoLocalPasswordResetQuestions" -Type DWord -Value 1 -Force
Write-Host "18.10.14.3 - 'Prevent the use of security questions for local accounts' set to 'Enabled'." -ForegroundColor Cyan

Write-Host "Credential User Interface settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.15 - Data Collection and Preview Builds
# ==============================

Write-Host "Configuring Data Collection and Preview Builds settings..." -ForegroundColor Cyan

# Define registry paths
$dataCollectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$previewBuildsPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"

# Ensure registry paths exist before applying settings
$paths = @($dataCollectionPath, $previewBuildsPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $path -Force | Out-Null
    }
}

# 18.10.15.1 - Allow Diagnostic Data (Choose either 0 or 1, leave one commented out)
# Set-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -Type DWord -Value 0 -Force
# Write-Host "18.10.15.1 - 'Allow Diagnostic Data' set to 'Diagnostic data off (not recommended)'." -ForegroundColor Cyan

Set-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -Type DWord -Value 1 -Force
Write-Host "18.10.15.1 - 'Allow Diagnostic Data' set to 'Send required diagnostic data'." -ForegroundColor Cyan

# 18.10.15.2 - Disable Enterprise Auth Proxy (Enabled)
Set-ItemProperty -Path $dataCollectionPath -Name "DisableEnterpriseAuthProxy" -Type DWord -Value 1 -Force
Write-Host "18.10.15.2 - 'Disable Enterprise Auth Proxy' set to 'Enabled'." -ForegroundColor Cyan

# 18.10.15.3 - Disable OneSettings Downloads (Enabled)
Set-ItemProperty -Path $dataCollectionPath -Name "DisableOneSettingsDownloads" -Type DWord -Value 1 -Force
Write-Host "18.10.15.3 - 'Disable OneSettings Downloads' set to 'Enabled'." -ForegroundColor Cyan

# 18.10.15.4 - Do not show feedback notifications (Enabled)
Set-ItemProperty -Path $dataCollectionPath -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 -Force
Write-Host "18.10.15.4 - 'Do not show feedback notifications' set to 'Enabled'." -ForegroundColor Cyan

# 18.10.15.5 - Enable OneSettings Auditing (Enabled)
Set-ItemProperty -Path $dataCollectionPath -Name "EnableOneSettingsAuditing" -Type DWord -Value 1 -Force
Write-Host "18.10.15.5 - 'Enable OneSettings Auditing' set to 'Enabled'." -ForegroundColor Cyan

# 18.10.15.6 - Limit Diagnostic Log Collection (Enabled)
Set-ItemProperty -Path $dataCollectionPath -Name "LimitDiagnosticLogCollection" -Type DWord -Value 1 -Force
Write-Host "18.10.15.6 - 'Limit Diagnostic Log Collection' set to 'Enabled'." -ForegroundColor Cyan

# 18.10.15.7 - Limit Dump Collection (Enabled)
Set-ItemProperty -Path $dataCollectionPath -Name "LimitDumpCollection" -Type DWord -Value 1 -Force
Write-Host "18.10.15.7 - 'Limit Dump Collection' set to 'Enabled'." -ForegroundColor Cyan

# 18.10.15.8 - Toggle user control over Insider builds (Disabled)
Set-ItemProperty -Path $previewBuildsPath -Name "AllowBuildPreview" -Type DWord -Value 0 -Force
Write-Host "18.10.15.8 - 'Toggle user control over Insider builds' set to 'Disabled'." -ForegroundColor Cyan

Write-Host "Data Collection and Preview Builds settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmarks 18.10.15.1-8 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.16.1 - Delivery Optimization - Download Mode
# ==============================

Write-Host "Configuring Delivery Optimization settings..." -ForegroundColor Cyan

# Define registry path
$deliveryOptimizationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"

# Ensure the registry path exists before applying settings
if (-not (Test-Path $deliveryOptimizationPath)) {
    Write-Host "Registry path $deliveryOptimizationPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $deliveryOptimizationPath -Force | Out-Null
}

# 18.10.16.1 - Ensure 'Download Mode' is NOT set to 'Internet (3)'
# Allowed values:
# 0 = HTTP only, no peering
# 1 = HTTP blended with peering behind same NAT
# 2 = HTTP blended with peering across private group
# 3 = Internet (NOT ALLOWED - DO NOT USE)
# 99 = Bypass mode

$allowedDownloadMode = 1  # Set to LAN Mode (Recommended)
Set-ItemProperty -Path $deliveryOptimizationPath -Name "DODownloadMode" -Type DWord -Value $allowedDownloadMode -Force
Write-Host "18.10.16.1 - 'Download Mode' configured to a secure setting (NOT 'Internet')." -ForegroundColor Cyan

Write-Host "Delivery Optimization settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.17 - Desktop App Installer
# ==============================

Write-Host "Configuring Desktop App Installer security settings..." -ForegroundColor Cyan

# Define registry path
$appInstallerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"

# Ensure the registry path exists before applying settings
if (-not (Test-Path $appInstallerPath)) {
    Write-Host "Registry path $appInstallerPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $appInstallerPath -Force | Out-Null
}

# CIS 18.10.17.1 - Ensure 'Enable App Installer' is set to 'Disabled'
Set-ItemProperty -Path $appInstallerPath -Name "EnableAppInstaller" -Type DWord -Value 0 -Force
Write-Host "18.10.17.1 - 'Enable App Installer' set to 'Disabled'." -ForegroundColor Cyan

# CIS 18.10.17.2 - Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'
Set-ItemProperty -Path $appInstallerPath -Name "EnableExperimentalFeatures" -Type DWord -Value 0 -Force
Write-Host "18.10.17.2 - 'Enable App Installer Experimental Features' set to 'Disabled'." -ForegroundColor Cyan

# CIS 18.10.17.3 - Ensure 'Enable App Installer Hash Override' is set to 'Disabled'
Set-ItemProperty -Path $appInstallerPath -Name "EnableHashOverride" -Type DWord -Value 0 -Force
Write-Host "18.10.17.3 - 'Enable App Installer Hash Override' set to 'Disabled'." -ForegroundColor Cyan

# CIS 18.10.17.4 - Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'
Set-ItemProperty -Path $appInstallerPath -Name "EnableMSAppInstallerProtocol" -Type DWord -Value 0 -Force
Write-Host "18.10.17.4 - 'Enable App Installer ms-appinstaller protocol' set to 'Disabled'." -ForegroundColor Cyan

Write-Host "Desktop App Installer security settings configured successfully." -ForegroundColor Green

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan


#########################################################################################################################

# ALL TESTS PASSED FROM HERE TO SECTION 19 - USER CONFIGURATION
Write-Host "Configuring Explorer and Shell Protocol security policies..." -ForegroundColor Cyan

# Define registry paths and settings common to both Windows 10 and Windows 11
$registrySettings = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer";                Key = "NoDataExecutionPrevention";          Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer";                Key = "NoHeapTerminationOnCorruption";        Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Key = "PreXPSP2ShellProtocolBehavior";        Value = 0 }
)

# If the system is Windows 11, add the additional setting
if ($isWindows11) {
    $registrySettings += @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Key = "DisableGraphRecentItems"; Value = 1 }
}

# Apply settings
foreach ($setting in $registrySettings) {
    $path = $setting.Path
    $key = $setting.Key
    $value = $setting.Value

    # Ensure registry path exists
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $path -Force | Out-Null
    }

    # Check if the key exists and has the wrong value
    $currentValue = (Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue).$key
    if ($null -ne $currentValue -and $currentValue -ne $value) {
        Write-Host "Incorrect value detected at $path\$key ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
    }

    # Set the correct value
    Set-ItemProperty -Path $path -Name $key -Type DWord -Value $value -Force
    Write-Host "Set $path\$key to '$value' (REG_DWORD)" -ForegroundColor Green
}

# Verify the changes
Write-Host "Verifying applied settings..." -ForegroundColor Cyan
foreach ($setting in $registrySettings) {
    $path = $setting.Path
    $key = $setting.Key
    $expectedValue = $setting.Value
    $actualValue = (Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue).$key

    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $path\$key is correctly set to '$expectedValue'." -ForegroundColor Green
    } else {
        Write-Host "ERROR: $path\$key is NOT set correctly (Current: $actualValue, Expected: $expectedValue)." -ForegroundColor Red
    }
}

Write-Host "Explorer and shell security policies have been successfully configured!" -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.34 - Internet Explorer (Windows 10 Only)
# ==============================

Write-Host "Checking if this is Windows 10 for Internet Explorer configuration..." -ForegroundColor Cyan

# Only apply this policy for Windows 10
if ($isWindows10) {
    Write-Host "Windows 10 detected. Applying Internet Explorer security policy..." -ForegroundColor Cyan

    # Define registry path and setting
    $iePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
    $ieSettingKey = "NotifyDisableIEOptions"
    $expectedValue = 1

    # Ensure registry path exists
    if (-not (Test-Path $iePolicyPath)) {
        Write-Host "Registry path $iePolicyPath does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $iePolicyPath -Force | Out-Null
    }

    # Check if the key exists and has the wrong value
    $currentValue = (Get-ItemProperty -Path $iePolicyPath -Name $ieSettingKey -ErrorAction SilentlyContinue).$ieSettingKey
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $ieSettingKey ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $iePolicyPath -Name $ieSettingKey -ErrorAction SilentlyContinue
    }

    # Set the correct value
    Set-ItemProperty -Path $iePolicyPath -Name $ieSettingKey -Type DWord -Value $expectedValue -Force
    Write-Host "Set $iePolicyPath\$ieSettingKey to '$expectedValue' (REG_DWORD)" -ForegroundColor Green

    # Verify the applied setting
    $actualValue = (Get-ItemProperty -Path $iePolicyPath -Name $ieSettingKey -ErrorAction SilentlyContinue).$ieSettingKey
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: Internet Explorer setting correctly applied." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Internet Explorer setting was NOT applied correctly!" -ForegroundColor Red
    }
} else {
    Write-Host "Windows 11 detected or unsupported OS. Skipping Internet Explorer setting." -ForegroundColor Yellow
}

Write-Host "Internet Explorer configuration check complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.36.1

# Define the registry path for LocationAndSensors policies
$locationSensorsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $locationSensorsPath)) {
    Write-Host "Registry path $locationSensorsPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "LocationAndSensors" -Force | Out-Null
}

# Set the registry DWORD value 'DisableLocation' to 1
New-ItemProperty -Path $locationSensorsPath -Name "DisableLocation" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.36.1 - 'DisableLocation' has been set to 1." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.36.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.40.1

# Define the registry path for Messaging policies
$messagingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $messagingPath)) {
    Write-Host "Registry path $messagingPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Messaging" -Force | Out-Null
}

# Set the registry DWORD value 'AllowMessageSync' to 0
New-ItemProperty -Path $messagingPath -Name "AllowMessageSync" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.40.1 - 'AllowMessageSync' has been set to 0." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.40.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.41 - Microsoft Account Authentication
# ==============================

Write-Host "Configuring Microsoft account authentication policy..." -ForegroundColor Cyan

# Define registry path and setting
$msAccountPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
$settingKey = "DisableUserAuth"
$expectedValue = 1

# Ensure registry path exists
if (-not (Test-Path $msAccountPolicyPath)) {
    Write-Host "Registry path $msAccountPolicyPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $msAccountPolicyPath -Force | Out-Null
}

# Check if the key exists and has the wrong value
$currentValue = (Get-ItemProperty -Path $msAccountPolicyPath -Name $settingKey -ErrorAction SilentlyContinue).$settingKey
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $settingKey ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $msAccountPolicyPath -Name $settingKey -ErrorAction SilentlyContinue
}

# Set the correct value
Set-ItemProperty -Path $msAccountPolicyPath -Name $settingKey -Type DWord -Value $expectedValue -Force
Write-Host "Set $msAccountPolicyPath\$settingKey to '$expectedValue' (REG_DWORD)" -ForegroundColor Green

# Verify the applied setting
$actualValue = (Get-ItemProperty -Path $msAccountPolicyPath -Name $settingKey -ErrorAction SilentlyContinue).$settingKey
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: Microsoft account authentication is blocked." -ForegroundColor Green
} else {
    Write-Host "ERROR: Microsoft account authentication policy was NOT applied correctly!" -ForegroundColor Red
}

Write-Host "Microsoft account configuration check complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.42.5.1 - Configure Local Setting Override for MAPS Reporting
# ==============================

Write-Host "Configuring MAPS reporting policy..." -ForegroundColor Cyan

# Define registry path and setting
$mapsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
$settingKey = "LocalSettingOverrideSpynetReporting"
$expectedValue = 0

# Ensure registry path exists
if (-not (Test-Path $mapsPolicyPath)) {
    Write-Host "Registry path $mapsPolicyPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $mapsPolicyPath -Force | Out-Null
}

# Check if the key exists and has the wrong value
$currentValue = (Get-ItemProperty -Path $mapsPolicyPath -Name $settingKey -ErrorAction SilentlyContinue).$settingKey
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $settingKey ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $mapsPolicyPath -Name $settingKey -ErrorAction SilentlyContinue
}

# Set the correct value
Set-ItemProperty -Path $mapsPolicyPath -Name $settingKey -Type DWord -Value $expectedValue -Force
Write-Host "Set $mapsPolicyPath\$settingKey to '$expectedValue' (REG_DWORD)" -ForegroundColor Green

# Verify the applied setting
$actualValue = (Get-ItemProperty -Path $mapsPolicyPath -Name $settingKey -ErrorAction SilentlyContinue).$settingKey
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: MAPS local setting override for reporting is disabled." -ForegroundColor Green
} else {
    Write-Host "ERROR: MAPS reporting override policy was NOT applied correctly!" -ForegroundColor Red
}

Write-Host "MAPS reporting configuration check complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.42.6.1 - Attack Surface Reduction (ASR) Configuration
# ==============================

Write-Host "Configuring Attack Surface Reduction (ASR) rules..." -ForegroundColor Cyan

# Define registry paths
$asrMainPath = "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
$asrRulesPath = "$asrMainPath\Rules"

# Ensure registry paths exist
foreach ($path in @($asrMainPath, $asrRulesPath)) {
    if (-not (Test-Path $path)) {
        Write-Host "Registry path $path does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $path -Force | Out-Null
    }
}

# Ensure 'ExploitGuard_ASR_Rules' is enabled
$asrMainKey = "ExploitGuard_ASR_Rules"
$expectedValue = 1
$currentValue = (Get-ItemProperty -Path $asrMainPath -Name $asrMainKey -ErrorAction SilentlyContinue).$asrMainKey

if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $asrMainKey ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $asrMainPath -Name $asrMainKey -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $asrMainPath -Name $asrMainKey -Type DWord -Value $expectedValue -Force
Write-Host "Set $asrMainPath\$asrMainKey to '$expectedValue' (REG_DWORD)" -ForegroundColor Green

# Define ASR rule settings
$asrRules = @{
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "1"  # Block Office communication app from creating child processes
    "3b576869-a4ec-4529-8536-b80a7769e899" = "1"  # Block Office applications from creating executable content
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "1"  # Block abuse of exploited vulnerable signed drivers
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "1"  # Block execution of potentially obfuscated scripts
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "1"  # Block Office apps from injecting code into other processes
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "1"  # Block Adobe Reader from creating child processes
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "1"  # Block Win32 API calls from Office macro
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "1"  # Block credential stealing from Windows LSASS
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "1"  # Block untrusted and unsigned processes from USB
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "1"  # Block executable content from email/webmail
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "1"  # Block JavaScript/VBScript from launching downloaded executables
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "1"  # Block Office applications from creating child processes
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "1"  # Block persistence through WMI event subscription
}

# Apply ASR rules
foreach ($rule in $asrRules.Keys) {
    $rulePath = "$asrRulesPath\$rule"

    # Check if rule exists with the wrong value
    $currentRuleValue = (Get-ItemProperty -Path $asrRulesPath -Name $rule -ErrorAction SilentlyContinue).$rule
    if ($null -ne $currentRuleValue -and $currentRuleValue -ne $asrRules[$rule]) {
        Write-Host "Incorrect value detected for ASR Rule $rule ($currentRuleValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $asrRulesPath -Name $rule -ErrorAction SilentlyContinue
    }

    # Apply correct rule value
    Set-ItemProperty -Path $asrRulesPath -Name $rule -Type String -Value $asrRules[$rule] -Force
    Write-Host "Set ASR rule $rule to '$($asrRules[$rule])' (REG_SZ)" -ForegroundColor Green
}

# Verify applied settings
$failedRules = @()
foreach ($rule in $asrRules.Keys) {
    $actualValue = (Get-ItemProperty -Path $asrRulesPath -Name $rule -ErrorAction SilentlyContinue).$rule
    if ($actualValue -ne $asrRules[$rule]) {
        $failedRules += $rule
    }
}

if ($failedRules.Count -eq 0) {
    Write-Host "SUCCESS: All ASR rules applied correctly!" -ForegroundColor Green
} else {
    Write-Host "ERROR: Some ASR rules failed to apply: $($failedRules -join ', ')" -ForegroundColor Red
}

Write-Host "Attack Surface Reduction (ASR) configuration complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.42.6.3.1 - Network Protection Configuration
# ==============================

Write-Host "Configuring Network Protection settings..." -ForegroundColor Cyan

# Define registry path
$networkProtectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"

# Ensure registry path exists
if (-not (Test-Path $networkProtectionPath)) {
    Write-Host "Registry path $networkProtectionPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $networkProtectionPath -Force | Out-Null
}

# Ensure 'EnableNetworkProtection' is set to 1 (Block)
$networkProtectionKey = "EnableNetworkProtection"
$expectedValue = 1
$currentValue = (Get-ItemProperty -Path $networkProtectionPath -Name $networkProtectionKey -ErrorAction SilentlyContinue).$networkProtectionKey

# Remove incorrect value if it exists
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $networkProtectionKey ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $networkProtectionPath -Name $networkProtectionKey -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $networkProtectionPath -Name $networkProtectionKey -Type DWord -Value $expectedValue -Force
Write-Host "Set $networkProtectionPath\$networkProtectionKey to '$expectedValue' (REG_DWORD)" -ForegroundColor Green

# Verify applied setting
$actualValue = (Get-ItemProperty -Path $networkProtectionPath -Name $networkProtectionKey -ErrorAction SilentlyContinue).$networkProtectionKey
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: Network Protection is correctly set to 'Block'." -ForegroundColor Green
} else {
    Write-Host "ERROR: Failed to apply Network Protection setting!" -ForegroundColor Red
}

Write-Host "Network Protection configuration complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.42.7.1 - Enable File Hash Computation Feature
# ==============================

Write-Host "Configuring MpEngine settings..." -ForegroundColor Cyan

# Define registry path
$mpEnginePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"

# Ensure registry path exists
if (-not (Test-Path $mpEnginePath)) {
    Write-Host "Registry path $mpEnginePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $mpEnginePath -Force | Out-Null
}

# Ensure 'EnableFileHashComputation' is set to 1 (Enabled)
$mpEngineKey = "EnableFileHashComputation"
$expectedValue = 1
$currentValue = (Get-ItemProperty -Path $mpEnginePath -Name $mpEngineKey -ErrorAction SilentlyContinue).$mpEngineKey

# Remove incorrect value if it exists
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $mpEngineKey ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $mpEnginePath -Name $mpEngineKey -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $mpEnginePath -Name $mpEngineKey -Type DWord -Value $expectedValue -Force
Write-Host "Set $mpEnginePath\$mpEngineKey to '$expectedValue' (REG_DWORD)" -ForegroundColor Green

# Verify applied setting
$actualValue = (Get-ItemProperty -Path $mpEnginePath -Name $mpEngineKey -ErrorAction SilentlyContinue).$mpEngineKey
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: File Hash Computation feature is correctly set to 'Enabled'." -ForegroundColor Green
} else {
    Write-Host "ERROR: Failed to apply File Hash Computation setting!" -ForegroundColor Red
}

Write-Host "MpEngine configuration complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.42.10 - Real-Time Protection Settings
# ==============================

Write-Host "Configuring Real-Time Protection settings..." -ForegroundColor Cyan

# Define registry path
$realTimeProtectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"

# Ensure registry path exists
if (-not (Test-Path $realTimeProtectionPath)) {
    Write-Host "Registry path $realTimeProtectionPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $realTimeProtectionPath -Force | Out-Null
}

# Define Real-Time Protection settings
$realTimeSettings = @(
    @{ Name = "DisableIOAVProtection"; Value = 0; Description = "Scan all downloaded files and attachments (Enabled)" }
    @{ Name = "DisableRealtimeMonitoring"; Value = 0; Description = "Turn off real-time protection (Disabled)" }
    @{ Name = "DisableBehaviorMonitoring"; Value = 0; Description = "Turn on behavior monitoring (Enabled)" }
    @{ Name = "DisableScriptScanning"; Value = 0; Description = "Turn on script scanning (Enabled)" }
)

# Apply each setting
foreach ($setting in $realTimeSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $realTimeProtectionPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $realTimeProtectionPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $realTimeProtectionPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $realTimeProtectionPath\$keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $realTimeProtectionPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

Write-Host "Real-Time Protection configuration complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.42.12.1

# Define the registry path for Windows Defender Reporting policies
$defenderReportingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $defenderReportingPath)) {
    Write-Host "Registry path $defenderReportingPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Reporting" -Force | Out-Null
}

# Set the registry DWORD value 'DisableGenericRePorts' to 1
New-ItemProperty -Path $defenderReportingPath -Name "DisableGenericRePorts" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.42.12.1 - 'DisableGenericRePorts' has been set to 1." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.42.12.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.42.13 - Windows Defender Scan Settings
# ==============================

Write-Host "Configuring Windows Defender Scan settings..." -ForegroundColor Cyan

# Define registry path
$defenderScanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"

# Ensure registry path exists
if (-not (Test-Path $defenderScanPath)) {
    Write-Host "Registry path $defenderScanPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $defenderScanPath -Force | Out-Null
}

# Define Scan settings
$scanSettings = @(
    @{ Name = "DisablePackedExeScanning"; Value = 0; Description = "Scan packed executables (Enabled)" }
    @{ Name = "DisableRemovableDriveScanning"; Value = 0; Description = "Scan removable drives (Enabled)" }
    @{ Name = "DisableEmailScanning"; Value = 0; Description = "Turn on e-mail scanning (Enabled)" }
)

# Apply each setting
foreach ($setting in $scanSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $defenderScanPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $defenderScanPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $defenderScanPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $defenderScanPath\$keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $defenderScanPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

Write-Host "Windows Defender Scan settings configuration complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.42.15 & 18.10.42.16 - Microsoft Defender Threat Settings
# ==============================

Write-Host "Configuring Microsoft Defender Threat settings..." -ForegroundColor Cyan

# Define registry path
$defenderPath = "HKLM:\Software\Policies\Microsoft\Windows Defender"

# Ensure registry path exists
if (-not (Test-Path $defenderPath)) {
    Write-Host "Registry path $defenderPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $defenderPath -Force | Out-Null
}

# Define Defender settings
$defenderSettings = @(
    @{ Name = "PUAProtection"; Value = 1; Description = "Configure detection for potentially unwanted applications (Enabled: Block)" }
    @{ Name = "DisableAntiSpyware"; Value = 0; Description = "Turn off Microsoft Defender AntiVirus (Disabled)" }
)

# Ensure subkey exists before setting values
foreach ($setting in $defenderSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description

    # Ensure the registry key is created
    if (-not (Test-Path "$defenderPath\$keyName")) {
        Write-Host "Creating missing registry key: $defenderPath\$keyName" -ForegroundColor Yellow
        New-Item -Path "$defenderPath" -Name $keyName -Force | Out-Null
    }

    # Get current value
    $currentValue = (Get-ItemProperty -Path $defenderPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect values
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $defenderPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $defenderPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Applied: $description"

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $defenderPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description! Retrying..." -ForegroundColor Red
        Remove-ItemProperty -Path $defenderPath -Name $keyName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Set-ItemProperty -Path $defenderPath -Name $keyName -Type DWord -Value $expectedValue -Force
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Microsoft Defender Threat settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# WILL TEST ON WINDOWS 11 TEST MACHINE
# ==============================
# CIS Benchmark 18.10.43 - Microsoft Defender Application Guard (Windows 11 Only)
# ==============================

if ($isWindows11) {
    Write-Host "Configuring Microsoft Defender Application Guard settings..." -ForegroundColor Cyan

    # Define registry path
    $appHVSIPath = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"

    # Ensure registry path exists
    if (-not (Test-Path $appHVSIPath)) {
        Write-Host "Registry path $appHVSIPath does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $appHVSIPath -Force | Out-Null
    }

    # Define Application Guard settings
    $appHVSISettings = @(
        @{ Name = "AuditApplicationGuard";              Value = 1; Description = "Allow auditing events in Microsoft Defender Application Guard (Enabled)" }
        @{ Name = "AllowCameraMicrophoneRedirection";     Value = 0; Description = "Allow camera and microphone access in Microsoft Defender Application Guard (Disabled)" }
        @{ Name = "AllowPersistence";                     Value = 0; Description = "Allow data persistence for Microsoft Defender Application Guard (Disabled)" }
        @{ Name = "SaveFilesToHost";                      Value = 0; Description = "Allow files to download and save to the host operating system from Microsoft Defender Application Guard (Disabled)" }
        @{ Name = "AppHVSIClipboardSettings";             Value = 1; Description = "Configure Microsoft Defender Application Guard clipboard settings (Enabled)" }
        @{ Name = "AllowAppHVSI_ProviderSet";             Value = 1; Description = "Turn on Microsoft Defender Application Guard in Managed Mode (Enabled)" }
    )

    # Apply each setting
    foreach ($setting in $appHVSISettings) {
        $keyName = $setting.Name
        $expectedValue = $setting.Value
        $description = $setting.Description
        $currentValue = (Get-ItemProperty -Path $appHVSIPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

        # Remove incorrect value if it exists
        if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
            Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
            Remove-ItemProperty -Path $appHVSIPath -Name $keyName -ErrorAction SilentlyContinue
        }

        # Apply correct setting
        Set-ItemProperty -Path $appHVSIPath -Name $keyName -Type DWord -Value $expectedValue -Force
        Write-Host "Set $appHVSIPath\$keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green

        # Verify applied setting
        $actualValue = (Get-ItemProperty -Path $appHVSIPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
        if ($actualValue -eq $expectedValue) {
            Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
        } else {
            Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
        }
    }

    Write-Host "Microsoft Defender Application Guard settings configuration complete." -ForegroundColor Cyan
} else {
    Write-Host "Skipping Microsoft Defender Application Guard settings. Not applicable to this OS version." -ForegroundColor Yellow
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.49.1

# Define the registry path for Windows Feeds policies
$feedsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $feedsPath)) {
    Write-Host "Registry path $feedsPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Windows Feeds" -Force | Out-Null
}

# Set the registry DWORD value 'EnableFeeds' to 0
New-ItemProperty -Path $feedsPath -Name "EnableFeeds" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.49.1 - 'EnableFeeds' has been set to 0." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.49.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.50 - OneDrive (Prevent Usage for File Storage)
# ==============================

Write-Host "Configuring OneDrive policy to prevent file storage..." -ForegroundColor Cyan

# Define registry path
$oneDrivePath = "HKLM:\Software\Policies\Microsoft\Windows\OneDrive"

# Ensure registry path exists
if (-not (Test-Path $oneDrivePath)) {
    Write-Host "Registry path $oneDrivePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $oneDrivePath -Force | Out-Null
}

# Define OneDrive setting
$oneDriveSetting = @{ Name = "DisableFileSyncNGSC"; Value = 1; Description = "Prevent the usage of OneDrive for file storage (Enabled)" }

$keyName = $oneDriveSetting.Name
$expectedValue = $oneDriveSetting.Value
$description = $oneDriveSetting.Description
$currentValue = (Get-ItemProperty -Path $oneDrivePath -Name $keyName -ErrorAction SilentlyContinue).$keyName

# Remove incorrect value if it exists
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $oneDrivePath -Name $keyName -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $oneDrivePath -Name $keyName -Type DWord -Value $expectedValue -Force
Write-Host "Set $oneDrivePath\$keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green

# Verify applied setting
$actualValue = (Get-ItemProperty -Path $oneDrivePath -Name $keyName -ErrorAction SilentlyContinue).$keyName
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
} else {
    Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
}

Write-Host "OneDrive policy configuration complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Update: Manage End User Experience configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.55.1

# Define the registry path for PushToInstall policies
$pushToInstallPath = "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $pushToInstallPath)) {
    Write-Host "Registry path $pushToInstallPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "PushToInstall" -Force | Out-Null
}

# Set the registry DWORD value 'DisablePushToInstall' to 1
New-ItemProperty -Path $pushToInstallPath -Name "DisablePushToInstall" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.55.1 - 'DisablePushToInstall' has been set to 1." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.55.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.56.2 & 18.10.56.3 - RemoteFX USB Device Redirection
# ==============================

Write-Host "Configuring Remote Desktop password saving policy based on OS version..." -ForegroundColor Cyan

# Define registry path for Terminal Services settings
$rdpPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure registry path exists
if (-not (Test-Path $rdpPolicyPath)) {
    Write-Host "Registry path $rdpPolicyPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $rdpPolicyPath -Force | Out-Null
}

# Windows 10: Apply CIS 18.10.56.2
if ($isWindows10) {
    $setting = @{ Name = "DisablePasswordSaving"; Value = 1; Description = "Do not allow passwords to be saved (Windows 10 - Enabled)" }

    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $rdpPolicyPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $rdpPolicyPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $rdpPolicyPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $rdpPolicyPath\$keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green
}

# Windows 11: Apply CIS 18.10.56.3
if ($isWindows11) {
    $setting = @{ Name = "DisablePasswordSaving"; Value = 1; Description = "Do not allow passwords to be saved (Windows 11 - Enabled)" }

    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $rdpPolicyPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $rdpPolicyPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $rdpPolicyPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $rdpPolicyPath\$keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green
}

# --- New Setting: 18.10.56.2.2 - Disable Cloud Clipboard Integration ---
# Define registry path for Terminal Services Client settings
$clientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"

# Ensure the Client registry path exists
if (-not (Test-Path $clientPath)) {
    Write-Host "Registry path $clientPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "Client" -Force | Out-Null
}

# Set the registry DWORD value 'DisableCloudClipboardIntegration' to 1
Set-ItemProperty -Path $clientPath -Name "DisableCloudClipboardIntegration" -Type DWord -Value 1 -Force
Write-Host "18.10.56.2.2 - 'DisableCloudClipboardIntegration' has been set to 1." -ForegroundColor Green

Write-Host "Remote Desktop password saving policy configuration complete." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.56.2-3 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.56.3.3.1-7 - Ensure 'Do not allow drive redirection' is set to 'Enabled'
# ==============================

Write-Host "Configuring CIS Benchmark 18.10.56.3.3.3 - Do not allow drive redirection..." -ForegroundColor Cyan

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure registry path exists
if (-not (Test-Path $registryPath)) {
    Write-Host "Registry path $registryPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# ---------------------------
# Primary Setting: fDisableCdm (Do not allow drive redirection)
# ---------------------------
$registryName = "fDisableCdm"
$expectedValue = 1

# Check if value exists and is incorrect, remove before resetting
$currentValue = (Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue).$registryName
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $registryName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue
}

# Apply correct setting for fDisableCdm
Set-ItemProperty -Path $registryPath -Name $registryName -Type DWord -Value $expectedValue -Force
Write-Host "Set $registryPath\$registryName to '$expectedValue' (REG_DWORD) - Do not allow drive redirection (Enabled)" -ForegroundColor Green

# ---------------------------
# Additional Settings:
# 18.10.56.3.3.1: EnableUiaRedirection -> 0
# 18.10.56.3.3.2: fDisableCcm -> 1
# 18.10.56.3.3.4: fDisableLocationRedir -> 1
# 18.10.56.3.3.5: fDisableLPT -> 1
# 18.10.56.3.3.6: fDisablePNPRedir -> 1
# 18.10.56.3.3.7: fDisableWebAuthn -> 1
# ---------------------------
$additionalSettings = @(
    @{ Name = "EnableUiaRedirection";     Value = 0; Description = "Disable UI Automation redirection" },
    @{ Name = "fDisableCcm";              Value = 1; Description = "Disable CCM" },
    @{ Name = "fDisableLocationRedir";    Value = 1; Description = "Disable Location Redirection" },
    @{ Name = "fDisableLPT";              Value = 1; Description = "Disable LPT" },
    @{ Name = "fDisablePNPRedir";         Value = 1; Description = "Disable Plug and Play Redirection" },
    @{ Name = "fDisableWebAuthn";         Value = 1; Description = "Disable Web Authentication" }
)

foreach ($setting in $additionalSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $registryPath -Name $keyName -ErrorAction SilentlyContinue
    }
    Set-ItemProperty -Path $registryPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $registryPath\$keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green
}

# Force Group Policy update to apply changes
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmarks 18.10.56.3.3.1-7 successfully applied!" -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.56.3.9 - Security Settings for Terminal Services
# ==============================

Write-Host "Configuring Terminal Services Security settings..." -ForegroundColor Cyan

# Define registry path
$tsSecurityPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure registry path exists
if (-not (Test-Path $tsSecurityPath)) {
    Write-Host "Registry path $tsSecurityPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $tsSecurityPath -Force | Out-Null
}

# Define security settings
$tsSecuritySettings = @(
    @{ Name = "fPromptForPassword"; Value = 1; Description = "Always prompt for password upon connection (Enabled)" }
    @{ Name = "fEncryptRPCTraffic"; Value = 1; Description = "Require secure RPC communication (Enabled)" }
    @{ Name = "SecurityLayer"; Value = 2; Description = "Require use of specific security layer for RDP connections (SSL)" }
    @{ Name = "UserAuthentication"; Value = 1; Description = "Require user authentication for remote connections (NLA Enabled)" }
    @{ Name = "MinEncryptionLevel"; Value = 3; Description = "Set client connection encryption level (High Level)" }
)

# Apply each setting
foreach ($setting in $tsSecuritySettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $tsSecurityPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $tsSecurityPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $tsSecurityPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Applied: $description"

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $tsSecurityPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description! Retrying..." -ForegroundColor Red
        Remove-ItemProperty -Path $tsSecurityPath -Name $keyName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Set-ItemProperty -Path $tsSecurityPath -Name $keyName -Type DWord -Value $expectedValue -Force
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Terminal Services Security settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.56.3.10.1-2

# Define the registry path for Terminal Services settings
$tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure the registry path exists
if (-not (Test-Path $tsPath)) {
    Write-Host "Registry path $tsPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $tsPath -Force | Out-Null
}

# 18.10.56.3.10.1 - Set MaxIdleTime to 900000 (must be non-zero and <= 900000)
$maxIdleTimeValue = 900000
Set-ItemProperty -Path $tsPath -Name "MaxIdleTime" -Value $maxIdleTimeValue -Type DWord -Force
Write-Host "18.10.56.3.10.1 - 'MaxIdleTime' set to $maxIdleTimeValue (ms)." -ForegroundColor Cyan

# 18.10.56.3.10.2 - Set MaxDisconnectionTime to 60000 (ms)
$maxDisconnectValue = 60000
Set-ItemProperty -Path $tsPath -Name "MaxDisconnectionTime" -Value $maxDisconnectValue -Type DWord -Force
Write-Host "18.10.56.3.10.2 - 'MaxDisconnectionTime' set to $maxDisconnectValue (ms)." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.56.3.10.1-2 settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.56.3.11 - Temporary Folders
# ==============================

Write-Host "Configuring Terminal Services Temporary Folder settings..." -ForegroundColor Cyan

# Define registry path
$tsTempPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure registry path exists
if (-not (Test-Path $tsTempPath)) {
    Write-Host "Registry path $tsTempPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $tsTempPath -Force | Out-Null
}

# Define required setting
$tempFolderSetting = @{ Name = "DeleteTempDirsOnExit"; Value = 1; Description = "Do not delete temp folders upon exit (Disabled)" }

# Apply the setting
$keyName = $tempFolderSetting.Name
$expectedValue = $tempFolderSetting.Value
$description = $tempFolderSetting.Description
$currentValue = (Get-ItemProperty -Path $tsTempPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

# Remove incorrect value if it exists
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $tsTempPath -Name $keyName -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $tsTempPath -Name $keyName -Type DWord -Value $expectedValue -Force
Write-Host "Applied: $description"

# Verify applied setting
$actualValue = (Get-ItemProperty -Path $tsTempPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
} else {
    Write-Host "ERROR: Failed to apply $description! Retrying..." -ForegroundColor Red
    Remove-ItemProperty -Path $tsTempPath -Name $keyName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Set-ItemProperty -Path $tsTempPath -Name $keyName -Type DWord -Value $expectedValue -Force
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Terminal Services Temporary Folder settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.57.1 - RSS Feeds
# ==============================

Write-Host "Configuring RSS Feed settings in Internet Explorer..." -ForegroundColor Cyan

# Define registry path
$feedsPath = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds"

# Ensure registry path exists
if (-not (Test-Path $feedsPath)) {
    Write-Host "Registry path $feedsPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $feedsPath -Force | Out-Null
}

# Define required setting
$rssSetting = @{ Name = "DisableEnclosureDownload"; Value = 1; Description = "Prevent downloading of enclosures (Enabled)" }

# Apply the setting
$keyName = $rssSetting.Name
$expectedValue = $rssSetting.Value
$description = $rssSetting.Description
$currentValue = (Get-ItemProperty -Path $feedsPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

# Remove incorrect value if it exists
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $feedsPath -Name $keyName -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $feedsPath -Name $keyName -Type DWord -Value $expectedValue -Force
Write-Host "Applied: $description"

# Verify applied setting
$actualValue = (Get-ItemProperty -Path $feedsPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
} else {
    Write-Host "ERROR: Failed to apply $description! Retrying..." -ForegroundColor Red
    Remove-ItemProperty -Path $feedsPath -Name $keyName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Set-ItemProperty -Path $feedsPath -Name $keyName -Type DWord -Value $expectedValue -Force
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "RSS Feed settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.58 - Windows Search & Cortana Policies
# ==============================

Write-Host "Configuring Windows Search and Cortana settings..." -ForegroundColor Cyan

# Define registry path
$searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"

# Ensure registry path exists
if (-not (Test-Path $searchPath)) {
    Write-Host "Registry path $searchPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $searchPath -Force | Out-Null
}

# Define Windows Search & Cortana settings
$searchSettings = @(
    @{ Name = "AllowCortana"; Value = 0; Description = "Allow Cortana (Disabled)" }
    @{ Name = "AllowCortanaAboveLock"; Value = 0; Description = "Allow Cortana Above Lock Screen (Disabled)" }
    @{ Name = "AllowIndexingEncryptedStoresOrItems"; Value = 0; Description = "Allow Indexing of Encrypted Files (Disabled)" }
    @{ Name = "AllowSearchToUseLocation"; Value = 0; Description = "Allow Search and Cortana to Use Location (Disabled)" }
    @{ Name = "AllowCloudSearch"; Value = 0; Description = "Allow Cloud Search (Disabled)" }
    @{ Name = "EnableDynamicContentInWSB"; Value = 0; Description = "Enable Dynamic Content in Windows Search Box (Disabled)" }
)

# Apply each setting
foreach ($setting in $searchSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $searchPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $searchPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $searchPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Applied: $description"

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $searchPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description! Retrying..." -ForegroundColor Red
        Remove-ItemProperty -Path $searchPath -Name $keyName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Set-ItemProperty -Path $searchPath -Name $keyName -Type DWord -Value $expectedValue -Force
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Search and Cortana settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.62.1

# Define the registry path for Software Protection Platform policies
$softwareProtectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $softwareProtectionPath)) {
    Write-Host "Registry path $softwareProtectionPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion" -Name "Software Protection Platform" -Force | Out-Null
}

# Set the registry DWORD value 'NoGenTicket' to 1
New-ItemProperty -Path $softwareProtectionPath -Name "NoGenTicket" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.62.1 - 'NoGenTicket' has been set to 0." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.62.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.65 - Microsoft Store Policies
# ==============================

Write-Host "Configuring Microsoft Store policies..." -ForegroundColor Cyan

# Define registry path
$storePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"

# Ensure registry path exists
if (-not (Test-Path $storePath)) {
    Write-Host "Registry path $storePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $storePath -Force | Out-Null
}

# Define Windows Store settings
$storeSettings = @(
    @{ Name = "RequirePrivateStoreOnly"; Value = 1; Description = "Only display the private store within the Microsoft Store (Enabled)" }
    @{ Name = "AutoDownload"; Value = 4; Description = "Turn off Automatic Download and Install of updates (Disabled)" }
    @{ Name = "DisableOSUpgrade"; Value = 1; Description = "Turn off the offer to update to the latest version of Windows (Enabled)" }
    # New Settings:
    @{ Name = "DisableStoreApps"; Value = 0; Description = "Disable Store Apps (Disabled)" }         # 18.10.65.1 (Enable with 1)
    @{ Name = "RemoveWindowsStore"; Value = 1; Description = "Remove the Windows Store (Enabled)" }   # 18.10.65.5
)

# Apply each setting
foreach ($setting in $storeSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $storePath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $storePath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $storePath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Applied: $description"

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $storePath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description! Retrying..." -ForegroundColor Red
        Remove-ItemProperty -Path $storePath -Name $keyName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Set-ItemProperty -Path $storePath -Name $keyName -Type DWord -Value $expectedValue -Force
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Microsoft Store policies configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.71 - Widgets
# ==============================

Write-Host "Configuring Widgets policy..." -ForegroundColor Cyan

# Define registry path
$widgetsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"

# Ensure registry path exists
if (-not (Test-Path $widgetsPath)) {
    Write-Host "Registry path $widgetsPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $widgetsPath -Force | Out-Null
}

# Define Widgets setting
$widgetsSetting = @{
    Name = "AllowNewsAndInterests"
    Value = 0
    Description = "Allow Widgets (Disabled)"
}

# Apply setting
$keyName = $widgetsSetting.Name
$expectedValue = $widgetsSetting.Value
$description = $widgetsSetting.Description
$currentValue = (Get-ItemProperty -Path $widgetsPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

# Remove incorrect value if it exists
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $widgetsPath -Name $keyName -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $widgetsPath -Name $keyName -Type DWord -Value $expectedValue -Force
Write-Host "Applied: $description"

# Verify applied setting
$actualValue = (Get-ItemProperty -Path $widgetsPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
} else {
    Write-Host "ERROR: Failed to apply $description! Retrying..." -ForegroundColor Red
    Remove-ItemProperty -Path $widgetsPath -Name $keyName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Set-ItemProperty -Path $widgetsPath -Name $keyName -Type DWord -Value $expectedValue -Force
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Widgets policy configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.75 - Windows Defender SmartScreen (Windows 11 Only)
# ==============================

Write-Host "Configuring Windows Defender SmartScreen Enhanced Phishing Protection..." -ForegroundColor Cyan

# Ensure these settings are only applied on Windows 11
if (-not $isWindows11) {
    Write-Host "Skipping Windows Defender SmartScreen configuration: This setting is only for Windows 11." -ForegroundColor Yellow
}

# Define registry path
$smartScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"

# Ensure registry path exists
if (-not (Test-Path $smartScreenPath)) {
    Write-Host "Registry path $smartScreenPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $smartScreenPath -Force | Out-Null
}

# Define SmartScreen settings
$smartScreenSettings = @(
    @{ Name = "CaptureThreatWindow"; Value = 1; Description = "Automatic Data Collection (Enabled)" }
    @{ Name = "NotifyMalicious"; Value = 1; Description = "Notify Malicious (Enabled)" }
    @{ Name = "NotifyPasswordReuse"; Value = 1; Description = "Notify Password Reuse (Enabled)" }
    @{ Name = "NotifyUnsafeApp"; Value = 1; Description = "Notify Unsafe App (Enabled)" }
    @{ Name = "ServiceEnabled"; Value = 1; Description = "Service Enabled (Enabled)" }
)

# Apply each setting
foreach ($setting in $smartScreenSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $smartScreenPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $smartScreenPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $smartScreenPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Applied: $description"

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $smartScreenPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Defender SmartScreen configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.75.2.1 - Configure Windows Defender SmartScreen (Explorer)
# ==============================

Write-Host "Configuring Windows Defender SmartScreen in Explorer..." -ForegroundColor Cyan

# Define registry path
$smartscreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

# Ensure registry path exists
if (-not (Test-Path $smartscreenPath)) {
    Write-Host "Registry path $smartscreenPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $smartscreenPath -Force | Out-Null
}

# Define SmartScreen settings
$settings = @(
    @{ Name = "EnableSmartScreen"; Value = 1; Type = "DWord"; Description = "Enable Windows Defender SmartScreen (Warn and prevent bypass)" },
    @{ Name = "ShellSmartScreenLevel"; Value = "Warn"; Type = "String"; Description = "Set ShellSmartScreenLevel to Warn" }
)

foreach ($setting in $settings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $type = $setting.Type
    $description = $setting.Description

    # Check existing value
    $currentValue = (Get-ItemProperty -Path $smartscreenPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $smartscreenPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting based on type
    if ($type -eq "DWord") {
        Set-ItemProperty -Path $smartscreenPath -Name $keyName -Type DWord -Value $expectedValue -Force
        Write-Host "Set $keyName to $expectedValue (REG_DWORD) - $description"
    } elseif ($type -eq "String") {
        Set-ItemProperty -Path $smartscreenPath -Name $keyName -Type String -Value $expectedValue -Force
        Write-Host "Set $keyName to '$expectedValue' (REG_SZ) - $description"
    }

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $smartscreenPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Defender SmartScreen configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.77.1 - Disable Windows Game Recording and Broadcasting
# ==============================

Write-Host "Configuring Windows Game Recording and Broadcasting settings..." -ForegroundColor Cyan

# Define registry path
$gameDVRPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"

# Ensure registry path exists
if (-not (Test-Path $gameDVRPath)) {
    Write-Host "Registry path $gameDVRPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $gameDVRPath -Force | Out-Null
}

# Define Game DVR setting
$setting = @{ Name = "AllowGameDVR"; Value = 0; Description = "Enables or disables Windows Game Recording and Broadcasting (Disabled)" }

$keyName = $setting.Name
$expectedValue = $setting.Value
$description = $setting.Description
$currentValue = (Get-ItemProperty -Path $gameDVRPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

# Remove incorrect value if it exists
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $gameDVRPath -Name $keyName -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $gameDVRPath -Name $keyName -Type DWord -Value $expectedValue -Force
Write-Host "Applied: $description"

# Verify applied setting
$actualValue = (Get-ItemProperty -Path $gameDVRPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
} else {
    Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Game Recording and Broadcasting configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.78.1 - Windows Hello for Business (Windows 11 Only)
# ==============================

if ($isWindows11) {
    Write-Host "Configuring Windows Hello for Business settings (Windows 11)..." -ForegroundColor Cyan

    # Define registry path
    $whfbPath = "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics"

    # Ensure registry path exists
    if (-not (Test-Path $whfbPath)) {
        Write-Host "Registry path $whfbPath does not exist. Creating it..." -ForegroundColor Yellow
        New-Item -Path $whfbPath -Force | Out-Null
    }

    # Define setting
    $setting = @{
        Name        = "EnableESSwithSupportedPeripherals"
        Value       = 1
        Type        = "DWord"
        Description = "Enable ESS with Supported Peripherals"
    }

    # Check existing value
    $currentValue = (Get-ItemProperty -Path $whfbPath -Name $setting.Name -ErrorAction SilentlyContinue).$($setting.Name)

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $setting.Value) {
        Write-Host "Incorrect value detected for $($setting.Name) ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $whfbPath -Name $setting.Name -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $whfbPath -Name $setting.Name -Value $setting.Value -Force
    Write-Host "Set $($setting.Name) to $($setting.Value) (REG_DWORD) - $($setting.Description)"

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $whfbPath -Name $setting.Name -ErrorAction SilentlyContinue).$($setting.Name)
    if ($actualValue -eq $setting.Value) {
        Write-Host "SUCCESS: $($setting.Description) is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $($setting.Description)!" -ForegroundColor Red
    }

    # Force Group Policy update
    Write-Host "Applying Group Policy update..."
    Start-Process -FilePath gpupdate -ArgumentList '/force' -Wait
    Write-Host "Windows Hello for Business configuration complete." -ForegroundColor Cyan
}
else {
    Write-Host "Skipping Windows Hello for Business configuration: Only applicable to Windows 11." -ForegroundColor Yellow
}

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.79.1-2 - Windows Ink Workspace Configuration
# ==============================

Write-Host "Configuring Windows Ink Workspace settings..." -ForegroundColor Cyan

# Define registry path
$inkWorkspacePath = "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace"

# Ensure registry path exists
if (-not (Test-Path $inkWorkspacePath)) {
    Write-Host "Registry path $inkWorkspacePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $inkWorkspacePath -Force | Out-Null
}

# --- Setting 1: AllowWindowsInkWorkspace ---
# Choose the appropriate value:
# 0 = Disabled (Recommended)
# 1 = On, but disallow access above lock
$settingName1 = "AllowWindowsInkWorkspace"
$settingValue1 = 0

# Apply setting 1
$currentValue1 = (Get-ItemProperty -Path $inkWorkspacePath -Name $settingName1 -ErrorAction SilentlyContinue).$settingName1

if ($null -ne $currentValue1 -and $currentValue1 -ne $settingValue1) {
    Write-Host "Incorrect value detected for $settingName1 ($currentValue1). Resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $inkWorkspacePath -Name $settingName1 -ErrorAction SilentlyContinue
}

Set-ItemProperty -Path $inkWorkspacePath -Name $settingName1 -Value $settingValue1 -Force
Write-Host "Set $settingName1 to $settingValue1 (REG_DWORD)" -ForegroundColor Cyan

# Validate setting 1
$actualValue1 = (Get-ItemProperty -Path $inkWorkspacePath -Name $settingName1 -ErrorAction SilentlyContinue).$settingName1
if ($actualValue1 -eq $settingValue1) {
    Write-Host "SUCCESS: $settingName1 is correctly configured." -ForegroundColor Green
} else {
    Write-Host "ERROR: $settingName1 setting failed!" -ForegroundColor Red
}

# --- Setting 2: AllowSuggestedAppsInWindowsInkWorkspace (18.10.79.1) ---
$settingName2 = "AllowSuggestedAppsInWindowsInkWorkspace"
$settingValue2 = 0

# Apply setting 2
$currentValue2 = (Get-ItemProperty -Path $inkWorkspacePath -Name $settingName2 -ErrorAction SilentlyContinue).$settingName2

if ($null -ne $currentValue2 -and $currentValue2 -ne $settingValue2) {
    Write-Host "Incorrect value detected for $settingName2 ($currentValue2). Resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $inkWorkspacePath -Name $settingName2 -ErrorAction SilentlyContinue
}

Set-ItemProperty -Path $inkWorkspacePath -Name $settingName2 -Value $settingValue2 -Force
Write-Host "Set $settingName2 to $settingValue2 (REG_DWORD)" -ForegroundColor Cyan

# Validate setting 2
$actualValue2 = (Get-ItemProperty -Path $inkWorkspacePath -Name $settingName2 -ErrorAction SilentlyContinue).$settingName2
if ($actualValue2 -eq $settingValue2) {
    Write-Host "SUCCESS: $settingName2 is correctly configured." -ForegroundColor Green
} else {
    Write-Host "ERROR: $settingName2 setting failed!" -ForegroundColor Red
}

# Optional: Force Group Policy update
gpupdate /force

Write-Host "Windows Ink Workspace configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.80 - Windows Installer Configuration
# ==============================

Write-Host "Configuring Windows Installer settings..." -ForegroundColor Cyan

# Define registry path
$installerPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer"

# Ensure registry path exists
if (-not (Test-Path $installerPath)) {
    Write-Host "Registry path $installerPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $installerPath -Force | Out-Null
}

# Define Windows Installer settings
$installerSettings = @(
    @{ Name = "EnableUserControl"; Value = 0; Description = "Allow user control over installs (Disabled)" }
    @{ Name = "AlwaysInstallElevated"; Value = 0; Description = "Always install with elevated privileges (Disabled)" }
)

# Apply each setting
foreach ($setting in $installerSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $installerPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $installerPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $installerPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $installerPath\$keyName to '$expectedValue' (REG_DWORD) - $description"

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $installerPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Installer configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.81 - Windows Logon Options
# ==============================

Write-Host "Configuring Windows Logon Options..." -ForegroundColor Cyan

# Define registry path
$logonPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

# Ensure registry path exists
if (-not (Test-Path $logonPath)) {
    Write-Host "Registry path $logonPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $logonPath -Force | Out-Null
}

# Define Windows Logon settings
$logonSettings = @(
    @{ Name = "EnableMPR"; Value = 0; Description = "Enable MPR notifications for the system (Disabled)" }
    @{ Name = "DisableAutomaticRestartSignOn"; Value = 1; Description = "Sign-in and lock last interactive user automatically after a restart (Disabled)" }
)

# Apply each setting
foreach ($setting in $logonSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $logonPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $logonPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $logonPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $logonPath\$keyName to '$expectedValue' (REG_DWORD) - $description"

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $logonPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Logon Options configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.86.2

# Define the registry path for PowerShell Transcription settings
$transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $transcriptionPath)) {
    Write-Host "Registry path $transcriptionPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "Transcription" -Force | Out-Null
}

# Set the registry DWORD value 'EnableTranscripting' to 1
New-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.86.2 - 'EnableTranscripting' has been set to 1." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.86.2 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ALL TESTS PASSED
# ==============================
# CIS Benchmark 18.10.88.1 - WinRM Client Settings
# ==============================

Write-Host "Configuring WinRM Client settings..." -ForegroundColor Cyan

# Define registry path
$winRMClientPath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"

# Ensure registry path exists
if (-not (Test-Path $winRMClientPath)) {
    Write-Host "Registry path $winRMClientPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $winRMClientPath -Force | Out-Null
}

# Define WinRM Client settings
$winRMClientSettings = @(
    @{ Name = "AllowBasic"; Value = 0; Description = "Allow Basic authentication (Disabled)" }
    @{ Name = "AllowUnencryptedTraffic"; Value = 0; Description = "Allow unencrypted traffic (Disabled)" }
    @{ Name = "AllowDigest"; Value = 0; Description = "Disallow Digest authentication (Enabled)" }
)

# Apply each setting
foreach ($setting in $winRMClientSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $winRMClientPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $winRMClientPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $winRMClientPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $winRMClientPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "WinRM Client settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.88.2 - WinRM Service Settings
# ==============================

Write-Host "Configuring WinRM Service settings..." -ForegroundColor Cyan

# Define registry path
$winRMServicePath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"

# Ensure registry path exists
if (-not (Test-Path $winRMServicePath)) {
    Write-Host "Registry path $winRMServicePath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $winRMServicePath -Force | Out-Null
}

# Define WinRM Service settings
$winRMServiceSettings = @(
    @{ Name = "AllowBasic"; Value = 0; Description = "Allow Basic authentication (Disabled)" }
    @{ Name = "AllowAutoConfig"; Value = 0; Description = "Allow AutoConfig (Disabled)" }
    @{ Name = "AllowUnencryptedTraffic"; Value = 0; Description = "Allow Unencrypted Traffic (Disabled)" }
    @{ Name = "DisableRunAs"; Value = 1; Description = "Disable RunAs for WinRM (Enabled)" } # ✅ Added this setting
)

# Apply each setting
foreach ($setting in $winRMServiceSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $winRMServicePath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $winRMServicePath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $winRMServicePath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $winRMServicePath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "WinRM Service settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# CIS Benchmark 18.10.89.1

# Define the registry path for WinRS settings under WinRM Service
$winRSPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"

# Check if the registry key exists; if not, create it
if (-not (Test-Path $winRSPath)) {
    Write-Host "Registry path $winRSPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "WinRS" -Force | Out-Null
}

# Set the registry DWORD value 'AllowRemoteShellAccess' to 0
New-ItemProperty -Path $winRSPath -Name "AllowRemoteShellAccess" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "18.10.89.1 - 'AllowRemoteShellAccess' has been set to 0." -ForegroundColor Cyan

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "CIS Benchmark 18.10.89.1 configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.90 - Windows Sandbox Settings
# ==============================

Write-Host "Configuring Windows Sandbox settings..." -ForegroundColor Cyan

# Define registry path
$sandboxPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"

# Ensure registry path exists
if (-not (Test-Path $sandboxPath)) {
    Write-Host "Registry path $sandboxPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $sandboxPath -Force | Out-Null
}

# Define Windows Sandbox settings
$sandboxSettings = @(
    @{ Name = "AllowClipboardRedirection"; Value = 0; Description = "Allow clipboard sharing with Windows Sandbox (Disabled)" }
    @{ Name = "AllowNetworking"; Value = 0; Description = "Allow networking in Windows Sandbox (Disabled)" }
)

# Apply each setting
foreach ($setting in $sandboxSettings) {
    $keyName = $setting.Name
    $expectedValue = $setting.Value
    $description = $setting.Description
    $currentValue = (Get-ItemProperty -Path $sandboxPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

    # Remove incorrect value if it exists
    if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
        Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
        Remove-ItemProperty -Path $sandboxPath -Name $keyName -ErrorAction SilentlyContinue
    }

    # Apply correct setting
    Set-ItemProperty -Path $sandboxPath -Name $keyName -Type DWord -Value $expectedValue -Force
    Write-Host "Set $keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green

    # Verify applied setting
    $actualValue = (Get-ItemProperty -Path $sandboxPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if ($actualValue -eq $expectedValue) {
        Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
    }
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Sandbox settings configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.91.2.1 - Prevent Users from Modifying Settings in Windows Security
# ==============================

Write-Host "Configuring Windows Security: Prevent users from modifying settings..." -ForegroundColor Cyan

# Define registry path
$securityPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"

# Ensure registry path exists
if (-not (Test-Path $securityPath)) {
    Write-Host "Registry path $securityPath does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -Path $securityPath -Force | Out-Null
}

# Define the setting
$setting = @{ 
    Name = "DisallowExploitProtectionOverride"
    Value = 1
    Type = "DWord"
    Description = "Prevent users from modifying settings in Windows Security"
}

$keyName = $setting.Name
$expectedValue = $setting.Value
$description = $setting.Description
$currentValue = (Get-ItemProperty -Path $securityPath -Name $keyName -ErrorAction SilentlyContinue).$keyName

# Remove incorrect value if it exists
if ($null -ne $currentValue -and $currentValue -ne $expectedValue) {
    Write-Host "Incorrect value detected for $keyName ($currentValue). Removing and resetting..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $securityPath -Name $keyName -ErrorAction SilentlyContinue
}

# Apply correct setting
Set-ItemProperty -Path $securityPath -Name $keyName -Type DWord -Value $expectedValue -Force
Write-Host "Set $keyName to '$expectedValue' (REG_DWORD) - $description" -ForegroundColor Green

# Verify applied setting
$actualValue = (Get-ItemProperty -Path $securityPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
if ($actualValue -eq $expectedValue) {
    Write-Host "SUCCESS: $description is correctly configured." -ForegroundColor Green
} else {
    Write-Host "ERROR: Failed to apply $description!" -ForegroundColor Red
}

# Force Group Policy update
Write-Host "Applying Group Policy update..."
gpupdate /force
Write-Host "Windows Security configuration complete." -ForegroundColor Cyan

#########################################################################################################################

# Ensure 18.10.92.2.1 (Configure Automatic Updates) is set to '0 - Every day'
# ------------------------------
# Step 8: Explicitly Enforce 'NoAutoUpdate' for Configure Automatic Updates
# (CIS 18.10.92.2.1 requires that NoAutoUpdate is set to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\Au)
# ------------------------------
$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\Au"
if (-not (Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
    Write-Host "Created registry key: $keyPath" -ForegroundColor Yellow
}
New-ItemProperty -Path $keyPath -Name "NoAutoUpdate" -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "Explicitly set 'NoAutoUpdate' to 0 in the registry at $keyPath" -ForegroundColor Green

# Display warning about required restart
Write-Host "NOTE: A system restart is required for the IPv6 disablement to take full effect." -ForegroundColor Yellow

#########################################################################################################################

# ==============================
# CIS Benchmark 18.10.92.4.3 - Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
# ==============================

$wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

# Ensure the registry path exists
if (-not (Test-Path $wuPolicyPath)) {
    New-Item -Path $wuPolicyPath -Force | Out-Null
}

# Set DeferQualityUpdates = 1 and DeferQualityUpdatesPeriodInDays = 0
Set-ItemProperty -Path $wuPolicyPath -Name "DeferQualityUpdates" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $wuPolicyPath -Name "DeferQualityUpdatesPeriodInDays" -Value 0 -Type DWord -Force

Write-Host "CIS 18.10.92.4.3: 'DeferQualityUpdates=1' and 'DeferQualityUpdatesPeriodInDays=0' configured successfully." -ForegroundColor Green

Restart-Computer -Force
