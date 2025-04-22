# Ensure Remote Registry Service is running
function Ensure-RemoteRegistryService {
    $ServiceName = "RemoteRegistry"

    # Check the status of the Remote Registry service
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($Service -eq $null) {
        Write-Error "The Remote Registry service is not installed on this system."
        return $false
    }

    if ($Service.Status -ne "Running") {
        Write-Host "Starting the Remote Registry service..."
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue

        # Wait for the service to start
        Start-Sleep -Seconds 2
        $Service.Refresh()

        if ($Service.Status -eq "Running") {
            Write-Host "Remote Registry service started successfully."
            return $true
        } else {
            Write-Error "Failed to start the Remote Registry service."
            return $false
        }
    } else {
        Write-Host "Remote Registry service is already running."
        return $true
    }
}

# Function to remove Teams from startup for a specific user
function Remove-TeamsStartup {
    param (
        [string]$UserHivePath,
        [string]$BackupPath
    )
    
    # Define the registry paths for Teams in the user's hive
    $TeamsStartupRegPath1 = "$UserHivePath\Software\Microsoft\Windows\CurrentVersion\Run"
    $TeamsStartupRegPath2 = "$UserHivePath\Software\Microsoft\Office\Teams"

    # Backup and remove Teams from the Run registry key
    if (Test-Path "$TeamsStartupRegPath1") {
        $BackupFile1 = Join-Path $BackupPath "Run_Backup_$($UserHivePath.Split('\')[-1]).reg"
        reg export "$TeamsStartupRegPath1" $BackupFile1 /y | Out-Null
        Remove-ItemProperty -Path "$TeamsStartupRegPath1" -Name "com.squirrel.Teams.Teams" -ErrorAction SilentlyContinue
        Write-Host "Removed Teams from $TeamsStartupRegPath1 and backed up to $BackupFile1"
    }

    # Backup and disable Teams auto-start setting
    if (Test-Path "$TeamsStartupRegPath2") {
        $BackupFile2 = Join-Path $BackupPath "Teams_Backup_$($UserHivePath.Split('\')[-1]).reg"
        reg export "$TeamsStartupRegPath2" $BackupFile2 /y | Out-Null
        Set-ItemProperty -Path "$TeamsStartupRegPath2" -Name "IsLoggedOut" -Value 1 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "$TeamsStartupRegPath2" -Name "IsLoginDisabled" -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Disabled Teams auto-start in $TeamsStartupRegPath2 and backed up to $BackupFile2"
    }
}

# Set backup path
$BackupPath = "C:\Temp\RegBackup"

# Ensure backup directory exists
if (!(Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath | Out-Null
    Write-Host "Created backup directory: $BackupPath"
}

# Ensure Remote Registry service is running
if (!(Ensure-RemoteRegistryService)) {
    Write-Error "Remote Registry service could not be started. Script will terminate."
    exit
}

# Enumerate all user profiles
$UserProfiles = Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false -and $_.LocalPath -match 'C:\\Users\\' }

foreach ($UserProfile in $UserProfiles) {
    # Load the user's registry hive
    $UserHivePath = "HKU\$($UserProfile.SID)"
    
    try {
        # Open the registry hive for this user
        reg load "HKU\$($UserProfile.SID)" "$($UserProfile.LocalPath)\NTUSER.DAT" | Out-Null
        Write-Host "Loaded registry hive for user: $($UserProfile.LocalPath)"
        
        # Call the function to remove Teams from this user's startup
        Remove-TeamsStartup -UserHivePath $UserHivePath -BackupPath $BackupPath
    } catch {
        Write-Warning "Could not load registry hive for user: $($UserProfile.LocalPath)"
    } finally {
        # Unload the registry hive
        reg unload "HKU\$($UserProfile.SID)" | Out-Null
        Write-Host "Unloaded registry hive for user: $($UserProfile.LocalPath)"
    }
}

Write-Host "Microsoft Teams startup removal completed for all users. Backups saved to $BackupPath."
