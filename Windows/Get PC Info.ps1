$OutputPath = "C:\Temp"
if (!(Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

$OutputFile = Join-Path -Path $OutputPath -ChildPath "userdata.txt"

Start-Transcript -Path $OutputFile -Append

function Check-WindowsVersion {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = [System.Version]$os.Version
    if ($osVersion.Major -ge 10) {
        Write-Output "Windows version is supported: $($os.Caption) ($($os.Version))"
    } else {
        Write-Output "Windows version is NOT supported: $($os.Caption) ($($os.Version))"
    }
}

function Get-UserProfiles {
    Get-CimInstance -ClassName Win32_UserProfile | Select-Object LocalPath, SID, LastUseTime | Sort-Object LastUseTime -Descending
}

function Get-DeviceSpecs {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $processor = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 Name
    $ram = [math]::Round(($computer.TotalPhysicalMemory / 1GB), 2)
    Write-Output "Device Name: $($computer.Name)"
    Write-Output "Manufacturer: $($computer.Manufacturer)"
    Write-Output "Model: $($computer.Model)"
    Write-Output "Processor: $($processor.Name)"
    Write-Output "RAM: $ram GB"
}

function Check-AzureADSettings {
    $domainJoined = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain
    if ($domainJoined -eq 'WORKGROUP') {
        Write-Output "Device is not domain-joined, suitable for Azure AD Join."
    } else {
        Write-Output "Device is domain-joined to $domainJoined. Review if hybrid join is required."
    }
    
    $aadStatus = dsregcmd /status | Select-String "AzureAdJoined" | ForEach-Object { $_ -replace '\s+', '' }
    if ($aadStatus -match "AzureAdJoined:Yes") {
        Write-Output "Device is already Azure AD joined."
    } else {
        Write-Output "Device is not Azure AD joined."
    }
}

Write-Output "Checking Windows Version..."
Check-WindowsVersion

Write-Output "`nListing User Profiles..."
Get-UserProfiles | Format-Table -AutoSize

Write-Output "`nGathering Device Specifications..."
Get-DeviceSpecs

Write-Output "`nChecking Azure AD Join Settings..."
Check-AzureADSettings

Stop-Transcript

Write-Output "Output has been saved to $OutputFile."
