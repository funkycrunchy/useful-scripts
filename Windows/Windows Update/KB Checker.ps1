# Prompt the user to input the KB number
$KBNumber = Read-Host -Prompt "Please enter the KB number you would like to check (e.g., KB5041585)"

# 1. Check if the KB is listed as a Hotfix/System update (Get-HotFix)
$hotFixUpdate = Get-HotFix | Where-Object { $_.HotFixID -eq $KBNumber }

# 2. Check Windows Defender Security Intelligence Updates (if relevant)
$defenderUpdate = $null
if ($KBNumber -eq "KB2267602") {
    $defenderInfo = Get-MpComputerStatus
    $defenderVersion = $defenderInfo.AntispywareSignatureVersion
    Write-Host "Windows Defender Security Intelligence Version: $defenderVersion"
    $defenderUpdate = $defenderVersion
}

# 3. Check all installed updates using WMI (broader check)
$wmiUpdate = Get-WmiObject -Query "Select * from Win32_QuickFixEngineering" | Where-Object { $_.HotFixID -eq $KBNumber }

# 4. Check if the KB is listed in DISM output (for cumulative updates)
$dismOutput = dism /online /get-packages | Select-String -Pattern $KBNumber

# Output the result for each section
if ($hotFixUpdate) {
    Write-Host "Update $KBNumber is installed as a Hotfix/System update."
} else {
    Write-Host "Update $KBNumber is NOT installed as a Hotfix/System update."
}

if ($defenderUpdate) {
    if ($KBNumber -eq "KB2267602") {
        Write-Host "Windows Defender Security Intelligence Update (KB2267602) is installed."
    }
} else {
    Write-Host "Windows Defender Security Intelligence Update is NOT installed or not applicable."
}

if ($wmiUpdate) {
    Write-Host "Update $KBNumber is installed as a WMI update."
} else {
    Write-Host "Update $KBNumber is NOT installed as a WMI update."
}

if ($dismOutput) {
    Write-Host "Update $KBNumber is installed as a DISM cumulative update."
} else {
    Write-Host "Update $KBNumber is NOT installed as a DISM cumulative update."
}
