# Script to get all mapped network drive paths
$MappedDrives = Get-WmiObject -Class Win32_NetworkConnection | Select-Object LocalName, RemoteName

if ($MappedDrives) {
    Write-Host "Mapped Network Drives:" -ForegroundColor Green
    foreach ($Drive in $MappedDrives) {
        Write-Host "Drive Letter: $($Drive.LocalName) -> Path: $($Drive.RemoteName)"
    }
} else {
    Write-Host "No mapped network drives found." -ForegroundColor Yellow
}