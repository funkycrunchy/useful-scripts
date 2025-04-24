$folders = @{
    "Desktop"     = "$env:USERPROFILE\Desktop"
    "Personal"    = "$env:USERPROFILE\Documents"    
    "Downloads"   = "$env:USERPROFILE\Downloads"
    "My Music"    = "$env:USERPROFILE\Music"
    "My Pictures" = "$env:USERPROFILE\Pictures"
    "My Video"    = "$env:USERPROFILE\Videos"
}

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

foreach ($name in $folders.Keys) {
    $path = $folders[$name]

    
    if (-not (Test-Path $path)) {
        Write-Host "Creating missing folder: $path"
        New-Item -ItemType Directory -Path $path | Out-Null
    }

    
    Set-ItemProperty -Path $regPath -Name $name -Value $path
    Write-Host "Set '$name' path to: $path"
}

Stop-Process -Name explorer -Force
Start-Process explorer

Write-Host "`n✅ All folder paths reset and folders verified."
