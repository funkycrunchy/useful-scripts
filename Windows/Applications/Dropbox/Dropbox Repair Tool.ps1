
Write-Host "Resetting Dropbox..."
$dropboxPath = "$env:LOCALAPPDATA\Dropbox\Client\Dropbox.exe"
if (Test-Path $dropboxPath) {
    Stop-Process -Name "Dropbox" -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath $dropboxPath -ArgumentList "/reset" -Wait
    Write-Host "Dropbox has been reset."
} else {
    Write-Host "Dropbox executable not found. Skipping reset step."
}

# Clear Dropbox Cache
Write-Host "Clearing Dropbox cache..."
$cachePath = "$env:USERPROFILE\Dropbox\.dropbox.cache"
if (Test-Path $cachePath) {
    Remove-Item -Path $cachePath -Recurse -Force
    Write-Host "Dropbox cache cleared."
} else {
    Write-Host "Dropbox cache folder not found. Skipping cache clear step."
}


Write-Host "Uninstalling Dropbox..."
$dropboxUninstaller = "$env:PROGRAMFILES\Dropbox\uninstall.exe"
if (Test-Path $dropboxUninstaller) {
    Start-Process -FilePath $dropboxUninstaller -ArgumentList "/S" -Wait
    Write-Host "Dropbox uninstalled."
} else {
    Write-Host "Dropbox uninstaller not found. Skipping uninstall step."
}


Write-Host "Reinstalling Dropbox..."
$dropboxInstaller = "$env:USERPROFILE\Downloads\DropboxInstaller.exe"
Invoke-WebRequest -Uri "https://www.dropbox.com/downloading?src=index" -OutFile $dropboxInstaller
Start-Process -FilePath $dropboxInstaller -Wait
Write-Host "Dropbox reinstalled."

Write-Host "All steps completed. Restart your computer and check Dropbox functionality."
 