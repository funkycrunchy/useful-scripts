Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Prompt for folder
$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$folderBrowser.Description = "Select folder containing ZIP files"
$null = $folderBrowser.ShowDialog()
$selectedPath = $folderBrowser.SelectedPath

if (-not $selectedPath) {
    Write-Host "No folder selected. Exiting script."
    exit
}

# Create or clear error log
$logFile = Join-Path $selectedPath "UnzipErrors.log"
"" | Out-File -FilePath $logFile

# Get all zip files
$zipFiles = Get-ChildItem -Path $selectedPath -Filter *.zip

foreach ($zipFile in $zipFiles) {
    $zipPath = $zipFile.FullName
    $zipName = $zipFile.BaseName
    $defaultDestination = Join-Path $selectedPath $zipName
    $extractHere = $defaultDestination

    try {
        # Open ZIP archive to inspect structure
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)

        # Get unique top-level folders
        $topLevelEntries = $zip.Entries |
            Where-Object { $_.FullName -match "^[^/\\]+[/\\]" } |
            ForEach-Object { $_.FullName.Split('/')[0] } |
            Select-Object -Unique

        # If there's only one top-level folder and it matches the ZIP name, extract directly to parent
        if ($topLevelEntries.Count -eq 1 -and $topLevelEntries[0] -eq $zipName) {
            $extractHere = $selectedPath  # Flatten destination
        } else {
            if (-not (Test-Path $extractHere)) {
                New-Item -ItemType Directory -Path $extractHere | Out-Null
            }
        }

        $zip.Dispose()

        # Extract using native Expand-Archive
        Expand-Archive -Path $zipPath -DestinationPath $extractHere -Force

        Write-Host "Extracted: $($zipFile.Name) to $extractHere"
    } catch {
        "$($zipFile.Name) - Error: $_" | Out-File -Append -FilePath $logFile
        Write-Warning "Failed to extract: $($zipFile.Name)"
    }
}

Write-Host "All zip files processed. Errors logged to: $logFile"
