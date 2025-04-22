
$DriveLetter = Read-Host "Enter the mapped drive letter (e.g., Z:)"

if (-not (Test-Path "$DriveLetter\")) {
    Write-Host "The drive $DriveLetter does not exist or is not accessible. Please check and try again." -ForegroundColor Red
    exit
}


$DrivePath = "$DriveLetter\"
$OutputFile = "C:\temp\FolderPermissionsReport.csv"
$Results = @()


function Get-FolderPermissions {
    param (
        [string]$FolderPath
    )
    try {
        $Acl = Get-Acl -Path $FolderPath
        foreach ($Access in $Acl.Access) {
            $Results += [PSCustomObject]@{
                FolderPath   = $FolderPath
                Identity     = $Access.IdentityReference
                Permissions  = $Access.FileSystemRights
                AccessType   = $Access.AccessControlType
                Inherited    = $Access.IsInherited
            }
        }
    } catch {
        Write-Warning "Failed to retrieve permissions for: $FolderPath - $_"
    }
}

Write-Output "Scanning folders on $DrivePath..."
$Folders = Get-ChildItem -Path $DrivePath -Directory -Recurse -ErrorAction SilentlyContinue

foreach ($Folder in $Folders) {
    Get-FolderPermissions -FolderPath $Folder.FullName
}

if ($Results.Count -gt 0) {
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Output "Permissions report saved to $OutputFile"
} else {
    Write-Output "No folders or permissions found."
}
 