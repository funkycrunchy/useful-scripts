function Remove-TeamsStartup {
    param([string]$UserHivePath
    )

    $TeamsStartupRegPath1 = "$UserHivePath\Software\Microsoft\Windows\CurrentVersion\Run"
    $TeamsStartupRegPath2 = "$UserHivePath\Software\Microsoft\Office\Teams"

    if (Test-Path "%TeamsStartupRegPath1"){
    
    Remove-ItemProperty -Path "$TeamsStartupRegPath1" -Name "com.squirrel.Teams.Teams" -ErrorAction SilentlyContinue
    Write-Host "Removed Teams Auto-Start on $TeamsStartupRegPath1"


    }




}