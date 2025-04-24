Add-Type -AssemblyName PresentationFramework

[xml]$xaml = Get-Content ".\GUI.xaml"
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$SourcePath = $window.FindName("SourcePath")
$DestinationPath = $window.FindName("DestinationPath")
$BrowseSource = $window.FindName("BrowseSource")
$BrowseDestination = $window.FindName("BrowseDestination")
$ChkRestartable = $window.FindName("ChkRestartable")
$ChkVerify = $window.FindName("ChkVerify")
$ChkMultithreaded = $window.FindName("ChkMultithreaded")
$ProgressBar = $window.FindName("ProgressBar")
$StatusText = $window.FindName("StatusText")
$BtnStartCopy = $window.FindName("BtnStartCopy")
$BtnCancelCopy = $window.FindName("BtnCancelCopy")

$cancelCopy = $false

function Select-Folder {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($dialog.ShowDialog() -eq "OK") {
        return $dialog.SelectedPath
    }
    return ""
}

$BrowseSource.Add_Click({
    $path = Select-Folder
    if ($path) { $SourcePath.Text = $path }
})

$BrowseDestination.Add_Click({
    $path = Select-Folder
    if ($path) { $DestinationPath.Text = $path }
})

$BtnCancelCopy.Add_Click({
    $cancelCopy = $true
    $window.Dispatcher.Invoke([action]{
        $StatusText.Text = "Cancelling..."
    })
})

function Get-FileHashString {
    param($Path)
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($stream)
        $stream.Close()
        return -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
    } catch {
        return $null
    }
}

function Copy-Files {
    param($source, $destination, $verify, $multithread)

    $baseFolder = Split-Path $source -Leaf
    $files = Get-ChildItem -Path $source -Recurse -File
    $total = $files.Count
    $i = 0
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $jobs = @()

    foreach ($file in $files) {
        if ($cancelCopy) {
            $window.Dispatcher.Invoke([action]{
                $StatusText.Text = "Copy cancelled."
                $ProgressBar.Value = 0
            })
            return
        }

        $relativePath = $file.FullName.Substring($source.Length).TrimStart('\')
        $relPath = Join-Path $baseFolder $relativePath
        $destPath = Join-Path $destination $relPath
        $destDir = Split-Path $destPath

        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        $i++
        $elapsed = $stopwatch.Elapsed.TotalSeconds
        if ($elapsed -gt 0) {
            $estimatedTotal = ($elapsed / $i) * $total
            $remaining = [math]::Round($estimatedTotal - $elapsed)
            $timeLeft = [TimeSpan]::FromSeconds($remaining).ToString("hh\:mm\:ss")
        } else {
            $timeLeft = "Calculating..."
        }

        $window.Dispatcher.Invoke([action]{
            $ProgressBar.Value = [math]::Round(($i / $total) * 100)
            $StatusText.Text = "Copying $($file.Name) ($i of $total) - Time left: $timeLeft"
        })

        if ($multithread) {
            $jobs += [System.Threading.Tasks.Task]::Run({
                Copy-Item $using:file.FullName -Destination $using:destPath -Force
                if ($using:verify) {
                    $srcHash = Get-FileHashString -Path $using:file.FullName
                    $dstHash = Get-FileHashString -Path $using:destPath
                    if ($srcHash -ne $dstHash) {
                        Write-Warning "Hash mismatch: $($using:file.Name)"
                    }
                }
            })
        } else {
            Copy-Item $file.FullName -Destination $destPath -Force
            if ($verify) {
                $srcHash = Get-FileHashString -Path $file.FullName
                $dstHash = Get-FileHashString -Path $destPath
                if ($srcHash -ne $dstHash) {
                    Write-Warning "Hash mismatch: $($file.Name)"
                }
            }
        }

        Start-Sleep -Milliseconds 10
    }

    if ($multithread -and $jobs.Count -gt 0) {
        [System.Threading.Tasks.Task]::WaitAll($jobs)
    }

    $stopwatch.Stop()

    $window.Dispatcher.Invoke([action]{
        if (-not $cancelCopy) {
            $ProgressBar.Value = 100
            $StatusText.Text = "Copy complete."
        }
    })
}

$BtnStartCopy.Add_Click({
    $src = $SourcePath.Text
    $dst = $DestinationPath.Text
    $verify = $ChkVerify.IsChecked
    $multithread = $ChkMultithreaded.IsChecked
    $cancelCopy = $false

    if (-not (Test-Path $src) -or -not (Test-Path $dst)) {
        [System.Windows.MessageBox]::Show("Please select valid source and destination folders.")
        return
    }

    $ProgressBar.Value = 0
    $StatusText.Text = "Starting copy..."

    [System.Threading.Tasks.Task]::Run([Action]{
       Copy-Files -source $src -destination $dst -verify $verify -multithread $multithread
    })
})

$window.ShowDialog() | Out-Null
