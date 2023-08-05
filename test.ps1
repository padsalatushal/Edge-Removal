
## targets
$remove_win32 = "Microsoft Edge", "Microsoft Edge Update", "Microsoft EdgeWebView"
$remove_appx = "MicrosoftEdge", "Win32WebViewHost"

## set useless policies
foreach ($p in 'HKLM:\SOFTWARE\Policies', 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node') {
    $path = "$p\Microsoft\EdgeUpdate"
    Write-Host " setting useless policies"
    Write-Host $path
    Set-ItemProperty -Path $path -Name "InstallDefault" -Value 0 -Force > $null 2>&1
    Set-ItemProperty -Path $path -Name "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value 0 -Force > $null 2>&1
    Set-ItemProperty -Path $path -Name "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Value 1 -Force > $null 2>&1
    Set-ItemProperty -Path $path -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -Force > $null 2>&1
}

$edgeupdate = 'Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'

foreach ($p in 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\Wow6432Node') {
  $path = "$p\$edgeupdate\Commands\on-logon-autolaunch"
  Set-ItemProperty -Path $path -Name "CommandLine" -Value 'systray.exe' -Force > $null 2>&1
  $path = "$p\$edgeupdate\Commands\on-logon-startup-boost"
  Set-ItemProperty -Path $path -Name "CommandLine" -Value 'systray.exe' -Force > $null 2>&1
  $path = "$p\$edgeupdate\Commands\on-os-upgrade"
  Set-ItemProperty -Path $path -Name "CommandLine" -Value 'systray.exe' -Force > $null 2>&1
}

## clear win32 uninstall block
foreach ($hk in 'HKCU:', 'HKLM:') {
  foreach ($wow in '', '\Wow6432Node') {
    foreach ($i in $remove_win32) {
      $path = "$hk\SOFTWARE$wow\Microsoft\Windows\CurrentVersion\Uninstall\$i"
      Remove-ItemProperty -Path $path -Name NoRemove -Force -ErrorAction SilentlyContinue
      Set-ItemProperty -Path $path -Name AllowUninstall -Value 1 -Force > $null 2>&1
    }
  }
}

## find all Edge setup.exe and gather BHO paths
$setup = ""
$bho = "$env:ProgramData\ie_to_edge_stub.exe","$env:Public\ie_to_edge_stub.exe"

"LocalApplicationData", "ProgramFilesX86", "ProgramFiles" | ForEach-Object {
    $setup += Get-ChildItem "$([Environment]::GetFolderPath($_))\Microsoft\Edge*\setup.exe" -Recurse -ErrorAction SilentlyContinue
    $bho += Get-ChildItem "$([Environment]::GetFolderPath($_))\Microsoft\Edge*\ie_to_edge_stub.exe" -Recurse -ErrorAction SilentlyContinue
}
Write-Host "Printing BHo"
Write-Host $bho

## shut edge down
$processesToKill = 'MicrosoftEdgeUpdate','chredge','msedge','edge','msedgewebview2','Widgets'

foreach ($processName in $processesToKill) {
    Get-Process -Name $processName -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process $_ -Force }
}

# Use dedicated C:\Scripts path due to Sigma rules FUD
$DIR = "$env:SystemDrive\Scripts"
$null = mkdir $DIR -ErrorAction SilentlyContinue

# Export OpenWebSearch innovative redirector
foreach ($b in $bho) {
    if (Test-Path $b) {
        try {
            Copy-Item $b "$DIR\ie_to_edge_stub.exe" -Force -ErrorAction SilentlyContinue
        } catch { }
    }
}

# Clear appx uninstall block and remove
$provisioned = Get-AppxProvisionedPackage -Online
$appxpackage = Get-AppxPackage -AllUsers
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$store_reg = $store

Write-Host "line 74"
Write-Host $store_reg
$users = 'S-1-5-18'

if (Test-Path $store) {
    $users += (Get-ChildItem $store | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName
}

foreach ($choice in $remove_appx) {
    if ('' -eq $choice.Trim()) { continue }

    foreach ($appx in $provisioned | Where-Object { $_.PackageName -like "*$choice*" }) {
        $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName
        Write-Host $PackageFamilyName
        $path = "$store_reg\Deprovisioned\$PackageFamilyName"
        cmd /c "reg add ""$store_reg\Deprovisioned\$PackageFamilyName"" /f >nul 2>nul"
        cmd /c "dism /online /remove-provisionedappxpackage /packagename:$($appx.PackageName) >nul 2>nul"
        # Set-ItemProperty -Path $path -Name CommandLine -Value 'systray.exe' -Force > $null 2>&1
        # dism /online /remove-provisionedappxpackage /packagename:$appxPackageName >$null 2>&1

        #powershell -nop -c remove-appxprovisionedpackage -packagename "'$($appx.PackageName)'" -online 2>&1 >''
    }

    foreach ($appx in $appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" }) {
        $inbox = (Get-ItemProperty "$store\InboxApplications\*$($appx.Name)*").Path.PSChildName
        $PackageFamilyName = $appx.PackageFamilyName
        $PackageFullName = $appx.PackageFullName
        Write-Host "LIne 98"
        Write-Host $PackageFullName

        foreach ($app in $inbox) {
            $registryPath = "$store_reg\Deprovisioned\$PackageFamilyName"
            Write-Host "LINE 103"
            Write-Host $registryPath
            cmd /c "reg delete ""$store_reg\InboxApplications\$app"" /f >nul 2>nul"
            # Remove-ItemProperty -Path $registryPath -Name PropertyName -Force -ErrorAction SilentlyContinue
        }

        $registryPath = "$store_reg\Deprovisioned\$PackageFamilyName"
        New-Item -Path $registryPath -Force | Out-Null
        Write-Host "LIne 110"
        Write-Host $registryPath
        cmd /c "reg add ""$store_reg\Deprovisioned\$PackageFamilyName"" /f >nul 2>nul"

        # Set-ItemProperty -Path $registryPath -Force -ErrorAction SilentlyContinue


        foreach ($sid in $users) {
            $registryPath = "$store_reg\EndOfLife\$sid\$PackageFullName"
            # New-Item -Path $registryPath -Force | Out-Null
            cmd /c "reg add ""$store_reg\EndOfLife\$sid\$PackageFullName"" /f >nul 2>nul"
            # Set-ItemProperty -Path $registryPath -Force -ErrorAction SilentlyContinue

        }
        cmd /c "dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >nul 2>nul"
        powershell -nop -c "remove-appxpackage -package '$PackageFullName' -AllUsers" 2>&1 >''
        # dism /Online /Set-NonRemovableAppPolicy /PackageFamily:$PackageFamilyName /NonRemovable:0 >$null 2>&1
        # Remove-AppxPackage -Package $PackageFullName -AllUsers | Out-Null

        foreach ($sid in $users) {
            $registryPath = "$store_reg\EndOfLife\$sid\$PackageFullName"
            cmd /c "reg delete ""$store_reg\EndOfLife\$sid\$PackageFullName"" /f >nul 2>nul"
            # Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue            
        }
    }
}

## shut edge down, again
$processesToKill = 'MicrosoftEdgeUpdate','chredge','msedge','edge','msedgewebview2','Widgets'

foreach ($processName in $processesToKill) {
    Get-Process -Name $processName -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process $_ -Force }
}

# brute-run found Edge setup.exe with uninstall args

$purge = '--uninstall --system-level --force-uninstall'
if ($also_remove_webview -eq 1){
    foreach ($s in $setup) {
        try {
            Start-Process -Wait $s -ArgumentList "--msedgewebview $purge"
        } catch {
            # Catch any errors if the process fails
        }
    }
}
foreach ($s in $setup) {
    try {
        Start-Process -Wait $s -ArgumentList "--msedge $purge"
    } catch {
        # Catch any errors if the process fails
    }
}

# prevent latest cumulative update (LCU) failing due to non-matching EndOfLife Edge entries
foreach ($i in $remove_appx) {
    Get-ChildItem "$store\EndOfLife" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_ -like "*${i}*" } | ForEach-Object {
        $registryKey = $_.Name
        if (Test-Path $registryKey) {
            Remove-Item -Path $registryKey -Force -ErrorAction SilentlyContinue
        }
    }

    Get-ChildItem "$store\Deleted\EndOfLife" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_ -like "*${i}*" } | ForEach-Object {
        $registryKey = $_.Name
        if (Test-Path $registryKey) {
            Remove-Item -Path $registryKey -Force -ErrorAction SilentlyContinue
        }
    }
}

# extra cleanup
$desktop = [Environment]::GetFolderPath('Desktop')
$appdata = [Environment]::GetFolderPath('ApplicationData')

Remove-Item -Path "$appdata\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Tombstones\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$appdata\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue


$IFEO = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$MSEP = ("$env:ProgramFiles", "$env:ProgramFiles(x86)")[[Environment]::Is64BitOperatingSystem] + '\Microsoft\Edge\Application'
$MIN = ('--headless', '--width 1 --height 1')[([Environment]::OSVersion.Version.Build) -gt 25179]
$CMD = "$env:systemroot\system32\conhost.exe $MIN"
$DIR = (Get-Location).Path
Write-Host "PRINTING dir"
Write-Host $DIR

Write-Host "printing msep"
Write-Host $MSEP

Write-Host "printing min"
Write-Host $MIN

Write-Host "printing cmd"
Write-Host $CMD
Write-Host "printing ifeo"
Write-Host $IFEO


# Set the registry keys for microsoft-edge protocol
Set-ItemProperty -Path 'REGISTRY::HKEY_CLASSES_ROOT\microsoft-edge' -Name '(Default)' -Value 'URL:microsoft-edge' -Force
Set-ItemProperty -Path 'REGISTRY::HKEY_CLASSES_ROOT\microsoft-edge' -Name 'URL Protocol' -Value '' -Force
Set-ItemProperty -Path 'REGISTRY::HKEY_CLASSES_ROOT\microsoft-edge' -Name 'NoOpenWith' -Value '' -Force
New-Item -Path 'REGISTRY::HKEY_CLASSES_ROOT\microsoft-edge\shell\open\command' -Name '(Default)' -Value "$DIR\ie_to_edge_stub.exe %1" -Force

# Set the registry keys for MSEdgeHTM protocol
New-ItemProperty -Path 'REGISTRY::HKEY_CLASSES_ROOT\MSEdgeHTM' -Name 'NoOpenWith' -Value '' -Force
New-ItemProperty -Path 'REGISTRY::HKEY_CLASSES_ROOT\MSEdgeHTM\shell\open\command' -Name '(Default)' -Value "$DIR\ie_to_edge_stub.exe %1" -Force

# Set the registry keys for ie_to_edge_stub.exe
New-ItemProperty -Path "$IFEO\ie_to_edge_stub.exe" -Name 'UseFilter' -Value 1 -Force
New-ItemProperty -Path "$IFEO\ie_to_edge_stub.exe\0" -Name 'FilterFullPath' -Value "$DIR\ie_to_edge_stub.exe" -Force
New-ItemProperty -Path "$IFEO\ie_to_edge_stub.exe\0" -Name 'Debugger' -Value "$CMD $DIR\OpenWebSearch.cmd" -Force

# Set the registry keys for msedge.exe
New-ItemProperty -Path "$IFEO\msedge.exe" -Name 'UseFilter' -Value 1 -Force
New-ItemProperty -Path "$IFEO\msedge.exe\0" -Name 'FilterFullPath' -Value "$MSEP\msedge.exe" -Force
New-ItemProperty -Path "$IFEO\msedge.exe\0" -Name 'Debugger' -Value "$CMD $DIR\OpenWebSearch.cmd" -Force
