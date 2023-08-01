
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
