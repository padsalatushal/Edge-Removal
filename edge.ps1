
## targets
$remove_win32 = "Microsoft Edge", "Microsoft Edge Update", "Microsoft EdgeWebView"
$remove_appx = "MicrosoftEdge", "Win32WebViewHost"

## set useless policies
foreach ($p in 'HKLM\SOFTWARE\Policies', 'HKLM\SOFTWARE', 'HKLM\SOFTWARE\WOW6432Node') {
    $path = "$p\Microsoft\EdgeUpdate"
    Write-Host " setting useless policies"
    Write-Host $path
    Set-ItemProperty -Path $path -Name "InstallDefault" -Value 0 -Force > $null 2>&1
    Set-ItemProperty -Path $path -Name "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value 0 -Force > $null 2>&1
    Set-ItemProperty -Path $path -Name "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Value 1 -Force > $null 2>&1
    Set-ItemProperty -Path $path -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -Force > $null 2>&1
}

$edgeupdate = 'Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'

foreach ($p in 'HKLM\SOFTWARE', 'HKLM\SOFTWARE\Wow6432Node') {
  $path = "$p\$edgeupdate\Commands\on-logon-autolaunch"
  Set-ItemProperty -Path $path -Name "CommandLine" -Value 'systray.exe' -Force > $null 2>&1
  $path = "$p\$edgeupdate\Commands\on-logon-startup-boost"
  Set-ItemProperty -Path $path -Name "CommandLine" -Value 'systray.exe' -Force > $null 2>&1
  $path = "$p\$edgeupdate\Commands\on-os-upgrade"
  Set-ItemProperty -Path $path -Name "CommandLine" -Value 'systray.exe' -Force > $null 2>&1
}

## clear win32 uninstall block
foreach ($hk in 'HKCU', 'HKLM') {
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