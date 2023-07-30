
## targets
$remove_win32 = "Microsoft Edge", "Microsoft Edge Update", "Microsoft EdgeWebView"
$remove_appx = "MicrosoftEdge", "Win32WebViewHost"

## set useless policies
foreach ($p in 'HKLM\SOFTWARE\Policies', 'HKLM\SOFTWARE', 'HKLM\SOFTWARE\WOW6432Node') {
    $path = "$p\Microsoft\EdgeUpdate"
    Write-Host $path
    Set-ItemProperty -Path $path -Name InstallDefault -Value 0 -Type DWord
    Set-ItemProperty -Path $path -Name Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} -Value 0 -Type DWord
    Set-ItemProperty -Path $path -Name Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} -Value 1 -Type DWord
    Set-ItemProperty -Path $path -Name DoNotUpdateToEdgeWithChromium -Value 1 -Type DWord
}


$edgeupdate = 'Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'

foreach ($p in 'HKLM\SOFTWARE', 'HKLM\SOFTWARE\Wow6432Node') {
  $path = "$p\$edgeupdate\Commands\on-logon-autolaunch"
  Set-ItemProperty -Path $path -Name CommandLine -Value 'systray.exe' -Type String
  $path = "$p\$edgeupdate\Commands\on-logon-startup-boost"
  Set-ItemProperty -Path $path -Name CommandLine -Value 'systray.exe' -Type String
  $path = "$p\$edgeupdate\Commands\on-os-upgrade"
  Set-ItemProperty -Path $path -Name CommandLine -Value 'systray.exe' -Type String
}

## clear win32 uninstall block
foreach ($hk in 'HKCU', 'HKLM') {
  foreach ($wow in '', '\Wow6432Node') {
    foreach ($i in $remove_win32) {
      $path = "$hk\SOFTWARE$wow\Microsoft\Windows\CurrentVersion\Uninstall\$i"
      Remove-ItemProperty -Path $path -Name NoRemove
      Set-ItemProperty -Path $path -Name AllowUninstall -Value 1 -Type DWord
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
# Write-Host $bho