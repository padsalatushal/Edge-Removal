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
