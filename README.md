# Edge-Removal

## Discription
- This script remove edge completely from windows
- Requires you to Run Script file ADMINISTRATOR! (if you don't use launch command)

## Demo

## Launch Command(Powershell) :
```bash
irm padsalatushal.github.io/edge.bat | iex
```
Or
```bash
iwr -useb https://padsalatushal.github.io/edge.bat | iex
```

If you are having TLS 1.2 Issues or You cannot find or resolve host then run with the following command:

```bash
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/padsalatushal/Edge-Removal/main/Edge_Removal.bat')
```

## Resources 

https://github.com/AveYo/fox
