param(
  [string]$Host = $env:IPTV_HOST,
  [int]$Port = [int]($env:IPTV_PORT -as [int]),
  [int]$RefreshMin = [int]($env:IPTV_REFRESH_MIN -as [int])
)

$scriptDir = Split-Path -LiteralPath $MyInvocation.MyCommand.Path -Parent
Set-Location $scriptDir

$argsList = @()
if ($Host) { $argsList += "IPTV_HOST=$Host" }
if ($Port) { $argsList += "IPTV_PORT=$Port" }
if ($RefreshMin) { $argsList += "IPTV_REFRESH_MIN=$RefreshMin" }

$envCmd = if ($argsList.Count -gt 0) { "$($argsList -join ' ') " } else { "" }

Start-Process -FilePath "powershell.exe" -WorkingDirectory $scriptDir -ArgumentList @(
  "-NoExit",
  "-Command",
  "$envCmd python server.py"
)

