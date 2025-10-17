<# 
���� IPTV Դ�����Լ�⣨WinPS 5.1 ���ݰ棩
���ߣ�ChatGPT��Ϊ��һһ���ƣ�
˵������ȡ m3u/m3u8��URL �򱾵أ�����ÿ��Ƶ������ HEAD��ʧ������ Range GET(0-1023)������ CSV
#>

param(
  [string]$M3U = "https://live.kilvn.com/iptv.m3u",
  [string]$OutCsv = "iptv_report.csv",
  [int]$TimeoutSec = 7,
  [string]$UA = "TVProbe/1.0",
  [string]$Referer = ""
)

Write-Host "=== IPTV ���ټ�� (WinPS 5.1 ����) ==="
Write-Host "M3U     : $M3U"
Write-Host "Timeout : $TimeoutSec s"
Write-Host ""

# ---------- ���ߺ��� ----------

function Get-M3uText {
  param([string]$Src,[int]$TimeoutSec,[string]$UA,[string]$Referer)

  if ($Src -match '^https?://') {
    $hdr = @{}
    if ($UA) { $hdr['User-Agent'] = $UA }
    if ($Referer) { $hdr['Referer'] = $Referer }
    try {
      $resp = Invoke-WebRequest -Uri $Src -UseBasicParsing -TimeoutSec $TimeoutSec -Headers $hdr -ErrorAction Stop
      return $resp.Content
    } catch {
      Write-Warning ("��ȡ M3U ʧ��: {0}" -f $_.Exception.Message)
      return $null
    }
  } else {
    if (Test-Path -LiteralPath $Src) {
      return Get-Content -LiteralPath $Src -Encoding UTF8 -Raw
    } else {
      Write-Warning "�����ļ������ڣ�$Src"
      return $null
    }
  }
}

function Parse-M3u {
  param([string]$Text)

  $lines = $Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  if ($lines.Count -eq 0 -or ($lines[0] -notlike '#EXTM3U*')) { return @() }

  $result = New-Object System.Collections.Generic.List[object]
  $index = 0
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -like '#EXTINF*') {
      $name = ""
      if ($line -match '#EXTINF:-?\d+[^,]*,(?<nm>.*)$') {
        $name = $Matches['nm'].Trim()
      }
      # ��һ���� URL
      $url = $null
      for ($j = $i + 1; $j -lt $lines.Count; $j++) {
        if ($lines[$j].StartsWith('#')) { continue }
        $url = $lines[$j]; $i = $j; break
      }
      if ($url) {
        $index++
        if (-not $name) { $name = "CH-$index" }
        $result.Add([PSCustomObject]@{
          Index = $index
          Name  = $name
          Url   = $url
        })
      }
    }
  }
  return $result
}

function Test-Head {
  param([string]$Url,[int]$TimeoutSec,[string]$UA,[string]$Referer)
  $hdr = @{}
  if ($UA) { $hdr['User-Agent'] = $UA }
  if ($Referer) { $hdr['Referer'] = $Referer }

  try {
    $resp = Invoke-WebRequest -Method Head -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSec -Headers $hdr -ErrorAction Stop
    # ĳЩվ��᷵�� 200/204/206 ֮��
    $code = [int]$resp.StatusCode
    return @{ Ok = $true; Code = $code; Msg = "HEAD OK" }
  } catch {
    # ȡ�� Response ʱ���õ�״̬��
    $code = $null
    try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
    return @{ Ok = $false; Code = $code; Msg = $_.Exception.Message }
  }
}

function Test-RangeGet {
  param([string]$Url,[int]$TimeoutSec,[string]$UA,[string]$Referer)
  # �� HttpWebRequest �ֶ��� Range��PS 5.1 ����
  try {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method = "GET"
    $req.Timeout = $TimeoutSec * 1000
    $req.ReadWriteTimeout = $TimeoutSec * 1000
    $req.AddRange(0,1023)
    if ($UA) { $req.UserAgent = $UA }
    if ($Referer) { $req.Referer = $Referer }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = $req.GetResponse()
    $code = [int]([System.Net.HttpWebResponse]$resp).StatusCode
    $stream = $resp.GetResponseStream()
    $buf = New-Object byte[] 64
    $read = $stream.Read($buf,0,$buf.Length)
    $stream.Close(); $resp.Close()
    $sw.Stop()

    if ($read -gt 0) {
      return @{ Ok = $true; Code = $code; Ms = [int]$sw.ElapsedMilliseconds; Msg = "Range $read B" }
    } else {
      return @{ Ok = $false; Code = $code; Ms = [int]$sw.ElapsedMilliseconds; Msg = "Empty" }
    }
  } catch {
    $code = 0
    try {
      if ($_.Exception.Response -is [System.Net.HttpWebResponse]) {
        $code = [int]$_.Exception.Response.StatusCode
      }
    } catch { }
    return @{ Ok = $false; Code = $code; Ms = 0; Msg = $_.Exception.Message }
  }
}

# ---------- ������ ----------

$m3uText = Get-M3uText -Src $M3U -TimeoutSec $TimeoutSec -UA $UA -Referer $Referer
if (-not $m3uText) {
  Write-Error "�޷���ȡ M3U ���ݡ�"
  exit 1
}

$channels = Parse-M3u -Text $m3uText
if (-not $channels -or $channels.Count -eq 0) {
  Write-Warning "δ�������κ�Ƶ����"
  exit 0
}

Write-Host ("������Ƶ����{0} ��" -f $channels.Count)
"Index,Name,Url,Ok,Code,Ms,Msg" | Out-File -FilePath $OutCsv -Encoding UTF8

$idx = 0
foreach ($ch in $channels) {
  $idx++
  $t0 = Get-Date
  $h = Test-Head -Url $ch.Url -TimeoutSec $TimeoutSec -UA $UA -Referer $Referer
  $ok = $false; $code = 0; $ms = 0; $msg = ""
  if ($h.Ok) {
    $ok = $true; $code = $h.Code; $msg = $h.Msg
  } else {
    $r = Test-RangeGet -Url $ch.Url -TimeoutSec $TimeoutSec -UA $UA -Referer $Referer
    $ok = $r.Ok; $code = $r.Code; $ms = $r.Ms; $msg = $r.Msg
  }
  if ($ms -eq 0) { $ms = [int]((Get-Date) - $t0).TotalMilliseconds }

  $status = if ($ok) { "OK " } else { "NG " }
  Write-Host ("{0,-4}{1,-3}{2,-6}{3,6}ms  {4}" -f $idx,$status,$code,$ms,$ch.Name)

  # CSV ת��
  $nameCsv = '"' + ($ch.Name -replace '"','""') + '"'
  $urlCsv  = '"' + ($ch.Url  -replace '"','""') + '"'
  $msgCsv  = '"' + (($msg|Out-String).Trim() -replace '"','""') + '"'
  $line = "{0},{1},{2},{3},{4},{5},{6}" -f $idx,$nameCsv,$urlCsv,($(if($ok){1}else{0})),$code,$ms,$msgCsv
  Add-Content -Path $OutCsv -Value $line -Encoding UTF8
}

Write-Host ""
Write-Host "�����ɣ��������$OutCsv"
