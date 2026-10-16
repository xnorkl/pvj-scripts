#Requires -RunAsAdministrator

<#
.EXAMPLE
    .\Get-LolbinFinding.ps1 | Format-Table -AutoSize   # exit 2 = FAIL found
#>
[CmdletBinding()]
param()

# high-signal LOLBAS: download/decode/execute proxies and encoded PowerShell
$sus = '(?i)(certutil.*(urlcache|verifyctl|-decode|-encode)|bitsadmin.*/transfer|\bmshta\b|regsvr32.*(/i:|scrobj)|rundll32.*(javascript:|http|\\\\)|msbuild.*\.(xml|csproj|proj)|installutil.*/logfile|\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|net\.webclient|\biwr\b|invoke-webrequest|start-bitstransfer)'
$script:fail = $false
function Out-Finding($Status, $Check, $Object, $Detail) {
    if ($Status -eq 'FAIL') { $script:fail = $true }
    [pscustomobject]@{ Status = $Status; Check = $Check; Object = $Object; Detail = "$Detail" }
}

# Live command lines (FAIL: happening now)
foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
    $cl = "$($p.CommandLine)"
    if ($cl -match $sus) { Out-Finding FAIL process "PID $($p.ProcessId) $($p.Name)" $cl }
}

# certutil download cache on disk (WARN: a download happened)
$cacheRoot = "$env:windir\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache"
foreach ($f in Get-ChildItem "$cacheRoot\Content" -File -Recurse -ErrorAction SilentlyContinue) {
    Out-Finding WARN certutil-cache $f.FullName "downloaded $($f.LastWriteTime.ToString('s'))"
}

# Prefetch shows a LOLBin ran (WARN: historical)
$lolExe = 'CERTUTIL|BITSADMIN|MSHTA|REGSVR32|RUNDLL32|MSBUILD|INSTALLUTIL|CSCRIPT|WSCRIPT|CMSTP'
foreach ($pf in Get-ChildItem "$env:windir\Prefetch\*.pf" -ErrorAction SilentlyContinue) {
    if ($pf.Name -match "^($lolExe)") { Out-Finding WARN prefetch $pf.Name "ran $($pf.LastWriteTime.ToString('s'))" }
}

# PowerShell script-block log (WARN: historical, needs 4104 logging on)
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 500 -ErrorAction Stop |
        Where-Object { $_.Message -match $sus } |
        ForEach-Object { Out-Finding WARN scriptblock "4104 $($_.TimeCreated.ToString('s'))" (($_.Message -split "`n")[0]) }
} catch { }   # log empty or disabled

if ($script:fail) { exit 2 }
