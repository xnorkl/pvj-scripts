#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Read-only hunt for Windows persistence (autostart extensibility points).
.DESCRIPTION
    Checks Run/RunOnce keys (HKLM + loaded user hives), Winlogon Shell/Userinit, AppInit_DLLs,
    IFEO debuggers / SilentProcessExit, LSA packages, services (path, quoting, signature, ServiceDll),
    scheduled tasks (incl. hidden tasks with the SD removed), WMI event consumers, startup folders,
    PowerShell profiles, BITS notify commands, netsh helpers and per-user COM hijacks.
      FAIL  command looks malicious (encoded PS, LOLBin download, user-writable path, ...) or a
            mechanism that is never legit on a game box (IFEO debugger, WMI command consumer, ...)
      WARN  third-party / unusual entry: review
    Emits: Status, Check, Object, Detail.
    Exit code: 0 clean, 1 error, 2 at least one FAIL (Ansible: failed_when: rc == 1).
.EXAMPLE
    .\Get-AutostartFinding.ps1 | Format-Table -AutoSize -Wrap
.EXAMPLE
    .\Get-AutostartFinding.ps1 | Where-Object Status -eq FAIL
#>
[CmdletBinding()]
param()

$sus = '(?i)(\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|\biex\b|invoke-expression|downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|bitsadmin|certutil.*(urlcache|decode)|mshta|regsvr32.*(/i:|scrobj)|rundll32.*(javascript|http|\\\\)|-w(indowstyle)?\s+h|\\appdata\\|\\temp\\|\\users\\public\\|\\perflogs\\|\\\\\d+\.\d+\.\d+\.\d+\\|https?://|\bnc(at)?(\.exe)?\s.*-e\b)'
$script:fail = $false
function Out-Finding($Status, $Check, $Object, $Detail) {
    if ($Status -eq 'FAIL') { $script:fail = $true }
    [pscustomobject]@{ Status = $Status; Check = $Check; Object = $Object; Detail = "$Detail" }
}
# Suspicious command -> FAIL, otherwise emit $Else (if given)
function Test-Entry($Check, $Object, $Command, $Else) {
    if ("$Command" -match $sus) { Out-Finding FAIL $Check $Object $Command }
    elseif ($Else) { Out-Finding $Else $Check $Object $Command }
}
function Get-RegValue($Key, $Name) { (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction SilentlyContinue).$Name }

$win = $env:windir
# ponytail: only hives of logged-on users are loaded; load NTUSER.DAT files if offline users matter
$userSids = Get-ChildItem Registry::HKEY_USERS | Where-Object PSChildName -match '^S-1-5-21-[\d-]+$' | ForEach-Object PSChildName
$hives = @('Registry::HKEY_LOCAL_MACHINE') + ($userSids | ForEach-Object { "Registry::HKEY_USERS\$_" })

# --- Run keys ---
$runKeys = 'Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run', 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
foreach ($h in $hives) {
    foreach ($rk in $runKeys) {
        $k = Get-Item -LiteralPath "$h\$rk" -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) { Test-Entry run "$($k.Name)\$n" $k.GetValue($n) WARN }
    }
    # Per-user Winlogon Shell override is never legit
    $s = Get-RegValue "$h\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" Shell
    if ($h -ne $hives[0] -and $s) { Out-Finding FAIL winlogon "$h\...\Winlogon\Shell" $s }
}

# --- Winlogon / AppInit / IFEO / LSA ---
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$v = Get-RegValue $wl Shell;    if ($v -notmatch '^explorer\.exe,?$') { Out-Finding FAIL winlogon "$wl\Shell" $v }
$v = Get-RegValue $wl Userinit; if ($v -notmatch '^[a-z]:\\windows\\system32\\userinit\.exe,?$') { Out-Finding FAIL winlogon "$wl\Userinit" $v }
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
    $v = Get-RegValue $k AppInit_DLLs; if ($v) { Out-Finding FAIL appinit "$k\AppInit_DLLs" $v }
}
foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue) {
    $v = Get-RegValue $k.PSPath Debugger; if ($v) { Out-Finding FAIL ifeo "$($k.Name)\Debugger" $v }
}
foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue) {
    $v = Get-RegValue $k.PSPath MonitorProcess; if ($v) { Out-Finding FAIL ifeo "$($k.Name)\MonitorProcess" $v }
}
$knownLsa = 'msv1_0', 'scecli', 'rassfm', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', '""', ''
foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig') {
    foreach ($n in 'Authentication Packages', 'Notification Packages', 'Security Packages') {
        foreach ($p in @(Get-RegValue $k $n)) { if ($p -notin $knownLsa) { Out-Finding FAIL lsa "$k\$n" $p } }
    }
}

# --- Services ---
foreach ($s in Get-CimInstance Win32_Service) {
    $path = "$($s.PathName)"
    if ($path -match $sus) { Out-Finding FAIL service $s.Name $path; continue }
    if ($path -notmatch '^"?([^"]+?\.(exe|sys|com))') { continue }
    $exe = [Environment]::ExpandEnvironmentVariables($Matches[1])
    if ($path -notmatch '^"' -and $exe -match ' ') { Out-Finding WARN service $s.Name "unquoted path with spaces: $path" }
    if ($exe -notlike "$win\*" -and (Test-Path -LiteralPath $exe)) {
        $sig = Get-AuthenticodeSignature -LiteralPath $exe
        if ($sig.Status -ne 'Valid') { Out-Finding WARN service $s.Name "$($sig.Status) signature: $path" }
    }
    $dll = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" ServiceDll
    if ($dll -and $dll -notlike "$win\system32\*") { Out-Finding FAIL service-dll $s.Name $dll }
}

# --- Scheduled tasks ---
foreach ($t in Get-ScheduledTask) {
    foreach ($a in $t.Actions) {
        $cmd = if ($a.Execute) { "$($a.Execute) $($a.Arguments)" } else { "COM handler $($a.ClassId)" }
        $else = if ($t.TaskPath -notlike '\Microsoft\*') { 'WARN' }
        Test-Entry task "$($t.TaskPath)$($t.TaskName)" $cmd $else
    }
}
# Tasks with the SD value deleted are invisible to schtasks/Get-ScheduledTask (Tarrask)
foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' -Recurse -ErrorAction SilentlyContinue) {
    $names = $k.GetValueNames()
    if ($names -contains 'Id' -and $names -notcontains 'SD') { Out-Finding FAIL task-hidden $k.Name 'security descriptor removed' }
}

# --- WMI event consumers that run code ---
foreach ($c in Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue) {
    switch ($c.CimClass.CimClassName) {
        'CommandLineEventConsumer'  { Out-Finding FAIL wmi $c.Name "$($c.ExecutablePath) $($c.CommandLineTemplate)" }
        'ActiveScriptEventConsumer' { Out-Finding FAIL wmi $c.Name "$($c.ScriptFileName) $($c.ScriptText)" }
    }
}

# --- Startup folders and PowerShell profiles ---
$profiles = Get-CimInstance Win32_UserProfile -Filter 'Special=False' | ForEach-Object LocalPath
$startup = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") +
    ($profiles | ForEach-Object { "$_\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
$shell = New-Object -ComObject WScript.Shell
foreach ($f in Get-ChildItem -LiteralPath $startup -File -Force -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini') {
    $body = if ($f.Extension -eq '.lnk') { $l = $shell.CreateShortcut($f.FullName); "$($l.TargetPath) $($l.Arguments)" }
            else { Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue }
    Test-Entry startup $f.FullName $body WARN
}
$psProfiles = @("$win\System32\WindowsPowerShell\v1.0\profile.ps1", "$win\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1") +
    ($profiles | ForEach-Object { Get-ChildItem "$_\Documents\WindowsPowerShell\*profile.ps1", "$_\Documents\PowerShell\*profile.ps1" -ErrorAction SilentlyContinue | ForEach-Object FullName })
foreach ($f in $psProfiles | Where-Object { Test-Path -LiteralPath $_ }) {
    Test-Entry ps-profile $f (Get-Content -LiteralPath $f -Raw) WARN
}

# --- BITS notify commands, netsh helpers, per-user COM hijacks ---
foreach ($m in bitsadmin /list /allusers /verbose 2>$null | Select-String 'NOTIFICATION COMMAND LINE:\s*(.+)') {
    $v = $m.Matches[0].Groups[1].Value.Trim(); if ($v -ne 'none') { Out-Finding FAIL bits 'bitsadmin' $v }
}
$ns = Get-Item 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction SilentlyContinue
if ($ns) { foreach ($n in $ns.GetValueNames()) { $v = $ns.GetValue($n); if ($v -match '\\') { Out-Finding WARN netsh "$($ns.Name)\$n" $v } } }
foreach ($sid in $userSids) {
    foreach ($k in Get-ChildItem "Registry::HKEY_USERS\${sid}_Classes\CLSID\*\InprocServer32" -ErrorAction SilentlyContinue) {
        Test-Entry com-hijack $k.Name $k.GetValue('') WARN
    }
}

if ($script:fail) { exit 2 }
