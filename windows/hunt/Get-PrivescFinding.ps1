#Requires -RunAsAdministrator

<#
.EXAMPLE
    .\Get-PrivescFinding.ps1 | Where-Object Status -eq FAIL   # exit 2 = FAIL found
#>
[CmdletBinding()]
param()

$script:fail = $false
function Out-Finding($Status, $Check, $Object, $Detail) {
    if ($Status -eq 'FAIL') { $script:fail = $true }
    [pscustomobject]@{ Status = $Status; Check = $Check; Object = $Object; Detail = "$Detail" }
}
function Get-RegValue($Key, $Name) { (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction SilentlyContinue).$Name }

$win = $env:windir
$trusted = 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'NT SERVICE\TrustedInstaller'
function Test-NonAdminWritable($Path) {
    (Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.FileSystemRights -match 'Write|Modify|FullControl|TakeOwnership|ChangePermissions' -and
        $_.IdentityReference.Value -notin $trusted
    } | ForEach-Object { $_.IdentityReference.Value }
}

# Accessibility binaries swapped for a shell: IFEO debugger, or no longer validly signed
foreach ($b in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'AtBroker.exe', 'DisplaySwitch.exe') {
    $dbg = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$b" Debugger
    if ($dbg) { Out-Finding FAIL stickykeys $b "IFEO debugger: $dbg" }
    $path = Join-Path "$win\System32" $b
    if (Test-Path -LiteralPath $path) {
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        if ($sig.Status -ne 'Valid') { Out-Finding FAIL stickykeys $path "not validly signed ($($sig.Status))" }
    }
}

# AlwaysInstallElevated in both hives = any user installs an MSI as SYSTEM
if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated) -eq 1 -and
    (Get-RegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated) -eq 1) {
    Out-Finding FAIL alwayselevated 'HKLM+HKCU\...\Windows\Installer' 'AlwaysInstallElevated=1'
}

# Defender off or carved out
try {
    $st = Get-MpComputerStatus -ErrorAction Stop
    if (-not $st.RealTimeProtectionEnabled) { Out-Finding FAIL defender RealTimeProtection 'disabled' }
    $mp = Get-MpPreference -ErrorAction Stop
    foreach ($p in $mp.ExclusionPath)      { Out-Finding WARN defender exclusion:path      $p }
    foreach ($p in $mp.ExclusionProcess)   { Out-Finding WARN defender exclusion:process   $p }
    foreach ($e in $mp.ExclusionExtension) { Out-Finding WARN defender exclusion:extension $e }
} catch { }   # Defender not installed

# Services: unquoted path with a space, or a binary non-admins can overwrite
foreach ($s in Get-CimInstance Win32_Service) {
    $path = "$($s.PathName)"
    if (-not $path) { continue }
    if ($path -notmatch '^"' -and $path -match '^(.*?\.exe)\b' -and $Matches[1] -match ' ') {
        Out-Finding WARN service $s.Name "unquoted path with spaces: $path"
    }
    $exe = if ($path -match '^"([^"]+)"') { $Matches[1] } elseif ($path -match '^(\S+\.exe)') { $Matches[1] }
    if ($exe) {
        $exe = [Environment]::ExpandEnvironmentVariables($exe)
        if (Test-Path -LiteralPath $exe) {
            foreach ($id in Test-NonAdminWritable $exe) { Out-Finding FAIL service "$($s.Name) ($id)" "service binary writable by non-admin: $exe" }
        }
    }
}

if ($script:fail) { exit 2 }
