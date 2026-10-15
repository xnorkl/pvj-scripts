#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Read-only audit of sshd's effective config plus the files that can change it.
.DESCRIPTION
    Emits findings only (PASS is silent): Status, Check, Object, Detail.
    Exit code: 0 clean, 1 error, 2 at least one FAIL (Ansible: failed_when: rc == 1).
    Audit only: fix by hand. Scorebot may rely on passwords and SSH must stay up.
.EXAMPLE
    .\Get-SshdConfigFinding.ps1 | Format-Table -AutoSize
#>
[CmdletBinding()]
param()

$svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
if (-not $svc -or $svc.PathName -notmatch '^"?([^"]+sshd\.exe)') { throw 'sshd service not found' }
$cfg = & $Matches[1] -T
if ($LASTEXITCODE) { throw 'sshd -T failed' }
$script:fail = $false
function Out-Finding($Status, $Check, $Object, $Detail) {
    if ($Status -eq 'FAIL') { $script:fail = $true }
    [pscustomobject]@{ Status = $Status; Check = $Check; Object = $Object; Detail = $Detail }
}

# setting ; value must match (regex) ; status if not ; why
$rules = @'
authorizedkeyscommand;^none$;FAIL;keys come from a program
authorizedprincipalscommand;^none$;FAIL;principals come from a program
trustedusercakeys;^none$;FAIL;any cert this CA signs can log in
authorizedprincipalsfile;^none$;WARN;cert principals file in use
authorizedkeysfile;^\.ssh/authorized_keys$;WARN;non-default key files
forcecommand;^none$;FAIL;command wraps every login
permituserenvironment;^no$;FAIL;~/.ssh/environment can set environment variables
permituserrc;^no$;WARN;~/.ssh/rc runs on every login
subsystem;^sftp (internal-sftp|\S*sftp-server(\.exe)?)( |$);FAIL;unexpected subsystem binary
hostkey;^(__PROGRAMDATA__|[A-Za-z]:[\\/]ProgramData)[\\/]ssh[\\/]ssh_host_[a-z0-9]+_key$;WARN;host key outside ProgramData\ssh
revokedkeys;^(?!none$);WARN;no KRL, run Revoke-SshKey.ps1
permitrootlogin;^(no|prohibit-password|without-password|forced-commands-only)$;FAIL;root can log in with a password
permitemptypasswords;^no$;FAIL;empty passwords allowed
hostbasedauthentication;^no$;FAIL;host-based trust
strictmodes;^yes$;FAIL;sshd accepts loosely permissioned key files
passwordauthentication;^no$;INFO;Scorebot may need passwords, so rotate them rather than disabling
allowtcpforwarding;^no$;WARN;port forwarding (pivot)
allowagentforwarding;^no$;WARN;agent hijack on this host
gatewayports;^no$;WARN;remote forwards bind on all interfaces
permittunnel;^no$;WARN;tunnels
loglevel;^VERBOSE$;WARN;VERBOSE logs which key fingerprint logged in
'@ -split "`r?`n"

foreach ($rule in $rules) {
    $key, $ok, $sev, $why = $rule -split ';', 4
    foreach ($line in $cfg) {
        $k, $val = $line.Trim() -split ' ', 2
        if ($k -eq $key -and $val -notmatch $ok) { Out-Finding $sev $key $val $why }
    }
}

# Config files: sshd_config plus Include targets (relative paths are under ProgramData\ssh)
$sshDir = "$env:ProgramData\ssh"
$main = "$sshDir\sshd_config"
$files = @($main) + @(Select-String -LiteralPath $main -Pattern '^\s*Include\s+(.+)' | ForEach-Object {
    foreach ($g in $_.Matches[0].Groups[1].Value -split '\s+') {
        $g = $g.Replace('__PROGRAMDATA__', $env:ProgramData)
        if (-not [IO.Path]::IsPathRooted($g)) { $g = Join-Path $sshDir $g }
        (Get-Item -Path $g -ErrorAction SilentlyContinue).FullName
    } })
$trusted = 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'NT SERVICE\TrustedInstaller'
foreach ($f in $files | Where-Object { $_ }) {
    $writers = (Get-Acl -LiteralPath $f).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -match 'Write|Modify|FullControl|ChangePermissions|TakeOwnership' -and
        $_.IdentityReference.Value -notin $trusted }
    foreach ($w in $writers) { Out-Finding FAIL file "$f ($($w.IdentityReference))" 'config writable by non-admin' }
    Out-Finding INFO file $f "modified $((Get-Item -LiteralPath $f).LastWriteTime.ToString('s'))"
    # sshd -T shows global values only, so Match blocks can override them unseen
    foreach ($m in Select-String -LiteralPath $f -Pattern '^\s*Match\s') {
        $sev = if ($m.Line -match '^\s*Match Group administrators\s*$') { 'INFO' } else { 'WARN' }   # Windows default block
        Out-Finding $sev match "${f}:$($m.LineNumber):$($m.Line.Trim())" 'overrides above are invisible to sshd -T: review'
    }
}

# Login-time scripts
if (Test-Path "$sshDir\sshrc") { Out-Finding FAIL file "$sshDir\sshrc" 'runs for every user on every login' }
foreach ($p in Get-CimInstance Win32_UserProfile -Filter 'Special=False') {
    foreach ($f in "$($p.LocalPath)\.ssh\rc", "$($p.LocalPath)\.ssh\environment") {
        if (Test-Path -LiteralPath $f) { Out-Finding WARN file $f 'runs or loads at login' }
    }
}

if ($script:fail) { exit 2 }
