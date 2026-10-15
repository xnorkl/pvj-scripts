#Requires -RunAsAdministrator

<#
.EXAMPLE
    .\Get-SshAuthorizedKey.ps1 | Export-Csv keys.csv -NoTypeInformation
#>
[CmdletBinding()]
param()

$svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
if (-not $svc -or $svc.PathName -notmatch '^"?([^"]+sshd\.exe)') { throw 'sshd service not found' }
$sshd = $Matches[1]
$keyRe = '(?<type>ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-[a-z0-9-]+@openssh\.com|[a-z0-9-]+-cert-v01@openssh\.com) (?<blob>AAAA[A-Za-z0-9+/=]+)'
$sha = [Security.Cryptography.SHA256]::Create()

$global = & $sshd -T
if ($LASTEXITCODE) { throw 'sshd -T failed' }
$global | Where-Object { $_ -match '^(authorizedkeyscommand|authorizedprincipalsfile|authorizedprincipalscommand|trustedusercakeys) (?!none$)' } |
    ForEach-Object { Write-Warning "alternate key trust path: $_" }

# Path -> owning user; ordered so first discovery wins
$files = [ordered]@{ "$env:ProgramData\ssh\administrators_authorized_keys" = 'BUILTIN\Administrators' }
foreach ($p in Get-CimInstance Win32_UserProfile -Filter 'Special=False') {
    try { $user = ([Security.Principal.SecurityIdentifier]$p.SID).Translate([Security.Principal.NTAccount]).Value } catch { continue }
    $name = $user.Split('\')[-1]   # ponytail: short name only; domain users with clashing local names may resolve wrong
    $cfg = & $sshd -T -C "user=$name,host=localhost,addr=127.0.0.1" 2>$null | Where-Object { $_ -like 'authorizedkeysfile *' }
    $paths = if ($cfg) { ($cfg -replace '^authorizedkeysfile ') -split ' ' } else {
        Write-Warning "sshd -T -C failed for $name; using default path"; '.ssh/authorized_keys' }
    foreach ($f in $paths) {
        $f = $f.Replace('__PROGRAMDATA__', $env:ProgramData).Replace('%h', $p.LocalPath).Replace('%u', $name).Replace('%%', '%')
        if (-not [IO.Path]::IsPathRooted($f)) { $f = Join-Path $p.LocalPath $f }
        $f = [IO.Path]::GetFullPath($f)
        if (-not $files.Contains($f)) { $files[$f] = $user }
    }
}

foreach ($f in $files.Keys) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
    foreach ($line in [IO.File]::ReadAllLines($f)) {
        if ($line -match '^\s*(#|$)') { continue }
        if ($line -notmatch $keyRe) { Write-Warning "unparsed line in ${f}: $line"; continue }
        $key = $Matches[0]
        $i = $line.IndexOf($key)
        $fp = try { 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash([Convert]::FromBase64String($Matches.blob))).TrimEnd('=') } catch { 'INVALID' }
        [pscustomobject]@{
            User        = $files[$f]
            Path        = $f
            Type        = $Matches.type
            Fingerprint = $fp
            Comment     = $line.Substring($i + $key.Length).Trim()
            Options     = $line.Substring(0, $i).Trim()
            Key         = $key
        }
    }
}
