#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Appends a public key to a user's primary authorized keys file (from sshd's effective config).
.DESCRIPTION
    Run this BEFORE Revoke-SshKey / Reset-SshAuthorizedKey so the team keeps key access.
    Admin accounts resolve to administrators_authorized_keys. ACLs are set so sshd accepts the file.
.EXAMPLE
    .\Add-SshAuthorizedKey.ps1 -UserName Administrator -PublicKeyPath .\team.pub
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $UserName,
    [Parameter(Mandatory)] [string] $PublicKeyPath
)

$svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
if (-not $svc -or $svc.PathName -notmatch '^"?([^"]+sshd\.exe)') { throw 'sshd service not found' }
$sshd = $Matches[1]
$keygen = Join-Path (Split-Path $sshd) 'ssh-keygen.exe'

$fp = & $keygen -lf $PublicKeyPath
if ($LASTEXITCODE) { throw "not a valid public key: $PublicKeyPath" }
$pub = (Get-Content -LiteralPath $PublicKeyPath -TotalCount 1).Trim()

$sid = ([Security.Principal.NTAccount]$UserName).Translate([Security.Principal.SecurityIdentifier]).Value
$home_ = (Get-CimInstance Win32_UserProfile -Filter "SID='$sid'").LocalPath
if (-not $home_) { throw "no profile for $UserName (log in once first)" }

$cfg = & $sshd -T -C "user=$UserName,host=localhost,addr=127.0.0.1" | Where-Object { $_ -like 'authorizedkeysfile *' }
$f = (($cfg -replace '^authorizedkeysfile ') -split ' ')[0]
$f = $f.Replace('__PROGRAMDATA__', $env:ProgramData).Replace('%h', $home_).Replace('%u', $UserName).Replace('%%', '%')
if (-not [IO.Path]::IsPathRooted($f)) { $f = Join-Path $home_ $f }
$f = [IO.Path]::GetFullPath($f)

if ((Test-Path -LiteralPath $f) -and ((Get-Content -LiteralPath $f) -match [regex]::Escape(($pub -split ' ')[1]))) {
    "no change: already present in $f"; return
}
if ($PSCmdlet.ShouldProcess($f, "add $fp")) {
    New-Item -ItemType Directory -Force (Split-Path $f) | Out-Null
    [IO.File]::AppendAllText($f, "$pub`n")
    # sshd ignores key files that other principals can write
    $grants = '*S-1-5-18:F', '*S-1-5-32-544:F'
    if ($f -notlike "$env:ProgramData\ssh\*") { $grants += "*${sid}:F" }
    icacls $f /inheritance:r /grant $grants | Out-Null
    "added $fp to $f"
}
