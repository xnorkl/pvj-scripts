#Requires -RunAsAdministrator

<#
.EXAMPLE
    .\Reset-SshHostKey.ps1 [-WhatIf]
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
if (-not $svc -or $svc.PathName -notmatch '^"?([^"]+sshd\.exe)') { throw 'sshd service not found' }
$sshd = $Matches[1]
$keygen = Join-Path (Split-Path $sshd) 'ssh-keygen.exe'
$sshDir = "$env:ProgramData\ssh"

$keys = & $sshd -T | Where-Object { $_ -like 'hostkey *' } |
    ForEach-Object { [IO.Path]::GetFullPath((($_ -replace '^hostkey ').Replace('__PROGRAMDATA__', $env:ProgramData))) }
# ponytail: ssh-keygen -A only writes default paths; custom HostKey paths are left alone
$keys = foreach ($k in $keys) {
    if ($k -like "$sshDir\ssh_host_*_key") { $k } else { Write-Warning "skipping non-default host key $k" }
}
if (-not $PSCmdlet.ShouldProcess(($keys -join ', '), 'regenerate host keys')) { return }

$backup = "$sshDir\hostkeys-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory $backup | Out-Null
foreach ($k in $keys) { Move-Item -LiteralPath $k, "$k.pub" $backup -ErrorAction SilentlyContinue }

& $keygen -A
if ($LASTEXITCODE) { Copy-Item "$backup\*" $sshDir -Force; throw "ssh-keygen -A failed; restored old host keys" }
foreach ($k in $keys) {
    if (Test-Path -LiteralPath $k) { icacls $k /inheritance:r /setowner '*S-1-5-18' /grant '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null }
}

& $sshd -t
if ($LASTEXITCODE) {
    Copy-Item "$backup\*" $sshDir -Force
    throw "sshd -t failed; restored old host keys from $backup"
}
Restart-Service sshd
foreach ($k in $keys) { if (Test-Path -LiteralPath "$k.pub") { & $keygen -lf "$k.pub" } }
"old keys saved under $backup"
