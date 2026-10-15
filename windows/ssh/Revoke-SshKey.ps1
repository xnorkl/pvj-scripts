#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Revokes keys server-wide via a KRL (RevokedKeys) so re-planted copies are still rejected.
.DESCRIPTION
    Takes Get-SshAuthorizedKey output on the pipeline. Keys in -ApprovedKeyPath are never revoked.
    Inserts RevokedKeys at the top of sshd_config if not set, validates with `sshd -t`
    (restoring the config on failure) and restarts sshd.
    NOTE: if the KRL file goes missing or unreadable, sshd rejects ALL pubkey auth (fails closed).
    Restarting sshd may drop SSH sessions; run from RDP/console.
.EXAMPLE
    .\Get-SshAuthorizedKey.ps1 | .\Revoke-SshKey.ps1 -ApprovedKeyPath .\team.pub -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [string[]] $Key,
    [string] $ApprovedKeyPath
)
begin { $all = [Collections.Generic.HashSet[string]]::new() }
process { foreach ($k in $Key) { [void]$all.Add($k) } }
end {
    $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    if (-not $svc -or $svc.PathName -notmatch '^"?([^"]+sshd\.exe)') { throw 'sshd service not found' }
    $sshd = $Matches[1]
    $keygen = Join-Path (Split-Path $sshd) 'ssh-keygen.exe'
    $cfg = "$env:ProgramData\ssh\sshd_config"

    $approved = if ($ApprovedKeyPath) { Get-Content -LiteralPath $ApprovedKeyPath | ForEach-Object { ($_ -split '\s+')[1] } }
    $spec = @($all | Where-Object { ($_ -split ' ')[1] -notin $approved } | ForEach-Object { "key: $_" })
    if (-not $spec) { 'no change: nothing to revoke'; return }
    if (-not $PSCmdlet.ShouldProcess("$($spec.Count) key(s)", 'revoke via KRL')) { return }

    $krl = ((& $sshd -T | Where-Object { $_ -like 'revokedkeys *' }) -replace '^revokedkeys ').Replace('__PROGRAMDATA__', $env:ProgramData)
    $backup = "$cfg.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item -LiteralPath $cfg $backup
    if ($krl -eq 'none') {
        $krl = "$env:ProgramData\ssh\revoked_keys"
        # top of file: must precede any Match block
        [IO.File]::WriteAllLines($cfg, [string[]](@("RevokedKeys $($krl -replace '\\', '/')") + [IO.File]::ReadAllLines($cfg)))
    }

    $specFile = New-TemporaryFile
    [IO.File]::WriteAllLines($specFile, [string[]]$spec)
    $update = if (Test-Path -LiteralPath $krl) { '-u' } else { $null }
    & $keygen -k $update -f $krl $specFile
    $ok = -not $LASTEXITCODE
    Remove-Item $specFile

    if ($ok) { & $sshd -t; $ok = -not $LASTEXITCODE }
    if (-not $ok) {
        Copy-Item -LiteralPath $backup $cfg -Force
        throw "KRL update or sshd -t failed; restored $cfg"
    }
    Restart-Service sshd
    "revoked $($spec.Count) key(s) into $krl"
}
