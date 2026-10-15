#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Rewrites every discovered authorized keys file down to an allowlist (default: empty).
.DESCRIPTION
    Takes Get-SshAuthorizedKey output on the pipeline. Originals are copied to
    %ProgramData%\ssh\quarantine-<ts>\ as evidence. Files are rewritten in place, so ACLs are kept.
.EXAMPLE
    .\Get-SshAuthorizedKey.ps1 | .\Reset-SshAuthorizedKey.ps1 -ApprovedKeyPath .\team.pub -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [string[]] $Path,
    [string] $ApprovedKeyPath
)
begin {
    $files = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $quarantine = "$env:ProgramData\ssh\quarantine-$(Get-Date -Format yyyyMMdd-HHmmss)"
}
process { foreach ($p in $Path) { [void]$files.Add($p) } }
end {
    $approved = if ($ApprovedKeyPath) { Get-Content -LiteralPath $ApprovedKeyPath | ForEach-Object { ($_ -split '\s+')[1] } | Where-Object { $_ } }
    foreach ($f in $files) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
        $old = [IO.File]::ReadAllLines($f)
        $keep = @($old | Where-Object { $line = $_; $approved | Where-Object { $line.Contains($_) } })
        if ($keep.Count -eq @($old | Where-Object { $_ -match '\S' }).Count) { continue }   # already only approved keys
        if (-not $PSCmdlet.ShouldProcess($f, "reset ($($old.Count) -> $($keep.Count) lines)")) { continue }
        $dest = Join-Path $quarantine ($f -replace ':', '')
        New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
        Copy-Item -LiteralPath $f $dest
        [IO.File]::WriteAllLines($f, [string[]]$keep)
        $changed = $true
        "reset $f ($($old.Count) -> $($keep.Count) lines)"
    }
    if ($changed) { "originals saved under $quarantine" } else { "no change: only approved keys present" }
}
