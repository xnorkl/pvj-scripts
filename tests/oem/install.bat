@echo off
rem Runs once at first boot (dockur/windows /oem). Enables WinRM for ansible.windows (test only).
powershell -Command "Enable-PSRemoting -Force; Set-Item WSMan:\localhost\Service\Auth\Basic $true; Set-Item WSMan:\localhost\Service\AllowUnencrypted $true; New-NetFirewallRule -DisplayName 'WinRM 5985' -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow"
