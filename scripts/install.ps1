[CmdletBinding()]
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'RionWeChat'),
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$installer = Join-Path (Split-Path -Parent $PSScriptRoot) 'projects\rion-wechat-reader\install.ps1'
& $installer -Prefix $Prefix -Python $Python
