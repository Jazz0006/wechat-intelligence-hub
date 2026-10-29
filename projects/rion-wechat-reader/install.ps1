[CmdletBinding()]
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'RionWeChat'),
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$runtime = $null
$created = $false
try {
    if ($env:OS -ne 'Windows_NT') { throw 'Windows 10/11 x64 is required.' }
    $Prefix = [IO.Path]::GetFullPath($Prefix)
    if ($Prefix.StartsWith('\\')) { throw 'A local installation directory is required.' }
    if (Test-Path -LiteralPath $Prefix) { throw 'Installation directory already exists; nothing overwritten.' }
    $parent = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($Prefix))
    while ($null -ne $parent) {
        if ($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Installation paths must not contain junctions or symbolic links.'
        }
        $parent = $parent.Parent
    }
    $pythonCommand = (Get-Command $Python -CommandType Application -ErrorAction Stop).Source
    $identity = & $pythonCommand -c "import json,platform,struct,sys; print(json.dumps([sys.platform,struct.calcsize('P'),platform.machine().lower(),list(sys.version_info[:2])]))"
    if ($LASTEXITCODE -ne 0) { throw 'Python could not be started.' }
    $identity = $identity | ConvertFrom-Json
    if ($identity[0] -ne 'win32' -or $identity[1] -ne 8 -or $identity[2] -notin @('amd64', 'x86_64') -or
        $identity[3][0] -ne 3 -or $identity[3][1] -notin @(11,12)) {
        throw 'Use Windows x64 Python 3.11 or 3.12. No Python was installed or changed.'
    }
    [void][IO.Directory]::CreateDirectory($Prefix)
    $created = $true
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($owner in @($sid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $owner, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Prefix -AclObject $acl
    $runtime = Join-Path $Prefix 'share\rion-wechat-cli'
    [void][IO.Directory]::CreateDirectory($runtime)
    [void][IO.Directory]::CreateDirectory((Join-Path $Prefix 'bin'))
    foreach ($file in @('rion_wechat_reader.py', 'rion_wechat_access.py', 'rion_wechat_windows.py')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $runtime $file)
    }
    & $pythonCommand -m venv --copies (Join-Path $runtime 'venv')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create the private Python runtime.' }
    $runtimePython = Join-Path $runtime 'venv\Scripts\python.exe'
    & $runtimePython -m pip install --disable-pip-version-check --no-input --only-binary=:all: --timeout 30 --retries 1 'sqlcipher3==0.6.2' 'zstandard==0.25.0'
    if ($LASTEXITCODE -ne 0) { throw 'Failed to install pinned binary dependencies.' }
    $launcher = @'
$ErrorActionPreference = 'Stop'
$runtime = Join-Path (Split-Path -Parent $PSScriptRoot) 'share\rion-wechat-cli'
$engine = if ([IO.Path]::GetFileNameWithoutExtension($PSCommandPath) -eq 'rion-wechat-access') { 'rion_wechat_access.py' } else { 'rion_wechat_reader.py' }
& (Join-Path $runtime 'venv\Scripts\python.exe') (Join-Path $runtime $engine) @args
exit $LASTEXITCODE
'@
    foreach ($name in @('rion-wechat-cli', 'rion-wechat-reader', 'rion-wechat-access')) {
        [IO.File]::WriteAllText((Join-Path $Prefix "bin\$name.ps1"), $launcher, [Text.UTF8Encoding]::new($false))
    }
    & $runtimePython (Join-Path $runtime 'rion_wechat_reader.py') self-test --require-sqlcipher
    if ($LASTEXITCODE -ne 0) { throw 'Reader self-test failed.' }
    Write-Output "Installed Windows reader and experimental access helper: $Prefix"
    Write-Output 'Installation did not read WeChat memory, obtain keys, change PATH, or request elevation.'
} catch {
    # Only this new installation is removed. Existing configs/materials live elsewhere.
    if ($created -and (Test-Path -LiteralPath $Prefix)) { Remove-Item -LiteralPath $Prefix -Recurse -Force }
    Write-Error $_
    exit 1
}
