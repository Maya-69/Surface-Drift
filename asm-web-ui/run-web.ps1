$ErrorActionPreference = 'Stop'
$webDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $webDir
Set-Location $repoRoot
python -m pip install -r (Join-Path $webDir 'requirements.txt')
python -m uvicorn server:app --app-dir $webDir --host 127.0.0.1 --port 8000
