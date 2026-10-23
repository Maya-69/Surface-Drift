$ErrorActionPreference = 'Stop'
$webDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $webDir
Set-Location $repoRoot

$venvPy = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPy) {
    & $venvPy -m uvicorn server:app --app-dir $webDir --host 127.0.0.1 --port 8000
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    py -3.12 -m uvicorn server:app --app-dir $webDir --host 127.0.0.1 --port 8000
} else {
    python -m uvicorn server:app --app-dir $webDir --host 127.0.0.1 --port 8000
}
