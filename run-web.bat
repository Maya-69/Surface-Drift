@echo off
set "REPO_ROOT=%~dp0"
set "WEB_DIR=%REPO_ROOT%asm-web-ui"
set "VENV_PY=%REPO_ROOT%.venv\Scripts\python.exe"

if exist "%VENV_PY%" (
    "%VENV_PY%" -m uvicorn server:app --app-dir "%WEB_DIR%" --host 127.0.0.1 --port 8000
) else (
    py -3.12 -m uvicorn server:app --app-dir "%WEB_DIR%" --host 127.0.0.1 --port 8000
)
