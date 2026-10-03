#!/usr/bin/env sh
set -eu
WEB_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(dirname "$WEB_DIR")"
cd "$REPO_ROOT"
python3 -m pip install -r "$WEB_DIR/requirements.txt"
python3 -m uvicorn server:app --app-dir "$WEB_DIR" --host 127.0.0.1 --port 8000
