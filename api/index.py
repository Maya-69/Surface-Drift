import os
import sys
from pathlib import Path

# Resolve directory paths
ROOT_DIR = Path(__file__).resolve().parent.parent
APP_DIR = ROOT_DIR / "asm-web-ui"

# Insert into Python path
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Vercel Serverless environment configurations (read-only filesystem bypass)
os.environ["VERCEL"] = "1"
os.environ.setdefault("DATABASE_PATH", "/tmp/asm_history.db")
os.environ.setdefault("ASM_ARTIFACTS_DIR", "/tmp/artifacts")
os.environ.setdefault("ASM_RUNS_DIR", "/tmp/demo_run")
os.environ.setdefault("ASM_PROJECT_ROOT", str(ROOT_DIR))

# Import the FastAPI application
from server import app
