#!/usr/bin/env python3
"""Start Patchalyzer.ai web server."""
import multiprocessing
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import uvicorn
from backend.config import HOST, PORT, ensure_dirs

if __name__ == "__main__":
    multiprocessing.freeze_support()
    ensure_dirs()
    print(f"Patchalyzer.ai: http://{HOST}:{PORT}")
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=False)
