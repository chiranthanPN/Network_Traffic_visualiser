"""
Network Traffic Analyser — Single-command launcher.

Starts the FastAPI backend, waits for it to become healthy,
then starts the Vite frontend dev server.

Usage:
    python run.py            (default: backend on 8000, frontend on 5173)
    python run.py --skip-install   (skip npm install even if node_modules is missing)

Press Ctrl+C once to shut everything down cleanly.
"""

import subprocess
import sys
import os
import time
import shutil
import urllib.request
import urllib.error

# Ensure UTF-8 output on Windows consoles if supported
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Configuration ────────────────────────────────────────────────────────────

ROOT_DIR       = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR    = os.path.join(ROOT_DIR, "backend")
FRONTEND_DIR   = os.path.join(ROOT_DIR, "frontend")
BACKEND_PORT   = 8000
FRONTEND_PORT  = 5173
HEALTH_URL     = f"http://localhost:{BACKEND_PORT}/api/health"
MAX_WAIT_SECS  = 60          # max seconds to wait for backend health
POLL_INTERVAL  = 1.5         # seconds between health polls

# ── Helpers ──────────────────────────────────────────────────────────────────

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def log(color, tag, msg):
    print(f"  {color}{BOLD}[{tag}]{RESET} {msg}", flush=True)

def has_backend_deps(python_exe):
    """Check if the given Python executable has uvicorn and fastapi installed."""
    if not python_exe:
        return False
    try:
        res = subprocess.run(
            [python_exe, "-c", "import uvicorn, fastapi"],
            capture_output=True,
            timeout=4,
        )
        return res.returncode == 0
    except Exception:
        return False

def find_python():
    """
    Search for a working Python executable that actually has the project's
    dependencies (uvicorn, fastapi) installed.
    """
    candidates = []

    # 1. Current running interpreter
    if sys.executable and os.path.exists(sys.executable):
        candidates.append(sys.executable)

    # 2. Well-known commands on PATH
    for cmd in ("py", "python", "python3"):
        path = shutil.which(cmd)
        if path and path not in candidates:
            candidates.append(cmd)

    # 3. Common Windows install locations
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        py313 = os.path.join(local_app_data, "Programs", "Python", "Python313", "python.exe")
        if os.path.exists(py313) and py313 not in candidates:
            candidates.append(py313)

        prog_py_dir = os.path.join(local_app_data, "Programs", "Python")
        if os.path.isdir(prog_py_dir):
            for entry in os.listdir(prog_py_dir):
                candidate = os.path.join(prog_py_dir, entry, "python.exe")
                if os.path.exists(candidate) and candidate not in candidates:
                    candidates.append(candidate)

        py_bin_dir = os.path.join(local_app_data, "Python")
        if os.path.isdir(py_bin_dir):
            for entry in os.listdir(py_bin_dir):
                candidate = os.path.join(py_bin_dir, entry, "python.exe")
                if os.path.exists(candidate) and candidate not in candidates:
                    candidates.append(candidate)

    # First pass: Return the first candidate that has uvicorn & fastapi installed
    for c in candidates:
        if has_backend_deps(c):
            return c

    # Second pass: Fall back to any functional Python if deps are missing
    for c in candidates:
        try:
            res = subprocess.run([c, "-c", "import sys"], capture_output=True, timeout=3)
            if res.returncode == 0:
                return c
        except Exception:
            pass

    return sys.executable or "python"

def find_npm():
    """Return the npm executable (preferring npm.cmd on Windows)."""
    if os.name == "nt":
        return shutil.which("npm.cmd") or shutil.which("npm")
    return shutil.which("npm")

def wait_for_backend(timeout=MAX_WAIT_SECS):
    """Poll the backend health endpoint until it responds 200."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(HEALTH_URL, headers={"User-Agent": "HealthCheck/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(POLL_INTERVAL)
    return False

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    skip_install = "--skip-install" in sys.argv

    print()
    print(f"  {CYAN}{BOLD}+==============================================+{RESET}")
    print(f"  {CYAN}{BOLD}|     Network Traffic Analyser  -  Launcher    |{RESET}")
    print(f"  {CYAN}{BOLD}+==============================================+{RESET}")
    print()

    python = find_python()
    npm    = find_npm()

    # ── Pre-flight checks ────────────────────────────────────────────────

    if not os.path.isdir(BACKEND_DIR):
        log(RED, "ERROR", f"Backend directory not found: {BACKEND_DIR}")
        sys.exit(1)

    if not os.path.isdir(FRONTEND_DIR):
        log(RED, "ERROR", f"Frontend directory not found: {FRONTEND_DIR}")
        sys.exit(1)

    # Verify Python has required backend packages
    if not has_backend_deps(python):
        log(RED, "ERROR", f"Python executable '{python}' is missing required packages (uvicorn/fastapi).")
        log(YELLOW, "HINT", f"Install them by running: {python} -m pip install -r backend/requirements.txt")
        sys.exit(1)

    log(GREEN, "PYTHON", f"Using Python: {python}")

    if npm is None:
        log(RED, "ERROR", "npm not found. Please install Node.js (v18+) and ensure npm is on PATH.")
        sys.exit(1)

    # ── Install frontend deps if needed ──────────────────────────────────

    node_modules = os.path.join(FRONTEND_DIR, "node_modules")
    if not os.path.isdir(node_modules) and not skip_install:
        log(YELLOW, "NPM", "node_modules not found - running npm install ...")
        result = subprocess.run(
            [npm, "install"],
            cwd=FRONTEND_DIR,
            shell=(os.name == "nt"),
        )
        if result.returncode != 0:
            log(RED, "ERROR", "npm install failed. Fix the errors above and retry.")
            sys.exit(1)
        log(GREEN, "NPM", "Dependencies installed.")
    else:
        log(GREEN, "NPM", "node_modules present - skipping install.")

    # ── Start backend ────────────────────────────────────────────────────

    log(CYAN, "BACKEND", f"Starting uvicorn on port {BACKEND_PORT} ...")

    backend_cmd = [
        python, "-m", "uvicorn",
        "app.main:app",
        "--host", "0.0.0.0",
        "--port", str(BACKEND_PORT),
    ]

    creation_flags = 0
    if os.name == "nt":
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

    backend_proc = subprocess.Popen(
        backend_cmd,
        cwd=BACKEND_DIR,
        creationflags=creation_flags,
    )

    # ── Wait for backend health ──────────────────────────────────────────

    log(CYAN, "BACKEND", f"Waiting for health check at {HEALTH_URL} ...")

    if not wait_for_backend():
        log(RED, "ERROR", f"Backend did not become healthy within {MAX_WAIT_SECS}s.")
        log(RED, "ERROR", "Check the backend console output for details.")
        backend_proc.terminate()
        sys.exit(1)

    log(GREEN, "BACKEND", "Backend is healthy [OK]")

    # ── Start frontend ───────────────────────────────────────────────────

    log(CYAN, "FRONTEND", f"Starting Vite dev server on port {FRONTEND_PORT} ...")

    frontend_cmd = [npm, "run", "dev", "--", "--port", str(FRONTEND_PORT)]

    frontend_proc = subprocess.Popen(
        frontend_cmd,
        cwd=FRONTEND_DIR,
        shell=(os.name == "nt"),
    )

    print()
    log(GREEN, "READY", f"Dashboard -> {BOLD}http://localhost:{FRONTEND_PORT}{RESET}")
    log(GREEN, "READY", f"API       -> {BOLD}http://localhost:{BACKEND_PORT}/api/health{RESET}")
    print()
    log(YELLOW, "INFO", "Press Ctrl+C to stop both servers.\n")

    # ── Wait for either process to exit, or Ctrl+C ───────────────────────

    try:
        while True:
            if backend_proc.poll() is not None:
                log(RED, "BACKEND", f"Backend exited with code {backend_proc.returncode}")
                frontend_proc.terminate()
                sys.exit(backend_proc.returncode or 1)

            if frontend_proc.poll() is not None:
                log(RED, "FRONTEND", f"Frontend exited with code {frontend_proc.returncode}")
                backend_proc.terminate()
                sys.exit(frontend_proc.returncode or 1)

            time.sleep(1)

    except KeyboardInterrupt:
        print()
        log(YELLOW, "SHUTDOWN", "Ctrl+C received - stopping servers ...")

        frontend_proc.terminate()
        backend_proc.terminate()

        try:
            frontend_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            frontend_proc.kill()

        try:
            backend_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            backend_proc.kill()

        log(GREEN, "SHUTDOWN", "All servers stopped.\n")


if __name__ == "__main__":
    main()
