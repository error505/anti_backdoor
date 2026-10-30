"""Starts Flockion Backdoor Watch on the loopback interface with a fresh session token."""

import argparse
import logging
import os
import secrets
import tempfile
import threading
from pathlib import Path
import webbrowser

import uvicorn

from backdoor_watch.container import build_services
from backdoor_watch.main import create_app
from backdoor_watch.platform.privileges import is_admin
from backdoor_watch.settings import Settings


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backdoor Watch")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--demo", action="store_true",
                        help="Show fictional data (read-only, touches nothing on this PC). For screenshots and trials.")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # A fixed token from the environment is only for the Vite dev server workflow.
    token = os.environ.get("BACKDOOR_WATCH_TOKEN") or secrets.token_urlsafe(32)
    settings = (Settings(port=args.port, token=token, demo=True, data_dir=Path(tempfile.mkdtemp(prefix="fbw-demo-")))
                if args.demo else Settings(port=args.port, token=token))
    url = f"http://127.0.0.1:{args.port}/#token={token}"

    if args.demo:
        print("DEMO MODE: fictional data, read-only. Nothing on this PC is inspected or changed.")
    elif not is_admin():
        print("WARNING: not running as administrator. Byte counters, firewall, services and "
              "some process details will be unavailable. Use start.ps1 to elevate.")
    print(f"\nBackdoor Watch UI: {url}\n")
    if not args.no_browser:
        threading.Timer(2.0, webbrowser.open, args=(url,)).start()
    uvicorn.run(create_app(build_services(settings)), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
