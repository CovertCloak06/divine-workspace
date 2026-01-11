#!/usr/bin/env python3
"""
File Watcher for PKN
Automatically runs checks when JavaScript files change
"""

import time
import subprocess
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

PKN_DIR = Path(__file__).parent
JS_DIR = PKN_DIR / "js"
PLUGINS_DIR = PKN_DIR / "plugins"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class JSFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_check = 0
        self.debounce = 1  # seconds

    def on_modified(self, event):
        if event.is_directory:
            return

        # Only check .js files
        if not event.src_path.endswith('.js'):
            return

        # Debounce multiple rapid changes
        now = time.time()
        if now - self.last_check < self.debounce:
            return

        self.last_check = now

        print(f"\n{Colors.CYAN}📝 File changed: {Path(event.src_path).name}{Colors.END}")
        print(f"{Colors.YELLOW}Running checks...{Colors.END}\n")

        # Run the error checker
        try:
            result = subprocess.run(
                ['python3', str(PKN_DIR / 'check_js_errors.py')],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                print(f"{Colors.GREEN}✓ All checks passed{Colors.END}\n")
            else:
                print(f"{Colors.RED}✗ Issues found - check output above{Colors.END}\n")

        except Exception as e:
            print(f"{Colors.RED}Error running checks: {e}{Colors.END}\n")

def main():
    print(f"{Colors.CYAN}{Colors.BOLD}PKN File Watcher{Colors.END}\n")
    print(f"Watching for changes in:")
    print(f"  • {JS_DIR}")
    print(f"  • {PLUGINS_DIR}")
    print(f"\n{Colors.YELLOW}Press Ctrl+C to stop{Colors.END}\n")

    event_handler = JSFileHandler()
    observer = Observer()

    # Watch js/ directory
    if JS_DIR.exists():
        observer.schedule(event_handler, str(JS_DIR), recursive=False)

    # Watch plugins/ directory
    if PLUGINS_DIR.exists():
        observer.schedule(event_handler, str(PLUGINS_DIR), recursive=True)

    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Stopping file watcher...{Colors.END}")
        observer.stop()

    observer.join()

if __name__ == "__main__":
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        main()
    except ImportError:
        print(f"{Colors.RED}Error: watchdog module not installed{Colors.END}")
        print(f"\nInstall with: pip3 install watchdog")
        print(f"Then run: ./dev watch")
