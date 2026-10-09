#!/usr/bin/env bash
# =============================================================================
# Supreme Watcher — one-command installer
#
#   Android (Termux):   pkg install -y curl && \
#     curl -sL https://raw.githubusercontent.com/CovertCloak06/supreme-watcher/main/scripts/install.sh | bash
#
#   Raspberry Pi / Linux:
#     curl -sL https://raw.githubusercontent.com/CovertCloak06/supreme-watcher/main/scripts/install.sh | bash
#
# It installs Node + the app, sets up auto-start-on-boot and auto-restart,
# then opens the tap-friendly web setup page. Safe to re-run (idempotent).
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/CovertCloak06/supreme-watcher.git"
APP_DIR="${SUPREME_WATCHER_DIR:-$HOME/supreme-watcher}"

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m!!\033[0m %s\n' "$*"; }

# --- Detect platform ---------------------------------------------------------
IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || command -v termux-setup-storage >/dev/null 2>&1; then
  IS_TERMUX=1
fi

# --- Install dependencies (Node + git) --------------------------------------
install_deps() {
  if [ "$IS_TERMUX" -eq 1 ]; then
    say "Installing Node.js + git via Termux…"
    pkg update -y >/dev/null 2>&1 || true
    pkg install -y nodejs-lts git termux-api >/dev/null
  elif command -v apt-get >/dev/null 2>&1; then
    say "Installing Node.js + git via apt (may ask for your password)…"
    if ! command -v node >/dev/null 2>&1; then
      curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >/dev/null
      sudo apt-get install -y nodejs git >/dev/null
    else
      sudo apt-get install -y git >/dev/null || true
    fi
  else
    warn "Unknown platform. Please install Node.js 20+ and git manually, then re-run."
    exit 1
  fi
  say "Node $(node -v), npm $(npm -v)"
}

# --- Clone or update the app -------------------------------------------------
fetch_app() {
  if [ -d "$APP_DIR/.git" ]; then
    say "Updating existing install in $APP_DIR…"
    git -C "$APP_DIR" pull --ff-only
  else
    say "Cloning into $APP_DIR…"
    git clone --depth 1 "$REPO_URL" "$APP_DIR"
  fi
  say "Installing packages + building…"
  # Build needs dev deps (typescript). Install all, build, then prune dev to save space.
  ( cd "$APP_DIR" \
      && npm install >/dev/null 2>&1 \
      && npm run build >/dev/null \
      && npm prune --omit=dev >/dev/null 2>&1 || true )
}

# --- Auto-start: Android (Termux:Boot) --------------------------------------
setup_autostart_termux() {
  say "Setting up auto-start on boot (Termux:Boot)…"
  mkdir -p "$HOME/.termux/boot"
  cat > "$HOME/.termux/boot/supreme-watcher.sh" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
# Keep the CPU awake and restart the watcher if it ever exits.
termux-wake-lock
cd "$APP_DIR"
while true; do
  node dist/index.js >> "\$HOME/supreme-watcher.log" 2>&1
  sleep 5
done
EOF
  chmod +x "$HOME/.termux/boot/supreme-watcher.sh"
  warn "IMPORTANT: install the 'Termux:Boot' app (F-Droid) and open it once,"
  warn "and disable battery optimization for Termux, or it won't run on boot."
}

# --- Auto-start: Raspberry Pi / Linux (systemd) -----------------------------
setup_autostart_systemd() {
  say "Setting up auto-start on boot (systemd)…"
  local unit=/etc/systemd/system/supreme-watcher.service
  sudo tee "$unit" >/dev/null <<EOF
[Unit]
Description=Supreme Watcher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$(command -v node) $APP_DIR/dist/index.js
Restart=always
RestartSec=5
User=$USER
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable supreme-watcher >/dev/null
  say "Service installed. Start it after setup with: sudo systemctl start supreme-watcher"
}

# --- Run the web setup if not configured ------------------------------------
run_setup() {
  if [ -f "$APP_DIR/.env" ] && grep -q 'PUSHOVER_USER=.\+' "$APP_DIR/.env"; then
    say "Already configured (.env found) — skipping setup page."
    return
  fi
  say "Launching the tap-friendly setup page…"
  say "Open http://localhost:8787 in this device's browser to finish."
  ( cd "$APP_DIR" && node dist/setup.js )
}

# --- Start it now ------------------------------------------------------------
start_now() {
  if [ "$IS_TERMUX" -eq 1 ]; then
    say "Starting the watcher now (also runs on every boot)…"
    ( cd "$APP_DIR" && nohup sh "$HOME/.termux/boot/supreme-watcher.sh" >/dev/null 2>&1 & )
  else
    sudo systemctl restart supreme-watcher || true
  fi
  say "✅ Done. Supreme Watcher is running and will restart on boot."
  say "   Logs (Android): ~/supreme-watcher.log"
  say "   Logs (Pi):      sudo journalctl -u supreme-watcher -f"
}

main() {
  install_deps
  fetch_app
  if [ "$IS_TERMUX" -eq 1 ]; then setup_autostart_termux; else setup_autostart_systemd; fi
  run_setup
  start_now
}

main "$@"
