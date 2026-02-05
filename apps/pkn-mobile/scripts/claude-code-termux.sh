#!/data/data/com.termux/files/usr/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║  Claude Code - Termux Install & Health Check            ║
# ║  For Samsung Galaxy S24 Ultra / Android via Termux      ║
# ╠══════════════════════════════════════════════════════════╣
# ║  Usage:                                                  ║
# ║    bash claude-code-termux.sh          (interactive)     ║
# ║    bash claude-code-termux.sh health   (health only)     ║
# ║    bash claude-code-termux.sh install  (install only)    ║
# ║    bash claude-code-termux.sh fix      (apply patches)   ║
# ╚══════════════════════════════════════════════════════════╝

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Detect environment
IS_TERMUX=false
if [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=true
fi

TMPDIR_ACTUAL="${TMPDIR:-/tmp}"
CLAUDE_TMP="$TMPDIR_ACTUAL/claude"

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }

# ─────────────────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────────────────
health_check() {
    echo ""
    echo -e "${BOLD}${CYAN}═══ Claude Code Termux Health Check ═══${NC}"
    echo ""
    ISSUES=0

    # 1. Environment
    echo -e "${BOLD}Environment:${NC}"
    if $IS_TERMUX; then
        pass "Running in Termux"
    else
        warn "Not running in Termux (detected: $(uname -s))"
    fi

    echo -e "  OS: $(uname -m) | $(uname -r)"
    echo -e "  HOME: $HOME"
    echo -e "  TMPDIR: ${TMPDIR:-'(not set)'}"
    echo ""

    # 2. Node.js
    echo -e "${BOLD}Node.js:${NC}"
    if command -v node &>/dev/null; then
        NODE_VER=$(node --version 2>/dev/null)
        NODE_MAJOR=$(echo "$NODE_VER" | sed 's/v//' | cut -d. -f1)
        if [ "$NODE_MAJOR" -ge 18 ]; then
            pass "Node.js $NODE_VER (>= 18 required)"
        else
            fail "Node.js $NODE_VER - version 18+ required"
            ISSUES=$((ISSUES + 1))
        fi
    else
        fail "Node.js not installed"
        ISSUES=$((ISSUES + 1))
    fi

    if command -v npm &>/dev/null; then
        pass "npm $(npm --version 2>/dev/null)"
    else
        fail "npm not installed"
        ISSUES=$((ISSUES + 1))
    fi
    echo ""

    # 3. Claude Code
    echo -e "${BOLD}Claude Code:${NC}"
    if command -v claude &>/dev/null; then
        CLAUDE_VER=$(claude --version 2>/dev/null || echo "unknown")
        pass "Claude Code installed: $CLAUDE_VER"
        CLAUDE_PATH=$(which claude)
        info "Location: $CLAUDE_PATH"

        # Check global npm root
        NPM_ROOT=$(npm root -g 2>/dev/null || echo "unknown")
        info "npm global root: $NPM_ROOT"
    else
        fail "Claude Code not installed"
        ISSUES=$((ISSUES + 1))
    fi
    echo ""

    # 4. /tmp path issue (THE major Termux bug)
    echo -e "${BOLD}Temp Directory (known Termux bug #15637):${NC}"
    if $IS_TERMUX; then
        # Check if /tmp is accessible
        if mkdir -p /tmp/claude_test 2>/dev/null; then
            rm -rf /tmp/claude_test
            pass "/tmp is writable (unusual for Termux)"
        else
            fail "/tmp is NOT writable - this breaks Claude Code"
            ISSUES=$((ISSUES + 1))
            info "Claude Code hardcodes /tmp/claude paths"
            info "Termux TMPDIR: ${TMPDIR:-'NOT SET'}"
        fi

        # Check if TMPDIR is set
        if [ -n "${TMPDIR:-}" ]; then
            if mkdir -p "$TMPDIR/claude_test" 2>/dev/null; then
                rm -rf "$TMPDIR/claude_test"
                pass "TMPDIR ($TMPDIR) is writable"
            else
                fail "TMPDIR ($TMPDIR) is NOT writable"
                ISSUES=$((ISSUES + 1))
            fi
        else
            warn "TMPDIR not set - should be set for Termux"
            ISSUES=$((ISSUES + 1))
        fi

        # Check if cli.js has been patched
        if command -v claude &>/dev/null; then
            CLI_JS=$(dirname "$(dirname "$(which claude)")")/lib/node_modules/@anthropic-ai/claude-code/cli.js 2>/dev/null || true
            # Try alternative path
            if [ ! -f "$CLI_JS" ]; then
                CLI_JS=$(npm root -g 2>/dev/null)/@anthropic-ai/claude-code/cli.js 2>/dev/null || true
            fi
            if [ -f "$CLI_JS" ]; then
                HARDCODED=$(grep -c '"/tmp/claude"' "$CLI_JS" 2>/dev/null || echo "0")
                if [ "$HARDCODED" -gt 0 ]; then
                    fail "cli.js has $HARDCODED hardcoded /tmp/claude references (unpatched)"
                    ISSUES=$((ISSUES + 1))
                else
                    pass "cli.js appears patched (no /tmp/claude hardcodes found)"
                fi
                info "cli.js location: $CLI_JS"
            else
                warn "Could not locate cli.js to check for /tmp patches"
            fi
        fi
    else
        if [ -w "/tmp" ]; then
            pass "/tmp is writable (non-Termux environment)"
        else
            fail "/tmp is NOT writable"
            ISSUES=$((ISSUES + 1))
        fi
    fi
    echo ""

    # 5. API Key
    echo -e "${BOLD}Authentication:${NC}"
    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        KEY_PREVIEW="${ANTHROPIC_API_KEY:0:10}..."
        pass "ANTHROPIC_API_KEY is set ($KEY_PREVIEW)"
    else
        warn "ANTHROPIC_API_KEY not set (Claude Code may use OAuth instead)"
        info "Run 'claude' to authenticate interactively"
    fi

    # Check for Claude config directory
    if [ -d "$HOME/.claude" ]; then
        pass "~/.claude config directory exists"
        if [ -f "$HOME/.claude/credentials.json" ] || [ -f "$HOME/.claude/.credentials.json" ]; then
            pass "Credentials file found"
        else
            info "No credentials file - may need to authenticate"
        fi
    else
        info "~/.claude does not exist yet (will be created on first run)"
    fi
    echo ""

    # 6. Disk space
    echo -e "${BOLD}Storage:${NC}"
    if $IS_TERMUX; then
        AVAIL=$(df -h "$HOME" 2>/dev/null | awk 'NR==2{print $4}' || echo "unknown")
        info "Available: $AVAIL"
    else
        AVAIL=$(df -h "$HOME" 2>/dev/null | awk 'NR==2{print $4}' || echo "unknown")
        info "Available: $AVAIL"
    fi
    echo ""

    # 7. Network
    echo -e "${BOLD}Network:${NC}"
    if curl -s --max-time 5 https://api.anthropic.com > /dev/null 2>&1; then
        pass "Can reach api.anthropic.com"
    else
        fail "Cannot reach api.anthropic.com"
        ISSUES=$((ISSUES + 1))
    fi

    if curl -s --max-time 5 https://registry.npmjs.org > /dev/null 2>&1; then
        pass "Can reach npm registry"
    else
        fail "Cannot reach npm registry"
        ISSUES=$((ISSUES + 1))
    fi
    echo ""

    # Summary
    echo -e "${BOLD}═══ Summary ═══${NC}"
    if [ "$ISSUES" -eq 0 ]; then
        echo -e "${GREEN}All checks passed. Claude Code should work.${NC}"
    else
        echo -e "${RED}Found $ISSUES issue(s) that need attention.${NC}"
        echo ""
        if $IS_TERMUX; then
            echo -e "${YELLOW}Recommended: Run 'bash claude-code-termux.sh fix' to apply patches${NC}"
        fi
    fi
    echo ""

    return $ISSUES
}

# ─────────────────────────────────────────────────────────
# Install
# ─────────────────────────────────────────────────────────
install_claude_code() {
    echo ""
    echo -e "${BOLD}${CYAN}═══ Installing Claude Code on Termux ═══${NC}"
    echo ""

    # Step 1: Update Termux packages
    echo -e "${BOLD}Step 1: Updating packages...${NC}"
    pkg update -y && pkg upgrade -y
    echo ""

    # Step 2: Install Node.js if missing
    echo -e "${BOLD}Step 2: Installing Node.js...${NC}"
    if command -v node &>/dev/null; then
        NODE_VER=$(node --version)
        info "Node.js already installed: $NODE_VER"
    else
        pkg install nodejs -y
        info "Node.js installed: $(node --version)"
    fi
    echo ""

    # Step 3: Install git (needed for some npm packages)
    echo -e "${BOLD}Step 3: Installing git...${NC}"
    if command -v git &>/dev/null; then
        info "git already installed"
    else
        pkg install git -y
    fi
    echo ""

    # Step 4: Set up TMPDIR properly
    echo -e "${BOLD}Step 4: Setting up TMPDIR...${NC}"
    if [ -z "${TMPDIR:-}" ]; then
        export TMPDIR="$HOME/.cache/tmp"
    fi
    mkdir -p "$TMPDIR"
    mkdir -p "$TMPDIR/claude"
    info "TMPDIR set to: $TMPDIR"

    # Persist TMPDIR in shell profile
    SHELL_RC="$HOME/.bashrc"
    if [ -f "$HOME/.zshrc" ] && [ "$SHELL" = *zsh* ]; then
        SHELL_RC="$HOME/.zshrc"
    fi

    if ! grep -q 'TMPDIR.*cache/tmp' "$SHELL_RC" 2>/dev/null; then
        echo '' >> "$SHELL_RC"
        echo '# Claude Code TMPDIR fix for Termux' >> "$SHELL_RC"
        echo 'export TMPDIR="$HOME/.cache/tmp"' >> "$SHELL_RC"
        echo 'mkdir -p "$TMPDIR/claude"' >> "$SHELL_RC"
        info "Added TMPDIR to $SHELL_RC"
    else
        info "TMPDIR already in $SHELL_RC"
    fi
    echo ""

    # Step 5: Install Claude Code
    echo -e "${BOLD}Step 5: Installing Claude Code...${NC}"
    npm install -g @anthropic-ai/claude-code
    echo ""

    # Step 6: Verify
    echo -e "${BOLD}Step 6: Verifying installation...${NC}"
    if command -v claude &>/dev/null; then
        pass "Claude Code installed: $(claude --version 2>/dev/null)"
    else
        fail "Installation may have failed. Check errors above."
        return 1
    fi
    echo ""

    # Step 7: Apply Termux patches
    echo -e "${BOLD}Step 7: Applying Termux patches...${NC}"
    apply_termux_fix
    echo ""

    echo -e "${GREEN}${BOLD}Installation complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run: source $SHELL_RC"
    echo "  2. Run: claude"
    echo "  3. Follow the authentication prompts"
    echo ""
}

# ─────────────────────────────────────────────────────────
# Apply /tmp fix
# ─────────────────────────────────────────────────────────
apply_termux_fix() {
    echo ""
    echo -e "${BOLD}${CYAN}═══ Applying Termux /tmp Fix ═══${NC}"
    echo ""

    if ! $IS_TERMUX; then
        warn "Not running on Termux. Fix may not be needed."
        echo -n "Continue anyway? (y/N): "
        read -r REPLY
        if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
            return 0
        fi
    fi

    # Ensure TMPDIR is set
    if [ -z "${TMPDIR:-}" ]; then
        export TMPDIR="$HOME/.cache/tmp"
    fi
    mkdir -p "$TMPDIR/claude"

    # Find cli.js
    CLI_JS=""
    if command -v claude &>/dev/null; then
        # Method 1: Follow the binary
        CLAUDE_BIN=$(which claude)
        REAL_BIN=$(readlink -f "$CLAUDE_BIN" 2>/dev/null || echo "$CLAUDE_BIN")
        CANDIDATE=$(dirname "$(dirname "$REAL_BIN")")/lib/node_modules/@anthropic-ai/claude-code/cli.js
        if [ -f "$CANDIDATE" ]; then
            CLI_JS="$CANDIDATE"
        fi

        # Method 2: npm root
        if [ -z "$CLI_JS" ]; then
            CANDIDATE="$(npm root -g 2>/dev/null)/@anthropic-ai/claude-code/cli.js"
            if [ -f "$CANDIDATE" ]; then
                CLI_JS="$CANDIDATE"
            fi
        fi

        # Method 3: Common Termux path
        if [ -z "$CLI_JS" ]; then
            CANDIDATE="$PREFIX/lib/node_modules/@anthropic-ai/claude-code/cli.js"
            if [ -f "$CANDIDATE" ]; then
                CLI_JS="$CANDIDATE"
            fi
        fi
    fi

    if [ -z "$CLI_JS" ] || [ ! -f "$CLI_JS" ]; then
        fail "Could not find cli.js. Is Claude Code installed?"
        info "Tried:"
        info "  - Following 'which claude' symlink"
        info "  - npm root -g"
        info "  - \$PREFIX/lib/node_modules/"
        return 1
    fi

    info "Found cli.js at: $CLI_JS"

    # Count hardcoded paths
    HARDCODED=$(grep -c '"/tmp/claude"' "$CLI_JS" 2>/dev/null || echo "0")
    HARDCODED_SCREENSHOT=$(grep -c '/tmp/claude_cli_latest_screenshot' "$CLI_JS" 2>/dev/null || echo "0")

    if [ "$HARDCODED" -eq 0 ] && [ "$HARDCODED_SCREENSHOT" -eq 0 ]; then
        pass "cli.js already patched or no hardcoded paths found"
        return 0
    fi

    info "Found $HARDCODED /tmp/claude references and $HARDCODED_SCREENSHOT screenshot path references"

    # Backup
    BACKUP="${CLI_JS}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$CLI_JS" "$BACKUP"
    info "Backup saved: $BACKUP"

    # Apply the patch - replace /tmp/claude with TMPDIR-based path
    ESCAPED_TMPDIR=$(echo "$TMPDIR" | sed 's/[&/\]/\\&/g')
    sed -i "s|\"/tmp/claude\"|\"${ESCAPED_TMPDIR}/claude\"|g" "$CLI_JS"
    sed -i "s|/tmp/claude_cli_latest_screenshot|${ESCAPED_TMPDIR}/claude_cli_latest_screenshot|g" "$CLI_JS"

    # Verify patch
    REMAINING=$(grep -c '"/tmp/claude"' "$CLI_JS" 2>/dev/null || echo "0")
    REMAINING_SS=$(grep -c '/tmp/claude_cli_latest_screenshot' "$CLI_JS" 2>/dev/null || echo "0")

    if [ "$REMAINING" -eq 0 ] && [ "$REMAINING_SS" -eq 0 ]; then
        pass "Patch applied successfully"
        info "Replaced /tmp/claude -> $TMPDIR/claude"
    else
        warn "Some paths may remain unpatched ($REMAINING left)"
        info "You may need to manually edit: $CLI_JS"
    fi
    echo ""

    # Also ensure the .bashrc TMPDIR export
    SHELL_RC="$HOME/.bashrc"
    if ! grep -q 'TMPDIR.*cache/tmp' "$SHELL_RC" 2>/dev/null; then
        echo '' >> "$SHELL_RC"
        echo '# Claude Code TMPDIR fix for Termux' >> "$SHELL_RC"
        echo 'export TMPDIR="$HOME/.cache/tmp"' >> "$SHELL_RC"
        echo 'mkdir -p "$TMPDIR/claude"' >> "$SHELL_RC"
        info "Added TMPDIR to $SHELL_RC"
    fi

    echo -e "${YELLOW}${BOLD}WARNING:${NC} This patch will be overwritten if you update Claude Code."
    echo "After any 'npm update', re-run: bash claude-code-termux.sh fix"
    echo ""
}

# ─────────────────────────────────────────────────────────
# Uninstall (clean)
# ─────────────────────────────────────────────────────────
uninstall_claude_code() {
    echo ""
    echo -e "${BOLD}${CYAN}═══ Uninstalling Claude Code ═══${NC}"
    echo ""
    echo -n "Are you sure? (y/N): "
    read -r REPLY
    if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
        info "Cancelled"
        return 0
    fi

    npm uninstall -g @anthropic-ai/claude-code 2>/dev/null || true
    rm -rf "$HOME/.claude" 2>/dev/null || true
    rm -rf "${TMPDIR:-/tmp}/claude" 2>/dev/null || true

    pass "Claude Code uninstalled"
    info "Re-run 'bash claude-code-termux.sh install' to reinstall"
    echo ""
}

# ─────────────────────────────────────────────────────────
# Interactive menu
# ─────────────────────────────────────────────────────────
show_menu() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║   Claude Code - Termux Manager           ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo "  1. Health Check    - Diagnose current installation"
    echo "  2. Install         - Fresh install of Claude Code"
    echo "  3. Apply Fix       - Patch /tmp paths for Termux"
    echo "  4. Reinstall       - Uninstall + fresh install"
    echo "  5. Uninstall       - Remove Claude Code"
    echo "  6. Launch Claude   - Start Claude Code"
    echo "  0. Exit"
    echo ""
    echo -n "  Select [0-6]: "
    read -r choice

    case "$choice" in
        1) health_check ;;
        2) install_claude_code ;;
        3) apply_termux_fix ;;
        4) uninstall_claude_code && install_claude_code ;;
        5) uninstall_claude_code ;;
        6)
            echo ""
            info "Launching Claude Code..."
            echo ""
            claude
            ;;
        0) exit 0 ;;
        *) warn "Invalid choice" ;;
    esac

    # Loop back to menu
    show_menu
}

# ─────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────
case "${1:-menu}" in
    health)  health_check ;;
    install) install_claude_code ;;
    fix)     apply_termux_fix ;;
    menu)    show_menu ;;
    *)
        echo "Usage: bash claude-code-termux.sh [health|install|fix|menu]"
        exit 1
        ;;
esac
