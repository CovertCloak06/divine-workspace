#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  PKN Command Cheatsheet - Gh0st Edition
#  Select a command → copies to clipboard → paste with Ctrl+V or long-press
# ═══════════════════════════════════════════════════════════════════════════════

# Colors
C_CYAN='\033[1;36m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_DIM='\033[2m'
C_RESET='\033[0m'

# Cheatsheet file location (customizable)
CHEATSHEET_FILE="${CHEATSHEET_FILE:-$HOME/pkn/scripts/commands.txt}"

# Default commands if file doesn't exist
create_default_cheatsheet() {
    cat > "$CHEATSHEET_FILE" << 'EOF'
# ═══════════════════════════════════════════════════════════════════════════════
# PKN COMMANDS CHEATSHEET
# Lines starting with # are headers/comments
# Add your own commands below each section
# ═══════════════════════════════════════════════════════════════════════════════

# ─── SERVER ───────────────────────────────────────────────────────────────────
pkn
python -m backend.server
pkill -f 'python.*backend'
curl -s http://127.0.0.1:8010/health | python -m json.tool

# ─── OLLAMA ───────────────────────────────────────────────────────────────────
ollama serve
ollama list
ollama run qwen2.5-coder:7b
ollama run dolphin-phi:latest
curl -s http://127.0.0.1:11434/api/tags | python -m json.tool

# ─── GIT ──────────────────────────────────────────────────────────────────────
git status
git diff
git add -A && git commit -m ""
git pull
git push
git log --oneline -10

# ─── NAVIGATION ───────────────────────────────────────────────────────────────
cd ~/pkn
cd ~/pkn/backend
cd ~/pkn/scripts
ls -la

# ─── TESTING ──────────────────────────────────────────────────────────────────
curl -X POST http://127.0.0.1:8010/api/multi-agent/chat -H "Content-Type: application/json" -d '{"message": "hello", "mode": "auto"}'
curl -s http://127.0.0.1:8010/api/multi-agent/agents | python -m json.tool
curl -s http://127.0.0.1:8010/api/multi-agent/backend | python -m json.tool

# ─── SYSTEM ───────────────────────────────────────────────────────────────────
top
df -h
free -h
termux-battery-status
termux-wifi-connectioninfo

# ─── CUSTOM ───────────────────────────────────────────────────────────────────
# Add your own commands here

EOF
    echo -e "${C_GREEN}Created default cheatsheet at: $CHEATSHEET_FILE${C_RESET}"
}

# Check if cheatsheet exists
if [ ! -f "$CHEATSHEET_FILE" ]; then
    create_default_cheatsheet
fi

# Show header
clear
echo -e "${C_CYAN}"
echo "    ┌────────────────────────────────┐"
echo "    │   📋 COMMAND CHEATSHEET        │"
echo "    │   Select → Copies to clipboard │"
echo "    └────────────────────────────────┘"
echo -e "${C_RESET}"

# Use fzf to select command (excluding comments)
selected=$(grep -v '^#' "$CHEATSHEET_FILE" | grep -v '^$' | fzf \
    --height=70% \
    --border=rounded \
    --reverse \
    --prompt="▶ " \
    --header="↑↓ Navigate │ Enter Select │ Esc Cancel" \
    --color="fg:#88c0d0,bg:#1a1b26,hl:#50fa7b,fg+:#ffffff,bg+:#2e3440,hl+:#50fa7b,info:#5ccfe6,prompt:#50fa7b,pointer:#ff79c6")

if [ -n "$selected" ]; then
    # Copy to clipboard using termux-clipboard-set
    echo -n "$selected" | termux-clipboard-set 2>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "\n${C_GREEN}✓ Copied to clipboard:${C_RESET}"
        echo -e "${C_CYAN}$selected${C_RESET}"
        echo -e "\n${C_DIM}Paste with: Ctrl+V or long-press → Paste${C_RESET}"
    else
        # Fallback: just print it
        echo -e "\n${C_YELLOW}⚠ termux-clipboard-set not available${C_RESET}"
        echo -e "${C_DIM}Install: pkg install termux-api${C_RESET}"
        echo -e "\n${C_GREEN}Command:${C_RESET}"
        echo -e "${C_CYAN}$selected${C_RESET}"
    fi
else
    echo -e "\n${C_DIM}Cancelled${C_RESET}"
fi
