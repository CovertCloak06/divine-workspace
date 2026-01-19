#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Setup Termux Widgets for PKN
#  Run this on phone: bash ~/pkn/scripts/setup-widgets.sh
# ═══════════════════════════════════════════════════════════════════════════════

C_CYAN='\033[1;36m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_DIM='\033[2m'
C_RESET='\033[0m'

echo -e "${C_CYAN}"
echo "┌────────────────────────────────────┐"
echo "│   🔧 PKN Widget Setup              │"
echo "└────────────────────────────────────┘"
echo -e "${C_RESET}"

# Create shortcuts directory
SHORTCUTS_DIR="$HOME/.shortcuts"
mkdir -p "$SHORTCUTS_DIR"
echo -e "${C_GREEN}✓${C_RESET} Created $SHORTCUTS_DIR"

# Copy widget scripts
WIDGETS_DIR="$HOME/pkn/scripts/widgets"
if [ -d "$WIDGETS_DIR" ]; then
    cp "$WIDGETS_DIR"/*.sh "$SHORTCUTS_DIR/"
    chmod +x "$SHORTCUTS_DIR"/*.sh
    echo -e "${C_GREEN}✓${C_RESET} Copied widget scripts"
else
    echo -e "${C_YELLOW}⚠${C_RESET} Widgets directory not found at $WIDGETS_DIR"
fi

# Make cheatsheet executable
chmod +x "$HOME/pkn/scripts/cheatsheet.sh" 2>/dev/null

# List installed widgets
echo ""
echo -e "${C_CYAN}Installed Widgets:${C_RESET}"
ls -1 "$SHORTCUTS_DIR"/*.sh 2>/dev/null | while read f; do
    echo -e "  ${C_DIM}•${C_RESET} $(basename "$f" .sh)"
done

echo ""
echo -e "${C_CYAN}┌────────────────────────────────────┐${C_RESET}"
echo -e "${C_CYAN}│${C_RESET} ${C_GREEN}Setup Complete!${C_RESET}                   ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}├────────────────────────────────────┤${C_RESET}"
echo -e "${C_CYAN}│${C_RESET} Next steps:                        ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}│${C_RESET}                                    ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}│${C_RESET} 1. Install ${C_GREEN}Termux:Widget${C_RESET} from     ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}│${C_RESET}    F-Droid (same repo as Termux)   ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}│${C_RESET}                                    ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}│${C_RESET} 2. Long-press home screen          ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}│${C_RESET}    → Widgets → Termux:Widget       ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}│${C_RESET}                                    ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}│${C_RESET} 3. Select a shortcut to add        ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}└────────────────────────────────────┘${C_RESET}"
echo ""

# Cheatsheet alias
echo -e "${C_DIM}Tip: Add to ~/.bashrc:${C_RESET}"
echo -e "${C_CYAN}alias cheat='bash ~/pkn/scripts/cheatsheet.sh'${C_RESET}"
echo ""
