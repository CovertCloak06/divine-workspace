#!/bin/bash
set -e
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'
echo -e "${BLUE}[*]${NC} Setting up Codex CLI..."

# Install if needed
command -v codex &>/dev/null || npm install -g @openai/codex

# Global config
mkdir -p ~/.codex
cat > ~/.codex/config.toml << 'TOML'
model = "gpt-5-codex"
approval_policy = "unless-allow-listed"
sandbox_mode = "workspace-write"
reasoning_effort = "medium"

[features]
web_search_request = true
shell_snapshot = true

[profiles.strict]
approval_policy = "always"
sandbox_mode = "always"

[profiles.fast]
approval_policy = "on-request"

[profiles.plan]
reasoning_effort = "high"
approval_policy = "always"
TOML

# Project AGENTS.md
cat > AGENTS.md << 'MD'
# Divine Workspace

Monorepo: PKN App, Code Academy, PKN Mobile

## Commands
- `just ci` - Run all checks
- `just dev` - Start dev server
- `just fmt` - Format code

## Rules
- Keep files under 200 lines
- Run `just fmt` before commits
- Plan before coding complex features

## Known Issues (PKN Mobile)
- Send button positioning
- Overlay z-index conflicts
- Text clipping on small screens
MD

# PKN Mobile specific
[[ -d "apps/pkn-mobile" ]] && cat > apps/pkn-mobile/AGENTS.md << 'MD'
# PKN Mobile

PWA mobile interface. Current focus: fix send button and overlay issues.

## Testing
pnpm dev  # Then test on mobile emulator
MD

# Update gitignore
grep -q "AGENTS.override.md" .gitignore 2>/dev/null || echo -e "\n# Codex\nAGENTS.override.md" >> .gitignore

echo -e "${GREEN}[✓]${NC} Done! Run: codex"
