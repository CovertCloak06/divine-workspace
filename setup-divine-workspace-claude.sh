#!/bin/bash
set -e
echo "🔮 Divine Workspace - Claude Code Setup"
echo "========================================"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p .claude/agents .claude/commands
echo -e "${GREEN}✓${NC} Directories created"

# CLAUDE.md
cat > CLAUDE.md << 'EOF'
# Divine Workspace - Claude Instructions

## Overview
Production-ready monorepo:
- **PKN**: AI assistant (Python/Flask/llama.cpp)
- **Code Academy**: Learning platform (HTML/CSS/Vanilla JS)
- **PKN Mobile**: Mobile PKN (Python/Flask/OpenAI API)

## CRITICAL RULES
1. **Plan before coding** — Use architect agent for complex features
2. **Files MUST stay under 200 lines** — Split into modules
3. **Always run `just ci` before committing**
4. **Check existing patterns first**

## Commands
```bash
just dev              # Start all dev servers
just dev-app pkn      # Start specific app
just test             # Run all tests
just lint             # Lint all code
just ci               # Full CI (run before commits!)
just check-file-sizes # Verify 200-line limits
```

## Architecture
```
divine-workspace/
├── apps/
│   ├── pkn/           # Local LLM assistant
│   ├── code-academy/  # Learning platform
│   └── pkn-mobile/    # Mobile (OpenAI API)
├── packages/          # Shared code
├── scripts/           # Helpers
└── justfile           # Task runner
```

## Before Changes
1. Read the app's CLAUDE.md
2. Check docs/ARCHITECTURE.md
3. Plan BEFORE coding (use architect agent)
4. Write/update tests

## Known Issues
- PKN Mobile: send button positioning, overlay z-index
- PWA may need manual refresh on hot reload
EOF
echo -e "${GREEN}✓${NC} CLAUDE.md"

# Architect agent
cat > .claude/agents/architect.md << 'EOF'
---
name: architect
description: Use BEFORE coding any feature. Creates plans to avoid debugging nightmares.
tools: Read, Grep, Glob, Bash
model: opus
---
You are the Divine Workspace architect. PLAN before coding.

## Process
1. Understand the requirement
2. Explore existing patterns
3. Identify dependencies
4. Design the approach
5. List risks

## Output
1. Summary (one paragraph)
2. Files to modify
3. New files needed
4. Testing strategy
5. Risks & mitigations
6. Step-by-step tasks

NEVER write code — only plan.
EOF
echo -e "${GREEN}✓${NC} architect agent"

# Code reviewer agent
cat > .claude/agents/code-reviewer.md << 'EOF'
---
name: code-reviewer
description: Review code before commits. Catches bugs and style issues.
tools: Read, Grep, Glob, Bash
model: sonnet
---
You are the code reviewer. Check for:
1. Logic errors, edge cases
2. Security issues
3. Performance problems
4. Style consistency
5. Error handling
6. File size (200 line limit)

Run `git diff` and review each file.
Output issues with severity and fixes.
Verdict: Ready to commit? ✅/❌
EOF
echo -e "${GREEN}✓${NC} code-reviewer agent"

# Debugger agent
cat > .claude/agents/debugger.md << 'EOF'
---
name: debugger
description: Find root causes when things break.
tools: Read, Bash, Grep, Glob
model: sonnet
---
You are the debugger. Find root causes, not symptoms.

Process:
1. Reproduce the issue
2. Isolate the component
3. Trace data flow
4. Hypothesize cause
5. Verify and fix

Common issues:
- PKN: LLM not loaded, port conflicts
- Code Academy: JS modules, CORS
- PKN Mobile: API keys, PWA cache, z-index
EOF
echo -e "${GREEN}✓${NC} debugger agent"

# Refactorer agent
cat > .claude/agents/refactorer.md << 'EOF'
---
name: refactorer
description: Improve code without changing behavior. Split large files.
tools: Read, Write, Edit, Bash, Grep, Glob
model: sonnet
---
You are the refactoring specialist.

Rules:
1. Never break functionality
2. One change at a time
3. Test after each change
4. Keep files under 200 lines

When splitting files:
1. Identify logical groupings
2. Extract to modules
3. Create clear interfaces
4. Update imports
EOF
echo -e "${GREEN}✓${NC} refactorer agent"

# Mobile UI agent
cat > .claude/agents/mobile-ui.md << 'EOF'
---
name: mobile-ui
description: Fix PKN Mobile PWA issues - overlays, buttons, text clipping.
tools: Read, Write, Edit, Bash, Grep, Glob
model: sonnet
---
You are the mobile UI specialist.

Known issues:
- Send button visibility/positioning
- Overlay z-index conflicts
- Text clipping in chat
- PWA viewport issues

Debugging:
```bash
grep -r "z-index" apps/pkn-mobile/
find apps/pkn-mobile -name "*.css"
```
EOF
echo -e "${GREEN}✓${NC} mobile-ui agent"

# Test writer agent
cat > .claude/agents/test-writer.md << 'EOF'
---
name: test-writer
description: Write comprehensive tests for new or existing code.
tools: Read, Write, Edit, Bash, Grep, Glob
model: sonnet
---
You are the test specialist.

Coverage priorities:
1. Happy path
2. Edge cases
3. Error conditions
4. Integration points

Run with: just test-app [app-name]
EOF
echo -e "${GREEN}✓${NC} test-writer agent"

# Commands
cat > .claude/commands/plan.md << 'EOF'
Plan implementation for: $ARGUMENTS
Use the architect agent. DO NOT write code until plan is approved.
EOF

cat > .claude/commands/review.md << 'EOF'
Review changes before commit.
Run git diff, check for issues, run just ci.
Verdict: Ready? ✅/❌
EOF

cat > .claude/commands/fix.md << 'EOF'
Fix: $ARGUMENTS
Understand, plan, implement, test, commit.
EOF

cat > .claude/commands/refactor.md << 'EOF'
Refactor: $ARGUMENTS
Use refactorer agent. Keep files under 200 lines.
EOF
echo -e "${GREEN}✓${NC} Custom commands"

# Settings
cat > .claude/settings.json << 'EOF'
{
  "permissions": {
    "allow": [
      "Bash(just:*)", "Bash(git diff:*)", "Bash(git log:*)", "Bash(git status)",
      "Bash(npm run:*)", "Bash(pnpm:*)", "Bash(python3:*)", "Bash(gh:*)",
      "Bash(cat:*)", "Bash(ls:*)", "Bash(find:*)", "Bash(grep:*)", "Edit"
    ],
    "deny": [
      "Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)", "Bash(rm -rf:*)", "Bash(sudo:*)"
    ]
  }
}
EOF
echo -e "${GREEN}✓${NC} Settings"

echo ""
echo "========================================"
echo -e "${GREEN}✅ Setup Complete!${NC}"
echo "========================================"
echo ""
echo "Created: CLAUDE.md, 6 agents, 4 commands, settings"
echo ""
echo "Start with: claude"
echo "Then try:   /agents"
echo ""
echo "To avoid debug hell, always start complex features with:"
echo "  \"Use the architect agent to plan [your feature]\""
