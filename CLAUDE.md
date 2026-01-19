# Divine Workspace

Monorepo for PKN applications. GitHub: https://github.com/CovertCloak06/divine-workspace

---

## 🔴 MANDATORY: MCP AGENT-TOOLS USAGE (READ FIRST)

**This is NON-NEGOTIABLE. Claude MUST use the MCP agent-tools system.**

### Why This Exists
The user has built an MCP server with 37 specialized agents. Using these agents produces HIGHER QUALITY results than manual work. Ignoring them wastes the user's investment and produces inferior output.

### Enforcement Rules

```
┌─────────────────────────────────────────────────────────────────────────┐
│  BEFORE doing ANY task, Claude MUST:                                    │
│                                                                         │
│  1. CHECK if task matches an agent trigger (see table below)            │
│  2. If YES → USE the MCP agent via mcp__agent-tools__<agent_name>       │
│  3. If NO  → Proceed manually                                           │
│                                                                         │
│  NEVER ignore a matching trigger. NEVER do manually what an agent does. │
└─────────────────────────────────────────────────────────────────────────┘
```

### Mandatory Agent Routing

| If task involves... | MUST use MCP tool | NO EXCEPTIONS |
|---------------------|-------------------|---------------|
| UI/menu styling, CSS | `mcp__agent-tools__ui_designer` or `mcp__agent-tools__css_wizard` | ✓ |
| Mobile/PWA/touch | `mcp__agent-tools__mobile_ui` | ✓ |
| Deploying to phone/server | `mcp__agent-tools__devops` | ✓ |
| Fixing bugs/errors | `mcp__agent-tools__debugger` | ✓ |
| Writing documentation | `mcp__agent-tools__docs_writer` | ✓ |
| Code review | `mcp__agent-tools__code_reviewer` | ✓ |
| Writing tests | `mcp__agent-tools__test_writer` | ✓ |
| Security/pentesting | `mcp__agent-tools__security_auditor` | ✓ |
| Performance issues | `mcp__agent-tools__performance_analyzer` | ✓ |
| Refactoring code | `mcp__agent-tools__refactorer` | ✓ |
| Planning features | `mcp__agent-tools__architect` | ✓ |
| Shell/bash scripts | `mcp__agent-tools__debugger` (for fixes) | ✓ |
| Agent/workflow design | `mcp__agent-tools__agent_designer` | ✓ |

### Complete Task Cycle (MANDATORY)

Every task MUST follow this cycle:

```
1. ROUTE    → Use mcp__agent-tools__route OR select specific agent
2. PLAN     → Agent analyzes and plans approach
3. EXECUTE  → Make changes (edits, writes)
4. DEPLOY   → Use mcp__agent-tools__devops if deployment needed
5. VERIFY   → Confirm changes work (test, check file exists, run command)
```

**FAILURES FROM THIS SESSION:**
- Made edits but didn't deploy (pkn-push) ❌
- User said "use ui-designer" but I did it manually ❌
- docs-writer agent ran but I didn't verify file existed ❌

### Project Tools (Use These)

| Tool | When to Use |
|------|-------------|
| `mcp__agent-tools__project_health` | Before starting work |
| `mcp__agent-tools__project_ci` | Before commits |
| `mcp__agent-tools__project_test` | After code changes |
| `mcp__agent-tools__project_lint` | After code changes |
| `mcp__agent-tools__git_diff` | Before commits |

### Quick Commands

| Shortcut | Full MCP Call |
|----------|---------------|
| `@debug <issue>` | `mcp__agent-tools__quick` with command |
| `@build <feature>` | `mcp__agent-tools__quick` with command |
| `@review` | `mcp__agent-tools__quick` with command |

### When User Explicitly Requests an Agent

```
If user says "use X agent" or "use the X agent":
  → IMMEDIATELY call mcp__agent-tools__<x>
  → Do NOT do the task manually
  → Do NOT say "I'll handle this myself"
```

### Accountability Checkpoint

After EVERY task, verify:
- [ ] Did I use the appropriate MCP agent? If not, WHY?
- [ ] Did I complete the full cycle (route → plan → execute → deploy → verify)?
- [ ] Did I verify output exists and works?

---

## 📚 Documentation Hub

**All documentation is centralized. Start here:**

| Quick Link | Description |
|------------|-------------|
| **[docs/INDEX.md](./docs/INDEX.md)** | 📖 Central documentation hub - START HERE |
| [docs/AGENTS.md](./docs/AGENTS.md) | All 9 agents, models, response times |
| [docs/TOOLS.md](./docs/TOOLS.md) | 90+ tools across 13 modules |
| [docs/SHADOW_OSINT.md](./docs/SHADOW_OSINT.md) | 35 OSINT tools (profiler, image, domain) |
| [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) | Deploy PKN, Mobile, Code Academy |
| [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) | System design & structure |
| [docs/TROUBLESHOOTING.md](./docs/TROUBLESHOOTING.md) | Common issues & solutions |
| [docs/CONTRIBUTING.md](./docs/CONTRIBUTING.md) | Development workflow |

**App-Specific:**
| App | CLAUDE.md | Docs |
|-----|-----------|------|
| PKN Desktop | [apps/pkn/CLAUDE.md](./apps/pkn/CLAUDE.md) | [apps/pkn/docs/](./apps/pkn/docs/) |
| PKN Mobile | [apps/pkn-mobile/CLAUDE.md](./apps/pkn-mobile/CLAUDE.md) | [apps/pkn-mobile/docs/](./apps/pkn-mobile/docs/) |
| Code Academy | [apps/code-academy/CLAUDE.md](./apps/code-academy/CLAUDE.md) | - |

---

## 🚨 PKN CORE PRINCIPLES (NON-NEGOTIABLE)

**These apply to ALL PKN apps (desktop and mobile). NEVER violate these.**

### LOCAL-FIRST ARCHITECTURE
- **DEFAULT:** All AI agents run locally via Ollama
- **OPTION:** Cloud (Groq/OpenAI) available when user needs speed
- **NEVER:** Suggest cloud-only or remove local capability
- **NEVER:** Say "local is too slow, just use cloud"

### UNCENSORED MODELS FOR SECURITY WORK
- Security agent uses `dolphin-phi:latest` (uncensored)
- Reasoner agent uses `nous-hermes:latest` (uncensored)
- Required for legitimate pentesting/security education
- NEVER suggest replacing with censored models

### USER'S HARDWARE
- **Phone:** Samsung Galaxy S24 Ultra (Snapdragon 8 Gen 3, 12GB RAM)
- Can run 7B models locally with ~7-13s response times
- Do NOT underestimate phone capabilities

### MODEL CHANGES POLICY
- Only suggest model changes if new option is FASTER **and** HIGHER QUALITY
- Uncensored requirements must STILL be met
- Never change just because it's "easier" or "more popular"
- Performance is king

**Full details:** See `apps/pkn-mobile/CLAUDE.md` for complete requirements

---

## 🔗 SHARED ARCHITECTURE (PKN Desktop & Mobile)

**PKN and PKN Mobile are THE SAME PROJECT with device-specific components.**

### Shared Code (Identical)
| Component | Location | Notes |
|-----------|----------|-------|
| **Backend Tools** | `backend/tools/` | All 18 tool modules (code, file, system, web, memory, osint, rag, planning, delegation, chain, sandbox, evaluation, scratchpad, workflow, git, project, pentest) |
| **Agent Manager** | `backend/agents/manager.py` | Core agent orchestration logic |
| **Memory System** | `backend/` | Session, global, project memory |
| **API Routes** | `backend/routes/` | All API endpoints |

### Device-Specific Components
| Component | Desktop (`apps/pkn/`) | Mobile (`apps/pkn-mobile/`) |
|-----------|----------------------|----------------------------|
| **Models** | 14B models (qwen2.5-coder:14b) | 7B models (qwen2.5-coder:7b) |
| **CSS** | `css/main.css` | `css/main.css` + `css/mobile.css` |
| **UI** | Desktop layout, hover interactions | Touch-optimized, hamburger menu |
| **Entry Point** | `server.py` | `server.py` (same structure) |

### When Making Backend Changes
```
┌────────────────────────────────────────────────────────────────┐
│  ALWAYS APPLY BACKEND CHANGES TO BOTH:                        │
│                                                                │
│  1. apps/pkn/backend/          (Desktop)                      │
│  2. apps/pkn-mobile/backend/   (Mobile)                       │
│                                                                │
│  They share the same architecture. Keep them in sync.         │
└────────────────────────────────────────────────────────────────┘
```

### Sync Commands
```bash
# Copy new tool to mobile
cp apps/pkn/backend/tools/new_tool.py apps/pkn-mobile/backend/tools/

# Copy entire tools directory
rsync -av apps/pkn/backend/tools/ apps/pkn-mobile/backend/tools/

# Deploy mobile to phone
scp -r -P 8022 apps/pkn-mobile/* localhost:~/pkn/
```

### Tool Module Status (18 total)
| Module | Purpose | Desktop | Mobile |
|--------|---------|---------|--------|
| code_tools | Edit, Write, Read | ✅ | ✅ |
| file_tools | Glob, Grep, Find | ✅ | ✅ |
| system_tools | Bash, Process, Todo | ✅ | ✅ |
| web_tools | Search, Fetch | ✅ | ✅ |
| memory_tools | Context, Recall | ✅ | ✅ |
| osint_tools | WHOIS, DNS, IP | ✅ | ✅ |
| rag_tools | Document retrieval | ✅ | ✅ |
| planning_tools | Task breakdown | ✅ | ✅ |
| delegation_tools | Agent-to-agent | ✅ | ✅ |
| chain_tools | Multi-step workflows | ✅ | ✅ |
| sandbox_tools | Safe code execution | ✅ | ✅ |
| evaluation_tools | Performance tracking | ✅ | ✅ |
| scratchpad_tools | Agent handoff storage | ✅ | ✅ |
| workflow_tools | 12 multi-agent workflows | ✅ | ✅ |
| git_tools | Version control ops | ✅ | ✅ |
| project_tools | Project management | ✅ | ✅ |
| pentest_tools | Security/offensive tools | ✅ | ✅ |

---

## Auto Agent Selection

**Claude: Automatically use the appropriate agent. Do not ask - just use the right one.**

### Core Development
| Trigger | Agent | Purpose |
|---------|-------|---------|
| "build", "implement", "create", "add feature" | **architect** | Plan first |
| "fix", "bug", "broken", "error", "not working" | **debugger** | Root cause analysis |
| "review", "check code", "before commit" | **code-reviewer** | Quality check |
| "test", "coverage", "TDD", "write tests" | **test-writer** | Create tests |
| "refactor", "clean up", "split", "too long" | **refactorer** | Improve structure |

### Integration & Tooling
| Trigger | Agent | Purpose |
|---------|-------|---------|
| "integrate", "connect", "API", "webhook", "third-party" | **tool-integrator** | External services |
| "MCP", "model context protocol", "build server" | **mcp-builder** | Custom MCP servers |
| "deploy", "CI/CD", "Docker", "GitHub Actions", "pipeline" | **devops** | Deployment & ops |
| "env", "environment", "config", "secrets", ".env" | **env-manager** | Configuration |

### Code Quality
| Trigger | Agent | Purpose |
|---------|-------|---------|
| "security", "vulnerability", "XSS", "injection", "auth" | **security-auditor** | Find vulnerabilities |
| "slow", "performance", "optimize", "memory", "speed" | **performance-analyzer** | Performance issues |
| "accessibility", "a11y", "screen reader", "ARIA", "WCAG" | **accessibility-checker** | Accessibility |
| "TypeScript", "types", "generics", "interface", "type error" | **type-surgeon** | Complex types |

### Documentation
| Trigger | Agent | Purpose |
|---------|-------|---------|
| "document", "README", "JSDoc", "comment", "docs" | **docs-writer** | Documentation |
| "changelog", "release notes", "what changed" | **changelog-writer** | Version history |
| "explain to", "non-technical", "user guide" | **explainer** | Plain language |

### Design & UX
| Trigger | Agent | Purpose |
|---------|-------|---------|
| "design component", "layout", "UI design" | **ui-designer** | Visual design |
| "user flow", "UX", "friction", "usability" | **ux-reviewer** | User experience |
| "CSS", "animation", "responsive", "styling" | **css-wizard** | Advanced CSS |
| "mobile", "PWA", "send button", "overlay" | **mobile-ui** | PKN Mobile |

### Data & AI
| Trigger | Agent | Purpose |
|---------|-------|---------|
| "database", "schema", "migration", "SQL", "model" | **data-modeler** | Data structures |
| "prompt", "system message", "LLM", "hallucination" | **prompt-engineer** | AI prompts |
| "agent", "multi-agent", "workflow", "orchestration" | **agent-designer** | Agent architecture |

### Project Management
| Trigger | Agent | Purpose |
|---------|-------|---------|
| "how long", "estimate", "timeline", "effort" | **estimator** | Time estimates |
| "prioritize", "what first", "important", "urgent" | **prioritizer** | Task ranking |
| "break down", "decompose", "epic", "smaller tasks" | **decomposer** | Task breakdown |

---

## Multi-Agent Workflows

For complex tasks, chain agents automatically:

**New Feature:**
1. architect → plan
2. (implement)
3. test-writer → tests
4. code-reviewer → verify
5. docs-writer → document

**Bug Fix:**
1. debugger → find cause
2. (fix)
3. test-writer → regression test
4. code-reviewer → verify

**New Integration:**
1. architect → plan
2. tool-integrator → connect
3. security-auditor → check
4. docs-writer → document

**Performance Issue:**
1. performance-analyzer → diagnose
2. (optimize)
3. test-writer → benchmark tests

---

## Quality Gates

Before "done":
- [ ] Code runs without errors
- [ ] `just fmt` applied
- [ ] `just lint` passes
- [ ] Files maintainable (utils ~200, app files 300-500)
- [ ] No debug code left
- [ ] Tests pass

Before commit:
- [ ] `just ci` passes
- [ ] Security check for sensitive changes
- [ ] Docs updated if API changed

---

## Project Structure

```
divine-workspace/
├── apps/
│   ├── pkn-app/        # Main AI assistant
│   ├── code-academy/   # Learning platform
│   └── pkn-mobile/     # Mobile PWA
├── packages/           # Shared libraries
└── justfile            # Task runner
```

## Commands

| Command | Purpose |
|---------|---------|
| `just dev` | Start dev server |
| `just ci` | All checks |
| `just test` | Run tests |
| `just fmt` | Format |
| `just lint` | Lint |
| `just build` | Build |

---

## Current Sprint

### Active Issues
- [ ] PKN Mobile: Verify all agents route to correct models

### Recently Completed
- [x] 2026-01-18: Local-first Ollama setup with uncensored models
- [x] 2026-01-18: Phone cleanup (~2.5GB freed)
- [x] 2026-01-18: PC PWA black screen fix (service worker v2.0)
- [x] 2026-01-18: Mobile background image sizing
- [x] 2026-01-09: Settings X button visibility

---

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-01-18 | Local-first architecture is NON-NEGOTIABLE | Privacy is core to PKN's value proposition |
| 2026-01-18 | Security agent uses uncensored models | Required for legitimate pentesting work |
| 2026-01-18 | Cloud is OPTION, not default | User controls when to trade privacy for speed |

---

## Communication Style

- Be concise
- Show code, don't just describe
- Brief summaries after tasks
- No walls of text
