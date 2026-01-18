# Divine Workspace

Monorepo for PKN applications. GitHub: https://github.com/CovertCloak06/divine-workspace

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
- [ ] Files under 200 lines
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
- [ ] PKN Mobile: Send button positioning
- [ ] PKN Mobile: Overlay z-index
- [ ] PKN Mobile: Text clipping

### Recently Completed
<!-- Add completed items with dates -->

---

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| | | |

---

## Communication Style

- Be concise
- Show code, don't just describe
- Brief summaries after tasks
- No walls of text
