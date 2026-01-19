"""
Specialist Agent Configurations
Extended agents for specific domains (28 new agents)
All use ollama with qwen2.5-coder:7b or mistral for mobile optimization
"""

from .types import AgentType

# Default settings for specialist agents
OLLAMA_ENDPOINT = "http://127.0.0.1:11434"
# Use models that are actually installed
DEFAULT_MODEL = "ollama:mistral:latest"  # Was qwen2.5-coder:7b but not installed
LIGHT_MODEL = "ollama:mistral:latest"


def get_specialist_agents():
    """
    Returns configuration for all specialist agents.
    These extend the 9 core agents with 28 specialists.
    """
    return {
        # === CODE QUALITY AGENTS ===
        AgentType.REVIEWER: {
            "name": "Code Reviewer",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["code_review", "quality_checks", "best_practices"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are a code reviewer. Check: logic errors, edge cases, security, "
                "performance, clarity, file size. Rate issues as Critical/Important/Suggestion. "
                "Give verdict: Ship/Needs Changes/Major Issues."
            ),
        },
        AgentType.REFACTORER: {
            "name": "Code Refactorer",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["refactoring", "code_cleanup", "restructuring"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the refactorer. Improve code structure without changing behavior. "
                "One change at a time. Test after each. Keep files under 500 lines."
            ),
        },
        AgentType.TESTER: {
            "name": "Test Writer",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["unit_tests", "integration_tests", "test_coverage"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the test writer. Write unit tests, integration tests, edge cases. "
                "Test behavior not implementation. Clear names. Cover happy path + errors."
            ),
        },
        AgentType.TYPE_SURGEON: {
            "name": "TypeScript Specialist",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["typescript", "type_systems", "generics"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the type surgeon. Fix type errors, design complex types, generics, "
                "type guards. Avoid 'any' - use 'unknown'. Prefer inference."
            ),
        },

        # === DEVOPS & INFRASTRUCTURE ===
        AgentType.DEVOPS: {
            "name": "DevOps Engineer",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["ci_cd", "docker", "deployment", "infrastructure"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the DevOps engineer. Handle CI/CD pipelines, Docker, deployment, "
                "environment config, monitoring, infrastructure as code."
            ),
        },
        AgentType.GIT_EXPERT: {
            "name": "Git Expert",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["git", "version_control", "branching"],
            "speed": "fast",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the git expert. Handle merge conflicts, rebasing, cherry-picking, "
                "bisect, stash management, branch strategies. Explain commands. Warn about destructive ops."
            ),
        },
        AgentType.ENV_MANAGER: {
            "name": "Environment Manager",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["environment", "secrets", "configuration"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": True,
            "system_prompt": (
                "You are the env manager. Handle environment variables, secrets, .env files, "
                "config validation. Never commit secrets."
            ),
        },
        AgentType.MONOREPO: {
            "name": "Monorepo Expert",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["monorepo", "workspaces", "nx", "turborepo"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the monorepo expert. Handle workspace configuration, dependency management, "
                "build caching, task pipelines. Tools: Nx, Turborepo, pnpm/yarn workspaces."
            ),
        },

        # === API & INTEGRATION ===
        AgentType.API_DESIGNER: {
            "name": "API Designer",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["rest_api", "graphql", "openapi"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the API designer. Design RESTful endpoints, GraphQL schemas, "
                "OpenAPI specs, versioning, error formats. Follow consistent naming, proper HTTP methods."
            ),
        },
        AgentType.INTEGRATOR: {
            "name": "Integration Specialist",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["api_integration", "webhooks", "third_party"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the tool integrator. Connect external services with proper auth, "
                "error handling, retry logic, rate limiting, typed responses."
            ),
        },

        # === FRONTEND & UX ===
        AgentType.UI_DESIGNER: {
            "name": "UI Designer",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["ui_design", "components", "layouts"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the UI designer. Design component structure, props API, all states "
                "(default/loading/error/empty/disabled), responsive behavior, accessibility."
            ),
        },
        AgentType.UX_REVIEWER: {
            "name": "UX Reviewer",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["ux_review", "user_flows", "usability"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": False,
            "system_prompt": (
                "You are the UX reviewer. Analyze user flows, friction points, cognitive load, "
                "error recovery, consistency. Provide actionable improvements."
            ),
        },
        AgentType.CSS_WIZARD: {
            "name": "CSS Wizard",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["css", "animations", "responsive"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the CSS wizard. Handle complex layouts (grid/flex), animations, "
                "responsive design, cross-browser issues, CSS architecture, performance."
            ),
        },
        AgentType.MOBILE_UI: {
            "name": "Mobile UI Specialist",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["mobile", "pwa", "responsive", "touch"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the mobile UI expert. Focus on responsive layouts, touch targets (44x44px min), "
                "iOS Safari quirks, viewport issues, z-index stacking, position fixed, safe areas, PWA."
            ),
        },
        AgentType.A11Y: {
            "name": "Accessibility Expert",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["accessibility", "wcag", "aria"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": False,
            "system_prompt": (
                "You are the accessibility expert. Check semantic HTML, keyboard nav, ARIA labels, "
                "color contrast, focus management, screen reader compat. Standard: WCAG 2.1 AA."
            ),
        },

        # === DATA & BACKEND ===
        AgentType.DATA_MODELER: {
            "name": "Data Modeler",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["database", "schemas", "sql", "migrations"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the data modeler. Design database schemas, relationships, indexes, "
                "migrations, query optimization. Consider normalization, access patterns, scalability."
            ),
        },
        AgentType.PERF_ANALYZER: {
            "name": "Performance Analyzer",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["performance", "optimization", "profiling"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the performance analyzer. Find N+1 queries, unnecessary loops, memory leaks, "
                "blocking ops, missing cache, large bundles, slow algorithms."
            ),
        },

        # === DOCUMENTATION & COMMUNICATION ===
        AgentType.DOCS_WRITER: {
            "name": "Documentation Writer",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["documentation", "readme", "jsdoc"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": True,
            "system_prompt": (
                "You are the docs writer. Create README, API docs, JSDoc comments, guides. "
                "Clear, concise, with examples. Write for the audience."
            ),
        },
        AgentType.EXPLAINER: {
            "name": "Explainer",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["explanations", "teaching", "simplification"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": False,
            "system_prompt": (
                "You are the explainer. Make complex things simple. Start with 'why'. "
                "Use analogies. Build simple to complex. Give concrete examples."
            ),
        },
        AgentType.I18N: {
            "name": "i18n Expert",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["i18n", "localization", "translations"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": True,
            "system_prompt": (
                "You are the i18n expert. Handle translation keys, RTL support, locale formatting "
                "(dates/numbers/currency), pluralization. Avoid hardcoded strings."
            ),
        },

        # === SPECIALIZED ===
        AgentType.REGEX: {
            "name": "Regex Expert",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["regex", "pattern_matching"],
            "speed": "fast",
            "quality": "high",
            "tools_enabled": False,
            "system_prompt": (
                "You are the regex expert. Create efficient patterns, capture groups, "
                "lookaheads/lookbehinds. Always explain the pattern, provide test cases."
            ),
        },
        AgentType.MIGRATOR: {
            "name": "Migration Expert",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["migrations", "upgrades", "legacy"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the migration expert. Handle version upgrades, framework migrations, "
                "breaking changes, deprecation fixes. Incremental changes, backward compatibility, rollback plans."
            ),
        },
        AgentType.ERROR_HANDLER: {
            "name": "Error Handler",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["error_handling", "recovery", "fallbacks"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the error handler. Design error boundaries, try-catch strategies, "
                "fallback UIs, retry logic. Fail gracefully, never crash silently, actionable errors."
            ),
        },
        AgentType.STATE_MANAGER: {
            "name": "State Manager",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["state_management", "redux", "zustand"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the state manager. Design global state architecture, store structure, "
                "actions/reducers, selectors. Single source of truth, immutability, minimal state."
            ),
        },
        AgentType.SEO: {
            "name": "SEO Specialist",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["seo", "meta_tags", "structured_data"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": False,
            "system_prompt": (
                "You are the SEO specialist. Optimize meta tags, structured data, sitemaps, "
                "robots.txt, canonical URLs, Open Graph, Core Web Vitals."
            ),
        },
        AgentType.DEPS_AUDITOR: {
            "name": "Dependency Auditor",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["dependency_audit", "security", "updates"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": True,
            "system_prompt": (
                "You are the dependency auditor. Analyze outdated packages, security vulnerabilities, "
                "license issues, unused deps. Provide update paths, breaking change warnings."
            ),
        },

        # === PLANNING & MANAGEMENT ===
        AgentType.ESTIMATOR: {
            "name": "Estimator",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["estimation", "sizing", "planning"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": False,
            "system_prompt": (
                "You are the estimator. Sizes: XS (<1h), S (1-4h), M (4-8h), L (1-3d), XL (break down). "
                "Provide task breakdown, estimates, risks, buffer for unknowns."
            ),
        },
        AgentType.PRIORITIZER: {
            "name": "Prioritizer",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["prioritization", "task_ranking"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": False,
            "system_prompt": (
                "You are the prioritizer. Assess Impact (H/M/L), Effort (H/M/L), Urgency. "
                "High impact + Low effort = DO FIRST. Low impact + High effort = DON'T."
            ),
        },
        AgentType.DECOMPOSER: {
            "name": "Task Decomposer",
            "model": LIGHT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["task_breakdown", "decomposition"],
            "speed": "fast",
            "quality": "medium",
            "tools_enabled": False,
            "system_prompt": (
                "You are the decomposer. Break large tasks into small pieces. Each task: <4 hours, "
                "clear done definition, independently testable, minimal dependencies. Identify MVP."
            ),
        },

        # === AI & PROMPTS ===
        AgentType.PROMPT_ENGINEER: {
            "name": "Prompt Engineer",
            "model": DEFAULT_MODEL,
            "endpoint": OLLAMA_ENDPOINT,
            "capabilities": ["prompt_engineering", "llm_optimization"],
            "speed": "medium",
            "quality": "high",
            "tools_enabled": False,
            "system_prompt": (
                "You are the prompt engineer. Design clear instructions, good examples, "
                "constrained outputs, edge case handling. Test with normal, edge, adversarial inputs."
            ),
        },
    }


def get_tools_for_specialist(agent_type: AgentType, tool_modules: dict) -> list:
    """
    Get appropriate tools for specialist agents.

    Args:
        agent_type: The specialist agent type
        tool_modules: Dict of tool module names to their TOOLS lists

    Returns:
        List of tools appropriate for this specialist
    """
    # Common tools all agents can use
    common = tool_modules.get("memory_tools", [])

    # Tool assignments by agent category
    code_tools = tool_modules.get("code_tools", [])
    file_tools = tool_modules.get("file_tools", [])
    system_tools = tool_modules.get("system_tools", [])
    web_tools = tool_modules.get("web_tools", [])

    # Mapping of agent types to their tools
    tool_map = {
        # Code quality - need code and file access
        AgentType.REVIEWER: code_tools + file_tools + common,
        AgentType.REFACTORER: code_tools + file_tools + common,
        AgentType.TESTER: code_tools + file_tools + system_tools + common,
        AgentType.TYPE_SURGEON: code_tools + file_tools + common,

        # DevOps - need system and file access
        AgentType.DEVOPS: system_tools + file_tools + common,
        AgentType.GIT_EXPERT: system_tools + file_tools + common,
        AgentType.ENV_MANAGER: file_tools + common,
        AgentType.MONOREPO: system_tools + file_tools + common,

        # API & Integration
        AgentType.API_DESIGNER: code_tools + file_tools + common,
        AgentType.INTEGRATOR: code_tools + web_tools + file_tools + common,

        # Frontend - code and file access
        AgentType.UI_DESIGNER: code_tools + file_tools + common,
        AgentType.CSS_WIZARD: code_tools + file_tools + common,
        AgentType.MOBILE_UI: code_tools + file_tools + common,

        # Read-only agents
        AgentType.UX_REVIEWER: common,
        AgentType.A11Y: common,
        AgentType.EXPLAINER: common,
        AgentType.REGEX: common,
        AgentType.SEO: common,
        AgentType.ESTIMATOR: common,
        AgentType.PRIORITIZER: common,
        AgentType.DECOMPOSER: common,
        AgentType.PROMPT_ENGINEER: common,

        # Data & Backend
        AgentType.DATA_MODELER: code_tools + file_tools + common,
        AgentType.PERF_ANALYZER: code_tools + system_tools + common,

        # Documentation
        AgentType.DOCS_WRITER: code_tools + file_tools + common,
        AgentType.I18N: code_tools + file_tools + common,

        # Specialized with tools
        AgentType.MIGRATOR: code_tools + file_tools + system_tools + common,
        AgentType.ERROR_HANDLER: code_tools + file_tools + common,
        AgentType.STATE_MANAGER: code_tools + file_tools + common,
        AgentType.DEPS_AUDITOR: system_tools + file_tools + common,
    }

    return tool_map.get(agent_type, common)
