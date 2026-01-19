"""
Task Classification Module
Analyzes tasks and routes to appropriate agents with 37 specialized agent types
"""

from typing import Dict, Any, List, Tuple
from .types import AgentType, TaskComplexity

# === TRIGGER KEYWORDS FOR ALL 37 AGENTS ===
TRIGGERS: Dict[AgentType, List[str]] = {
    # === CORE AGENTS ===
    AgentType.CODER: [
        "code", "function", "class", "debug", "bug", "error", "implement",
        "write code", "python", "javascript", "script", "algorithm", "syntax",
        "variable", "programming", "compile", "runtime"
    ],
    AgentType.REASONER: [
        "plan", "strategy", "approach", "analyze", "compare", "evaluate",
        "pros and cons", "should i", "which", "best way", "explain why",
        "logic", "reasoning", "think through", "consider"
    ],
    AgentType.RESEARCHER: [
        "search", "find", "lookup", "research", "what is", "who is",
        "when did", "how to", "wikipedia", "documentation", "docs",
        "latest", "current", "news", "github", "library", "learn about"
    ],
    AgentType.EXECUTOR: [
        "run", "execute", "list files", "read file", "write file",
        "create file", "delete", "move", "copy", "command", "bash",
        "shell", "directory", "terminal", "cli"
    ],
    AgentType.GENERAL: [
        "hello", "hi", "hey", "thanks", "thank you", "help", "chat"
    ],
    AgentType.CONSULTANT: [
        "vote", "decide", "choose between", "which option", "expert opinion",
        "deep thought", "complex decision", "consult", "advise", "recommend",
        "philosophical", "ethical", "strategic decision", "critical choice"
    ],
    AgentType.SECURITY: [
        "hack", "exploit", "vulnerability", "pentest", "security",
        "cybersecurity", "injection", "xss", "csrf", "sql injection",
        "malware", "backdoor", "privilege escalation", "nmap", "metasploit",
        "red team", "attack", "payload", "cve", "osint", "reconnaissance",
        "port scan", "firewall", "bypass"
    ],
    AgentType.VISION: [
        "image", "screenshot", "picture", "photo", "visual", "see",
        "look at", "analyze image", "describe image", "ui", "diagram",
        "chart", "graph", "ocr", "extract text", "recognize", "detect"
    ],
    AgentType.VISION_CLOUD: [
        "image", "screenshot", "picture", "photo", "visual"
    ],

    # === CODE QUALITY AGENTS ===
    AgentType.REVIEWER: [
        "review", "check code", "before commit", "pr review", "code quality",
        "looks good", "lgtm", "approve", "feedback on"
    ],
    AgentType.REFACTORER: [
        "refactor", "clean up", "reorganize", "split", "extract",
        "simplify", "too long", "restructure", "improve code"
    ],
    AgentType.TESTER: [
        "test", "coverage", "tdd", "unit test", "write tests", "add tests",
        "integration test", "e2e", "jest", "pytest", "spec"
    ],
    AgentType.TYPE_SURGEON: [
        "typescript", "types", "generics", "interface", "type error",
        "typing", "type inference", "type guard", "any type"
    ],

    # === DEVOPS & INFRASTRUCTURE ===
    AgentType.DEVOPS: [
        "deploy", "ci/cd", "docker", "github actions", "pipeline",
        "kubernetes", "k8s", "container", "yaml", "jenkins", "terraform"
    ],
    AgentType.GIT_EXPERT: [
        "git", "merge", "rebase", "conflict", "cherry-pick", "bisect",
        "stash", "branch", "commit", "push", "pull", "reset", "checkout"
    ],
    AgentType.ENV_MANAGER: [
        "env", "environment", ".env", "config", "secrets", "api key",
        "credentials", "dotenv", "configuration"
    ],
    AgentType.MONOREPO: [
        "monorepo", "workspace", "nx", "turborepo", "lerna",
        "pnpm workspace", "yarn workspace", "packages"
    ],

    # === API & INTEGRATION ===
    AgentType.API_DESIGNER: [
        "rest api", "graphql", "openapi", "swagger", "endpoint design",
        "api spec", "api versioning", "http methods", "request response"
    ],
    AgentType.INTEGRATOR: [
        "integrate", "api", "webhook", "third-party", "connect",
        "external", "oauth", "sdk", "client library"
    ],

    # === FRONTEND & UX ===
    AgentType.UI_DESIGNER: [
        "component", "ui design", "layout", "design system", "mockup",
        "wireframe", "prototype", "visual design"
    ],
    AgentType.UX_REVIEWER: [
        "user flow", "ux", "friction", "usability", "user experience",
        "journey", "onboarding", "conversion"
    ],
    AgentType.CSS_WIZARD: [
        "css", "animation", "style", "responsive", "flexbox", "grid",
        "sass", "tailwind", "styled-components", "media query"
    ],
    AgentType.MOBILE_UI: [
        "mobile", "pwa", "touch", "viewport", "ios", "android",
        "tablet", "responsive mobile", "app store"
    ],
    AgentType.A11Y: [
        "accessibility", "a11y", "screen reader", "aria", "wcag",
        "keyboard nav", "focus", "contrast", "alt text"
    ],

    # === DATA & BACKEND ===
    AgentType.DATA_MODELER: [
        "database", "schema", "migration", "sql", "model", "query",
        "table", "postgres", "mysql", "mongodb", "orm", "prisma"
    ],
    AgentType.PERF_ANALYZER: [
        "slow", "performance", "optimize", "speed", "memory", "leak",
        "fast", "latency", "profiling", "bottleneck", "cache"
    ],

    # === DOCUMENTATION & COMMUNICATION ===
    AgentType.DOCS_WRITER: [
        "document", "readme", "jsdoc", "comment", "docs", "explain code",
        "api docs", "wiki", "guide", "tutorial"
    ],
    AgentType.EXPLAINER: [
        "explain", "what is", "how does", "understand", "clarify",
        "eli5", "simple terms", "teach me", "break down"
    ],
    AgentType.I18N: [
        "i18n", "internationalization", "localize", "translate", "rtl",
        "l10n", "language support", "locale", "translation"
    ],

    # === SPECIALIZED ===
    AgentType.REGEX: [
        "regex", "regexp", "pattern match", "capture group",
        "regular expression", "match pattern"
    ],
    AgentType.MIGRATOR: [
        "migrate", "upgrade version", "legacy code", "modernize",
        "breaking change", "deprecate", "version upgrade"
    ],
    AgentType.ERROR_HANDLER: [
        "error handling", "try catch", "error boundary", "graceful degradation",
        "fallback", "recovery", "exception", "catch error"
    ],
    AgentType.STATE_MANAGER: [
        "state management", "redux", "zustand", "context api",
        "global state", "store", "reducer", "action"
    ],
    AgentType.SEO: [
        "seo", "meta tags", "sitemap", "robots.txt", "structured data",
        "lighthouse", "open graph", "search ranking"
    ],
    AgentType.DEPS_AUDITOR: [
        "dependency", "npm audit", "outdated", "vulnerable package",
        "upgrade packages", "deps", "security vulnerability"
    ],

    # === PLANNING & MANAGEMENT ===
    AgentType.ESTIMATOR: [
        "how long", "estimate", "timeline", "effort", "time",
        "story points", "sizing"
    ],
    AgentType.PRIORITIZER: [
        "prioritize", "what first", "important", "urgent", "order",
        "backlog", "roadmap"
    ],
    AgentType.DECOMPOSER: [
        "break down", "decompose", "smaller tasks", "split task",
        "subtasks", "epic"
    ],

    # === AI & PROMPTS ===
    AgentType.PROMPT_ENGINEER: [
        "prompt", "system message", "llm", "gpt", "claude prompt",
        "prompt engineering", "few-shot", "chain of thought"
    ],
}

# Weights for scoring (higher = more priority when matched)
AGENT_WEIGHTS = {
    AgentType.SECURITY: 2.5,      # Highest for safety-critical routing
    AgentType.VISION: 2.0,
    AgentType.VISION_CLOUD: 2.0,
    AgentType.CONSULTANT: 2.0,
    AgentType.GIT_EXPERT: 1.5,    # Specific tool expertise
    AgentType.REGEX: 1.5,
    AgentType.TYPE_SURGEON: 1.5,
}


class TaskClassifier:
    """Classifies tasks and determines appropriate agent routing"""

    def __init__(self):
        self.triggers = TRIGGERS
        self.weights = AGENT_WEIGHTS

    def classify(self, instruction: str) -> Dict[str, Any]:
        """
        Classify task by type, complexity, and required agent.

        Returns dict with agent_type, complexity, confidence, reasoning, requires_tools
        """
        instruction_lower = instruction.lower()

        # Score each agent based on keyword matches
        scores: Dict[AgentType, float] = {}
        for agent, keywords in self.triggers.items():
            score = 0
            for kw in keywords:
                if kw in instruction_lower:
                    # Base score for substring match
                    score += 2
                    # Bonus for word boundary match
                    import re
                    if re.search(rf'\b{re.escape(kw)}\b', instruction_lower):
                        score += 1
            if score > 0:
                weight = self.weights.get(agent, 1.0)
                scores[agent] = score * weight

        # Get highest scoring agent
        if scores:
            agent_type = max(scores, key=scores.get)
            max_score = scores[agent_type]
            confidence = min(max_score / 10.0, 1.0)
        else:
            agent_type = AgentType.GENERAL
            confidence = 0.5

        # Determine complexity
        word_count = len(instruction.split())
        has_multi_steps = any(
            word in instruction_lower
            for word in ["and then", "after that", "next", "also", "additionally", "then"]
        )

        if word_count < 10 and not has_multi_steps:
            complexity = TaskComplexity.SIMPLE
        elif word_count < 30 and not has_multi_steps:
            complexity = TaskComplexity.MEDIUM
        else:
            complexity = TaskComplexity.COMPLEX

        # Determine if tools are needed
        tool_agents = {
            AgentType.CODER, AgentType.RESEARCHER, AgentType.EXECUTOR,
            AgentType.SECURITY, AgentType.GIT_EXPERT, AgentType.DEVOPS,
            AgentType.DATA_MODELER, AgentType.TESTER, AgentType.DEPS_AUDITOR
        }
        requires_tools = agent_type in tool_agents

        return {
            "agent_type": agent_type,
            "complexity": complexity,
            "confidence": confidence,
            "reasoning": f"Matched {agent_type.value} (score: {scores.get(agent_type, 0):.1f})",
            "requires_tools": requires_tools,
            "word_count": word_count,
            "has_multi_steps": has_multi_steps,
        }

    def route(self, instruction: str, conversation_id: str = None) -> Dict[str, Any]:
        """
        Route a task to the most appropriate agent.

        Returns dict with agent, classification, strategy, estimated_time, agent_config
        """
        classification = self.classify(instruction)
        agent_type = classification["agent_type"]

        # Determine strategy
        if classification["complexity"] == TaskComplexity.COMPLEX:
            strategy = "multi_agent"
        else:
            strategy = "single_agent"

        # Map agents to speed estimates
        fast_agents = {AgentType.GENERAL, AgentType.EXPLAINER, AgentType.ESTIMATOR}
        slow_agents = {AgentType.CONSULTANT, AgentType.SECURITY, AgentType.VISION}

        if agent_type in fast_agents:
            estimated_time = "2-5 seconds"
        elif agent_type in slow_agents:
            estimated_time = "10-30 seconds"
        else:
            estimated_time = "5-15 seconds"

        # Get agent config (self.agents is set by AgentManager)
        agent_config = getattr(self, 'agents', {}).get(agent_type, {
            "name": agent_type.value,
            "model": "ollama:mistral:latest",
            "endpoint": "http://127.0.0.1:11434",
            "capabilities": [],
            "speed": "medium",
            "quality": "medium",
            "tools_enabled": True,
        })

        return {
            "agent": agent_type,
            "classification": classification,
            "strategy": strategy,
            "estimated_time": estimated_time,
            "agent_config": agent_config,
        }

    def get_agent_for_triggers(self, triggers: List[str]) -> Tuple[AgentType, float]:
        """
        Find the best agent for a list of trigger keywords.
        Returns (agent_type, confidence)
        """
        combined = " ".join(triggers)
        result = self.classify(combined)
        return result["agent_type"], result["confidence"]
