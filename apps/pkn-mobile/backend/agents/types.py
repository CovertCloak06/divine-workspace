"""
Agent Types and Data Structures
Enums and dataclasses for multi-agent system
"""

import uuid
import time
from typing import Dict, Any
from enum import Enum


class AgentType(Enum):
    """Types of specialized agents"""

    # === CORE AGENTS (Original 9) ===
    CODER = "coder"  # Code writing, debugging, refactoring
    REASONER = "reasoner"  # Planning, logic, problem solving
    RESEARCHER = "researcher"  # Web research, documentation lookup
    EXECUTOR = "executor"  # Command execution, system tasks
    GENERAL = "general"  # General conversation, simple Q&A
    CONSULTANT = "consultant"  # External LLM (Claude/GPT) for high-level decisions
    SECURITY = "security"  # Cybersecurity, pentesting, vulnerability analysis
    VISION = "vision"  # Vision/image analysis, UI understanding (LOCAL)
    VISION_CLOUD = "vision_cloud"  # Cloud vision via Groq (FREE, fast)

    # === SPECIALIST AGENTS (New) ===
    # Code Quality
    REVIEWER = "reviewer"  # Code review, quality checks
    REFACTORER = "refactorer"  # Code cleanup, restructuring
    TESTER = "tester"  # Test writing, coverage
    TYPE_SURGEON = "type_surgeon"  # TypeScript types, generics

    # DevOps & Infrastructure
    DEVOPS = "devops"  # CI/CD, Docker, deployment
    GIT_EXPERT = "git_expert"  # Git operations, merge conflicts
    ENV_MANAGER = "env_manager"  # Environment, secrets, config
    MONOREPO = "monorepo"  # Nx, Turborepo, workspaces

    # API & Integration
    API_DESIGNER = "api_designer"  # REST, GraphQL, OpenAPI
    INTEGRATOR = "integrator"  # Third-party APIs, webhooks

    # Frontend & UX
    UI_DESIGNER = "ui_designer"  # Component design, layouts
    UX_REVIEWER = "ux_reviewer"  # User flows, usability
    CSS_WIZARD = "css_wizard"  # CSS, animations, responsive
    MOBILE_UI = "mobile_ui"  # Mobile/PWA specialist
    A11Y = "a11y"  # Accessibility, WCAG, ARIA

    # Data & Backend
    DATA_MODELER = "data_modeler"  # Database, schemas, SQL
    PERF_ANALYZER = "perf_analyzer"  # Performance optimization

    # Documentation & Communication
    DOCS_WRITER = "docs_writer"  # README, JSDoc, documentation
    EXPLAINER = "explainer"  # Explain concepts simply
    I18N = "i18n"  # Internationalization, translations

    # Specialized
    REGEX = "regex"  # Regular expressions
    MIGRATOR = "migrator"  # Version upgrades, legacy code
    ERROR_HANDLER = "error_handler"  # Error boundaries, recovery
    STATE_MANAGER = "state_manager"  # Redux, Zustand, Context
    SEO = "seo"  # SEO, meta tags, structured data
    DEPS_AUDITOR = "deps_auditor"  # Dependency vulnerabilities

    # Planning & Management
    ESTIMATOR = "estimator"  # Time/effort estimates
    PRIORITIZER = "prioritizer"  # Task prioritization
    DECOMPOSER = "decomposer"  # Break down large tasks

    # AI & Prompts
    PROMPT_ENGINEER = "prompt_engineer"  # LLM prompts, system messages


class TaskComplexity(Enum):
    """Task complexity levels"""

    SIMPLE = "simple"  # Quick answers, basic operations
    MEDIUM = "medium"  # Requires some reasoning or tool use
    COMPLEX = "complex"  # Multi-step, requires multiple agents


class AgentMessage:
    """Message for agent-to-agent communication"""

    def __init__(
        self,
        from_agent: str,
        to_agent: str,
        task_id: str,
        content: Dict[str, Any],
        requires_response: bool = False,
    ):
        self.id = str(uuid.uuid4())
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.task_id = task_id
        self.content = content
        self.requires_response = requires_response
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "task_id": self.task_id,
            "content": self.content,
            "requires_response": self.requires_response,
            "timestamp": self.timestamp,
        }
