# Agent Reference - PKN Multi-Agent System

**Single source of truth for ALL agent configurations across PC and Mobile.**

## Related Documentation

- [Tools Reference](./TOOLS.md) - Tools available to agents
- [Shadow OSINT](./SHADOW_OSINT.md) - OSINT-specific tools
- [Deployment](./DEPLOYMENT.md) - How to deploy agents
- [Architecture](./ARCHITECTURE.md) - System design
- [PC CLAUDE.md](../apps/pkn/CLAUDE.md) - PC-specific details
- [Mobile CLAUDE.md](../apps/pkn-mobile/CLAUDE.md) - Mobile-specific details

---

## Overview

PKN uses **9 specialized AI agents** that work together to handle different types of tasks. Each agent is optimized for specific capabilities, with different models configured for PC vs Mobile hardware.

**Key Design Principles:**
- **LOCAL-FIRST**: All agents default to local inference (Ollama) for privacy
- **CLOUD OPTION**: Users can toggle to cloud (Groq/Claude) for speed when needed
- **UNCENSORED MODELS**: Security/Reasoner agents use abliterated models for legitimate security work
- **FULL TOOL ACCESS**: All 13 tool modules + 35 OSINT tools available to all agents

---

## Agent Summary Table

| Agent | Model (PC) | Model (Mobile) | Purpose | Response Time |
|-------|-----------|----------------|---------|---------------|
| **CODER** | qwen2.5-coder:14b | qwen2.5-coder:7b | Code writing, debugging | 15-30s / ~10s |
| **GENERAL** | llama3.1-8b-lexi | qwen:latest | Quick Q&A | 8-15s / ~1s |
| **REASONER** | qwen3:14b | nous-hermes:latest | Planning, logic | 20-40s / ~13s |
| **SECURITY** | qwen3-abliterated:4b | dolphin-phi:latest | Pentesting (UNCENSORED) | 10-20s / ~7s |
| **RESEARCHER** | mistral:latest | mistral:latest | Web research | 25-60s / ~15s |
| **EXECUTOR** | deepseek-coder:6.7b | qwen2.5-coder:7b | System commands | 20-40s / ~10s |
| **VISION** | llava:latest | llava:latest | Image analysis | 15-25s / ~15s |
| **CONSULTANT** | Claude API | Claude API | Cloud reasoning (premium) | ~3-5s |
| **VISION_CLOUD** | Groq Llama-3.2-90B | Groq Llama-3.2-90B | Fast cloud vision (FREE) | ~1-3s |

**Legend:**
- Response times: PC / Mobile
- UNCENSORED: Uses abliterated models without safety filters (for security work)
- FREE: No API cost, no credit card required
- API: Requires API key configuration

---

## Detailed Agent Configurations

### 1. CODER - Code Writing & Debugging

**Purpose:** Expert code writer, debugger, and refactoring specialist

**Models:**
- **PC:** `qwen2.5-coder:14b` (8.4GB) - High quality code generation
- **Mobile:** `qwen2.5-coder:7b` (4.7GB) - Fast mobile-friendly coding

**Capabilities:**
- Code writing (Python, JavaScript, Bash, etc.)
- Debugging and error analysis
- Code refactoring and optimization
- Code review and suggestions

**Tools Available:**
- `code_tools`: Symbol extraction, AST parsing, code analysis
- `file_tools`: Read/write/search files
- `memory_tools`: Remember coding patterns, user preferences
- `sandbox_tools`: Safe code execution environment

**Best For:**
- Writing new functions/scripts
- Fixing bugs in existing code
- Refactoring messy code
- Code reviews

**Example Prompt:** *"Write a Python function to parse JSON logs and extract error messages"*

---

### 2. GENERAL - Quick Q&A Assistant

**Purpose:** Fast responses for simple questions and conversations

**Models:**
- **PC:** `llama3.1-8b-lexi` (Q4_0 quantized) - Ultra-fast inference
- **Mobile:** `qwen:latest` (2.3GB) - Smallest, fastest model

**Capabilities:**
- Simple question answering
- Explanations and definitions
- General conversation
- Quick lookups

**Tools Available:**
- `memory_tools`: Session context
- `web_tools`: Basic web search (if needed)
- `chain_tools`: Simple tool chaining

**Best For:**
- "What is X?"
- "How do I Y?"
- Quick facts and definitions
- Casual conversation

**Response Time:** ~1-2 seconds (fastest agent)

**Example Prompt:** *"What does API stand for?"*

---

### 3. REASONER - Planning & Logic

**Purpose:** Complex problem-solving, planning, multi-step reasoning

**Models:**
- **PC:** `qwen3:14b` - Advanced reasoning capabilities
- **Mobile:** `nous-hermes:latest` (3.8GB, **UNCENSORED**)

**Capabilities:**
- Step-by-step planning
- Logical analysis
- Problem decomposition
- Decision making
- Strategy formulation

**Tools Available:**
- `planning_tools`: Task planning, execution tracking
- `delegation_tools`: Coordinate other agents
- `memory_tools`: Long-term reasoning context
- `workflow_tools`: Multi-agent orchestration

**Why Uncensored (Mobile):**
- Can analyze security strategies without safety filters
- Helps with security planning alongside SECURITY agent
- No content restrictions for technical discussions

**Best For:**
- "Plan out how to build X"
- "What's the best approach to solve Y?"
- Multi-step workflows
- Strategic decisions

**Example Prompt:** *"Plan a multi-stage approach to optimize this codebase"*

---

### 4. SECURITY - Penetration Testing (UNCENSORED)

**Purpose:** Cybersecurity expert for legitimate pentesting and security work

**Models:**
- **PC:** `qwen3-abliterated:4b` (**UNCENSORED**)
- **Mobile:** `dolphin-phi:latest` (1.6GB, **UNCENSORED**)

**Capabilities:**
- Penetration testing
- Vulnerability analysis
- Exploit development (educational)
- Security auditing
- Malware analysis
- Network security assessment
- Web security testing
- Cryptography
- OSINT (Open Source Intelligence)

**Why Uncensored:**
- User does legitimate security/pentesting work
- Needs to discuss: SQL injection, XSS, buffer overflows, exploits
- Censored models refuse helpful security education
- "Abliterated" = fine-tuned to remove safety guardrails

**Tools Available (Full Kali-style Toolkit):**
- `osint_tools`: Port scanning, DNS, IP lookup, WHOIS
- `pentest_tools`: Reverse shells, payloads, exploits
- `recon_tools`: Banner grabbing, header analysis, directory enumeration
- `privesc_tools`: SUID hunting, cron analysis, kernel exploits
- `network_tools`: TCP/UDP scanning, traceroute, ARP
- `crypto_tools`: Hash cracking, JWT analysis, encoding/decoding
- `shadow_tools`: 35 OSINT tools (username hunting, Google dorks, etc.)
- `web_tools`: Web reconnaissance
- `system_tools`: System analysis, command execution
- `file_tools`: File operations for analysis
- `code_tools`: Code review for vulnerabilities

**Best For:**
- Security assessments
- Vulnerability scanning
- Exploit analysis
- OSINT investigations
- Security education

**Example Prompt:** *"Analyze this web app for SQL injection vulnerabilities"*

**Warning:** Only use for authorized testing on systems you own or have permission to test.

---

### 5. RESEARCHER - Web Research & Documentation

**Purpose:** Information gathering, web search, documentation lookup

**Models:**
- **PC:** `mistral:latest` (4.4GB)
- **Mobile:** `mistral:latest` (4.4GB)

**Capabilities:**
- Web search and scraping
- Documentation lookup
- Fact-checking
- Research aggregation
- Source citation

**Tools Available:**
- `web_tools`: HTTP requests, web scraping, search
- `osint_tools`: Domain analysis, email validation, etc.
- `file_tools`: Save research findings
- `rag_tools`: Vector search through documentation
- `memory_tools`: Remember research context

**Best For:**
- "Research X and summarize findings"
- Documentation lookups
- Fact verification
- Gathering information

**Example Prompt:** *"Research the latest Python asyncio best practices"*

---

### 6. EXECUTOR - System Commands & File Operations

**Purpose:** Execute system commands, manage files, run scripts

**Models:**
- **PC:** `deepseek-coder:6.7b` - Fast command execution
- **Mobile:** `qwen2.5-coder:7b` (4.7GB)

**Capabilities:**
- Command execution
- File operations (create, read, write, delete)
- System tasks (permissions, processes)
- Script execution
- Git operations
- Project management

**Tools Available:**
- `system_tools`: Execute shell commands, process management
- `file_tools`: Full file system access
- `git_tools`: Version control operations
- `project_tools`: Project structure management
- `sandbox_tools`: Safe execution environment
- `evaluation_tools`: Test execution results

**Best For:**
- "Run this command and show output"
- File manipulation tasks
- Git operations
- System administration

**Example Prompt:** *"Create a new directory structure for a Flask app"*

---

### 7. VISION - Image Analysis (Local)

**Purpose:** Analyze images, screenshots, diagrams locally

**Models:**
- **PC:** `llava:latest` (~7B parameters)
- **Mobile:** `llava:latest` (~7B parameters)

**Capabilities:**
- Image analysis
- Screenshot understanding
- UI/UX analysis
- Visual debugging
- Diagram interpretation
- OCR (text extraction)
- Object detection
- Scene understanding

**Tools Available:**
- `file_tools`: Load images from disk
- `web_tools`: Fetch images from URLs
- `memory_tools`: Remember visual context

**Best For:**
- Analyzing screenshots
- UI mockup review
- Diagram interpretation
- Visual debugging

**Privacy:** Fully local - images never leave your device

**Example Prompt:** *"Analyze this screenshot and describe the UI layout"*

---

### 8. VISION_CLOUD - Fast Cloud Vision (FREE)

**Purpose:** Ultra-fast image analysis using Groq's free cloud API

**Model:**
- **Groq Llama-3.2-90B-Vision-Preview** (FREE, no credit card)

**Capabilities:**
- Same as VISION agent but much faster (~1-3s)
- Superior accuracy with 90B parameter model
- English-only responses

**Setup:**
1. Get free API key: https://console.groq.com
2. Add to `.env`: `GROQ_API_KEY=your_key_here`
3. No credit card required

**Fallback:** If Groq unavailable, automatically falls back to local VISION agent

**Best For:**
- Fast image analysis when speed matters
- Complex visual understanding
- High-quality OCR

**Cost:** $0 (completely free)

---

### 9. CONSULTANT - Premium Cloud Reasoning

**Purpose:** Highest-quality reasoning using Claude API (premium)

**Model:**
- **Claude 3.5 Sonnet** (Anthropic)

**Capabilities:**
- Maximum intelligence
- Complex reasoning
- High-level decisions
- Voting on agent consensus
- Expert advice

**Tools Available:**
- ALL tools (full suite - 13 modules + OSINT)

**Setup:**
1. Get API key: https://console.anthropic.com
2. Add to `.env`: `ANTHROPIC_API_KEY=your_key_here`

**Cost:** Pay-per-use (charged by Anthropic)

**Fallback:** If Claude unavailable, falls back to local REASONER agent

**Best For:**
- Complex decisions
- Maximum quality reasoning
- When local agents struggle

---

## Tool Access by Agent

All agents have access to common tools:
- `memory_tools` - Session persistence, user preferences
- `scratchpad_tools` - Agent-to-agent handoff
- `workflow_tools` - Multi-agent coordination

**Agent-Specific Tool Suites:**

| Agent | Additional Tools |
|-------|-----------------|
| CODER | code_tools, file_tools, sandbox_tools |
| EXECUTOR | system_tools, file_tools, git_tools, project_tools, evaluation_tools |
| RESEARCHER | web_tools, osint_tools, file_tools, rag_tools |
| REASONER | planning_tools, delegation_tools |
| SECURITY | ALL tools (full Kali-style suite + Shadow OSINT) |
| CONSULTANT | ALL tools (complete access) |
| VISION | file_tools, web_tools |
| GENERAL | Basic subset (file read, glob, web search) |

**See Also:**
- [Tools Reference](./TOOLS.md) - Complete tool documentation
- [Shadow OSINT](./SHADOW_OSINT.md) - 35 OSINT tools for SECURITY agent

---

## Backend Modes: Local vs Cloud

### Local Mode (Default)

**Privacy-First Design:**
- All inference runs on your hardware
- No data sent to external servers
- Fully offline capable
- Free to use (no API costs)

**Configuration:**
- PC: Ollama on port 11434
- Mobile: Ollama on port 11434
- Models stored locally

**Advantages:**
- Complete privacy
- No API costs
- Offline capability
- No rate limits

**Disadvantages:**
- Slower response times (10-30s)
- Requires model storage (20-40GB)
- Dependent on hardware

### Cloud Mode (Optional)

**Speed-Optimized Design:**
- Uses Groq API (free) for fast inference
- 1-3 second responses
- No local model storage needed

**Toggle Backend:**
```bash
# Via API endpoint
POST /api/multi-agent/backend
{"backend": "cloud"}  # or "local"
```

**Advantages:**
- Ultra-fast responses (1-3s)
- No local storage needed
- Works on low-end hardware

**Disadvantages:**
- Requires internet
- Data sent to Groq servers
- Requires API key (but free)

**Best Practice:** Use local by default, toggle to cloud when speed matters

---

## Configuration Files

### PC Configuration

**Location:** `/home/gh0st/dvn/divine-workspace/apps/pkn/`

**Files:**
- `backend/agents/manager.py` - Agent orchestration (1,111 lines)
- `backend/config/model_config.py` - Model assignments
- `.env` - API keys and settings

**Example `.env`:**
```bash
OLLAMA_BASE=http://127.0.0.1:11434
ANTHROPIC_API_KEY=sk-ant-...
GROQ_API_KEY=gsk_...
```

### Mobile Configuration

**Location:** `~/pkn/` (on Termux)

**Files:**
- `backend/agents/manager.py` - Mobile agent manager (1,264 lines)
- `backend/config/model_config.py` - Mobile model assignments
- `.env` or `.bashrc` - API keys

**Mobile-Specific:**
- Lighter models (7B instead of 14B)
- Optimized for battery/memory
- Same capabilities, slightly slower

---

## Model Storage Requirements

### PC (Full Setup)

| Model | Size | Agent | Usage |
|-------|------|-------|-------|
| qwen2.5-coder:14b | 8.4GB | CODER | Code generation |
| qwen3:14b | 8.5GB | REASONER | Planning |
| mistral:latest | 4.4GB | RESEARCHER | Research |
| deepseek-coder:6.7b | 4.0GB | EXECUTOR | Commands |
| llama3.1-8b-lexi | 4.7GB | GENERAL | Quick Q&A |
| qwen3-abliterated:4b | 2.3GB | SECURITY | Pentesting |
| llava:latest | 4.7GB | VISION | Images |
| **Total** | **~37GB** | | |

### Mobile (Optimized Setup)

| Model | Size | Agent | Usage |
|-------|------|-------|-------|
| qwen2.5-coder:7b | 4.7GB | CODER | Code generation |
| nous-hermes:latest | 3.8GB | REASONER | Planning (uncensored) |
| mistral:latest | 4.4GB | RESEARCHER | Research |
| qwen:latest | 2.3GB | GENERAL | Quick Q&A |
| dolphin-phi:latest | 1.6GB | SECURITY | Pentesting (uncensored) |
| llava:latest | 4.7GB | VISION | Images |
| **Total** | **~22GB** | | |

**Note:** Cloud agents (CONSULTANT, VISION_CLOUD) require no local storage.

---

## Response Time Benchmarks

**Measured on Samsung Galaxy S24 Ultra (Snapdragon 8 Gen 3, 12GB RAM):**

| Agent | Model | Response Time | Task Type |
|-------|-------|---------------|-----------|
| GENERAL | qwen:latest | ~0.8s | "What is X?" |
| SECURITY | dolphin-phi | ~7.2s | Security analysis |
| REASONER | nous-hermes | ~12.9s | Multi-step planning |
| CODER | qwen2.5-coder:7b | ~10s | Code generation |
| VISION | llava:latest | ~15s | Image analysis |
| VISION_CLOUD | Groq | ~1-3s | Fast cloud vision |
| CONSULTANT | Claude API | ~3-5s | Premium reasoning |

**PC times:** Generally 1.5-2x faster with more powerful hardware.

---

## Agent Selection Logic

**Automatic Routing (Task Classifier):**

The system automatically routes tasks to the best agent based on keywords:

| Keywords | Agent | Reason |
|----------|-------|--------|
| "code", "function", "debug", "refactor" | CODER | Code-related tasks |
| "plan", "strategy", "analyze", "think" | REASONER | Planning/logic |
| "research", "search", "find", "lookup" | RESEARCHER | Information gathering |
| "run", "execute", "command", "file" | EXECUTOR | System operations |
| "security", "exploit", "vulnerability", "pentest" | SECURITY | Security work |
| "image", "screenshot", "analyze photo" | VISION | Visual analysis |
| Everything else | GENERAL | Default fallback |

**Manual Override:**
```bash
# Force specific agent
POST /api/multi-agent/chat
{
  "message": "Your task",
  "agent_override": "coder"  # Force CODER agent
}
```

---

## Multi-Agent Collaboration

Agents can work together on complex tasks:

**Example Workflow:**
1. **REASONER** creates plan
2. **CODER** writes implementation
3. **SECURITY** audits for vulnerabilities
4. **EXECUTOR** deploys to system

**Delegation Example:**
```python
# REASONER delegates to CODER
manager.delegate_to_agent(
    from_agent="reasoner",
    to_agent="coder",
    task="Write function based on plan"
)
```

**See Also:** [Architecture](./ARCHITECTURE.md) for agent collaboration patterns

---

## Troubleshooting

### Agent Not Responding

**Local Mode:**
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama
pkill ollama && ollama serve &
```

**Cloud Mode:**
```bash
# Verify API key
echo $GROQ_API_KEY

# Test Groq connection
curl https://api.groq.com/openai/v1/models \
  -H "Authorization: Bearer $GROQ_API_KEY"
```

### Wrong Agent Selected

**Check routing logic:**
```bash
# Get task classification
POST /api/multi-agent/classify
{"instruction": "Your task"}
```

**Use manual override:**
```bash
POST /api/multi-agent/chat
{
  "message": "Your task",
  "agent_override": "security"  # Force specific agent
}
```

### Model Not Found (Mobile)

**Check installed models:**
```bash
ollama list
```

**Pull missing model:**
```bash
ollama pull qwen2.5-coder:7b
```

**See:** Mobile CLAUDE.md for required models list

---

## Security Considerations

### Uncensored Models

**SECURITY and REASONER (mobile) use uncensored models.**

**Why:**
- Legitimate security/pentesting work requires discussing exploits
- Educational content on vulnerabilities
- Technical discussions without filters

**Responsible Use:**
- Only use on authorized systems
- Educational purposes only
- Follow local laws and regulations

### Privacy

**Local Mode:**
- Zero external data transmission
- All processing on-device
- Models stored locally
- Complete privacy

**Cloud Mode:**
- Data sent to Groq/Anthropic servers
- Check their privacy policies
- Use local mode for sensitive data

---

## Performance Optimization

### PC Optimization

**GPU Acceleration (if available):**
```bash
# Use CUDA/ROCm for faster inference
ollama serve --gpu-layers 45
```

**Context Size:**
```bash
# Increase for longer conversations
ollama run qwen2.5-coder:14b --ctx-size 8192
```

### Mobile Optimization

**Battery Saving:**
```bash
# Use smaller models
GENERAL agent (qwen:latest 2.3GB) instead of larger models
```

**Memory Management:**
```bash
# Limit concurrent models
ollama serve --keep-alive 5m  # Unload after 5 minutes
```

---

## Future Enhancements

**Planned Features:**
- Real-time streaming responses for all agents
- Function calling for tool execution (currently prompt-based)
- Agent-to-agent direct messaging
- Persistent agent memory across sessions
- Custom agent creation by users

**See:** [ROADMAP.md](./ROADMAP.md) for full development plan

---

## Quick Reference

**Start Agents (PC):**
```bash
./pkn_control.sh start-all
```

**Start Agents (Mobile):**
```bash
pkn  # Launch Termux menu
# Select: 1) PKN Mobile
```

**Check Agent Status:**
```bash
curl http://localhost:8010/api/multi-agent/agents
```

**Switch Backend:**
```bash
POST /api/multi-agent/backend
{"backend": "cloud"}  # or "local"
```

**View Agent Stats:**
```bash
curl http://localhost:8010/api/multi-agent/stats
```

---

**Last Updated:** 2026-01-18
**Version:** 1.0
**Platforms:** PC (Linux) + Mobile (Termux/Android)
