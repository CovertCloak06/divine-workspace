# PKN Multi-Agent System - Configuration Guide

**Last Updated:** 2026-01-14
**Version:** 2.0 (All Ollama, Tools Enabled)

---

## Overview

PKN uses a multi-agent system where specialized AI agents handle different types of tasks. All agents have full tool access and run locally via Ollama for maximum performance and privacy.

---

## Quick Reference

| Agent | Model | Speed | Use Case | Tools |
|-------|-------|-------|----------|-------|
| **CODER** | qwen2.5-coder:14b | 15-30s | Code writing, debugging | code, file, sandbox, web, memory |
| **REASONER** | qwen3:14b | 20-40s | Planning, logic, analysis | planning, memory, delegation |
| **RESEARCHER** | mistral:latest | 25-60s | Web research, documentation | web, osint, rag, file, memory |
| **EXECUTOR** | deepseek-coder:6.7b | 20-40s | System commands, file ops | system, file, sandbox, evaluation |
| **GENERAL** | llama3.1-8b-lexi | 8-15s | Quick Q&A, conversation | memory, web, chain |
| **SECURITY** | qwen3-abliterated:4b | 10-20s | Pentesting, security (UNCENSORED) | ALL TOOLS |
| **VISION** | llava:latest | 15-25s | Image/screenshot analysis | file, web, memory |
| **CONSULTANT** | Claude API | 3-5s | Premium reasoning (CLOUD) | ALL TOOLS |
| **VISION_CLOUD** | Groq Llama-3.2-90B | 1-3s | Fast vision (CLOUD, FREE) | None |

---

## Agent Details

### CODER Agent
**Purpose:** Code writing, debugging, refactoring, code review

**Model:** `ollama:qwen2.5-coder:14b`
**Endpoint:** `http://127.0.0.1:11434`
**Speed:** Fast (~15-30s)
**Quality:** High

**Tools Available:**
- `code_tools` - Code analysis, symbol extraction, completion
- `file_tools` - Read/write files
- `sandbox_tools` - Safe code execution
- `web_tools` - Web search for documentation
- `memory_tools` - Remember context

**Best For:**
- Writing new functions/classes
- Debugging code
- Refactoring
- Code reviews
- Explaining code

**Example:**
```bash
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Write a Python function to validate email addresses",
    "agent_override": "coder"
  }'
```

---

### REASONER Agent
**Purpose:** Planning, logic, problem solving, analysis

**Model:** `ollama:qwen3:14b`
**Endpoint:** `http://127.0.0.1:11434`
**Speed:** Fast (~20-40s)
**Quality:** High

**Tools Available:**
- `planning_tools` - Break down complex tasks
- `memory_tools` - Context retention
- `delegation_tools` - Coordinate with other agents

**Best For:**
- Breaking down complex problems
- Creating implementation plans
- Logical analysis
- Decision making
- Strategic planning

---

### RESEARCHER Agent
**Purpose:** Web research, documentation lookup, fact-checking

**Model:** `ollama:mistral:latest`
**Endpoint:** `http://127.0.0.1:11434`
**Speed:** Medium (~25-60s including web lookups)
**Quality:** High

**Tools Available:**
- `web_tools` - Web search, HTTP requests, scraping
- `osint_tools` - WHOIS, DNS, IP lookup, email validation
- `rag_tools` - Document search and retrieval
- `file_tools` - Read documentation files
- `memory_tools` - Remember research

**Best For:**
- Web research
- Finding documentation
- Looking up technical information
- OSINT investigations
- Fact-checking

---

### EXECUTOR Agent
**Purpose:** System commands, file operations, task execution

**Model:** `ollama:deepseek-coder:6.7b`
**Endpoint:** `http://127.0.0.1:11434`
**Speed:** Fast (~20-40s)
**Quality:** Medium

**Tools Available:**
- `system_tools` - Execute shell commands
- `file_tools` - File operations (create, read, write, delete)
- `sandbox_tools` - Safe execution environment
- `evaluation_tools` - Task success verification

**Best For:**
- Running system commands
- File management
- Automation tasks
- System administration
- Script execution

**Security Note:** Use with caution - has system command access

---

### GENERAL Agent
**Purpose:** Quick Q&A, simple conversations, general assistance

**Model:** `ollama:mannix/llama3.1-8b-lexi:q4_0`
**Endpoint:** `http://127.0.0.1:11434`
**Speed:** Very Fast (~8-15s)
**Quality:** Medium

**Tools Available:**
- `memory_tools` - Context retention
- `web_tools` - Basic web search
- `chain_tools` - Multi-step workflows

**Best For:**
- Quick questions
- General conversation
- Simple explanations
- Fast responses needed

---

### SECURITY Agent (UNCENSORED)
**Purpose:** Penetration testing, security analysis, exploit development

**Model:** `ollama:huihui_ai/qwen3-abliterated:4b-v2-q4_K_M`
**Endpoint:** `http://127.0.0.1:11434`
**Speed:** Fast (~10-20s)
**Quality:** High
**⚠️ UNCENSORED:** No content filtering

**Tools Available:**
- `osint_tools` - Port scanning, DNS, IP analysis
- `web_tools` - Web reconnaissance
- `system_tools` - System analysis, commands
- `file_tools` - File analysis
- `code_tools` - Vulnerability code review
- `memory_tools` - Track findings

**Best For:**
- Penetration testing
- Vulnerability analysis
- Exploit development
- Security auditing
- Malware analysis
- Network security
- Red teaming

**Important:**
- Use only for authorized security testing
- Uncensored model - no ethical restrictions
- Full tool access for security operations

---

### VISION Agent
**Purpose:** Image analysis, screenshot understanding, UI debugging

**Model:** `ollama:llava:latest`
**Endpoint:** `http://127.0.0.1:11434`
**Speed:** Medium (~15-25s)
**Quality:** High
**Vision Capable:** Yes

**Tools Available:**
- `file_tools` - Load image files
- `web_tools` - Fetch images from URLs
- `memory_tools` - Remember visual context

**Best For:**
- Analyzing screenshots
- Understanding UI layouts
- OCR (text from images)
- Diagram interpretation
- Visual debugging
- Object detection

---

### CONSULTANT Agent (CLOUD)
**Purpose:** Premium reasoning, complex decisions, expert advice

**Model:** Claude API (claude-3-5-sonnet-20241022)
**Endpoint:** Anthropic API (cloud)
**Speed:** Very Fast (~3-5s)
**Quality:** Very High
**⚠️ Cloud Service:** Requires API key

**Tools Available:** ALL TOOLS (full access)

**Best For:**
- Complex reasoning
- High-stakes decisions
- Expert-level advice
- When local models are too slow
- Maximum quality needed

**Setup:**
```bash
export ANTHROPIC_API_KEY="your_key_here"
```

---

### VISION_CLOUD Agent (FREE)
**Purpose:** Fast cloud vision analysis

**Model:** Groq Llama-3.2-90B-Vision
**Endpoint:** Groq API (cloud)
**Speed:** Very Fast (~1-3s)
**Quality:** Very High
**⚠️ Cloud Service:** FREE (no credit card needed)

**Best For:**
- Fast image analysis
- When local vision is too slow
- Screenshot analysis
- Free cloud alternative

---

## All Available Tools (13 Modules)

### 1. code_tools
- Code analysis and parsing
- Symbol extraction (functions, classes, variables)
- Code completion suggestions
- Syntax validation

### 2. file_tools
- Read file contents
- Write files safely
- Glob pattern matching (find files)
- File metadata

### 3. system_tools
- Execute shell commands
- Process management
- System information
- Environment variables

### 4. web_tools
- HTTP GET/POST requests
- Web scraping
- Web search
- API calls

### 5. memory_tools
- Session memory (current conversation)
- Global memory (long-term facts)
- Project memory (project-specific)
- Context management

### 6. osint_tools
- WHOIS lookups
- DNS queries
- IP geolocation
- Email validation
- Port scanning
- Domain intelligence

### 7. rag_tools
- Document retrieval
- Vector search
- Semantic search
- Knowledge base queries

### 8. planning_tools
- Task breakdown
- Step-by-step planning
- Dependency analysis
- Timeline estimation

### 9. delegation_tools
- Agent-to-agent communication
- Task delegation
- Multi-agent coordination
- Result aggregation

### 10. chain_tools
- Multi-step workflows
- Tool chaining
- Sequential execution
- Pipeline management

### 11. sandbox_tools
- Safe code execution
- Isolated environments
- Resource limits
- Security boundaries

### 12. evaluation_tools
- Agent performance tracking
- Success/failure metrics
- Response quality evaluation
- Benchmark testing

### 13. Advanced Features
- RAGMemory - Enhanced memory with vector search
- TaskPlanner - Complex task planning
- PlanExecutor - Execute multi-step plans
- AgentDelegationManager - Coordinate multiple agents
- CodeSandbox - Secure code execution
- AgentEvaluator - Performance monitoring

---

## Configuration Files

### PC Configuration
**File:** `/home/gh0st/dvn/divine-workspace/apps/pkn/backend/agents/manager.py`

**Key Configuration:**
```python
def _init_agents(self):
    """Initialize all agent configurations"""

    self.agents[AgentType.CODER] = {
        "name": "Qwen Coder",
        "model": "ollama:qwen2.5-coder:14b",
        "endpoint": "http://127.0.0.1:11434",
        "capabilities": ["code_writing", "debugging", ...],
        "speed": "fast",
        "quality": "high",
        "tools_enabled": True,  # Full tool access
    }
    # ... more agents
```

### Mobile Configuration
**File:** `/home/gh0st/dvn/divine-workspace/apps/pkn-mobile/backend/agents/manager.py`

**Mobile uses lighter models:**
- qwen2.5-coder:**7b** (instead of 14b)
- qwen:**latest** (instead of qwen3:14b)
- Same tools, optimized for phone

---

## Performance Guide

### Expected Response Times

| Task Complexity | Local (Ollama) | Cloud (Claude/Groq) |
|----------------|----------------|---------------------|
| Simple Q&A | 8-15s | 2-3s |
| Code snippet | 15-30s | 3-5s |
| Complex code | 30-60s | 5-10s |
| Research | 25-60s | 5-15s |
| Vision | 15-25s | 1-3s |

### Optimization Tips

**For Faster Responses:**
1. Use GENERAL agent for simple questions
2. Use cloud agents (CONSULTANT, VISION_CLOUD) when speed is critical
3. Keep context windows small
4. Use specific agents (don't rely on auto-routing)

**For Better Quality:**
1. Use CONSULTANT (Claude) for complex reasoning
2. Use qwen2.5-coder:14b for code quality
3. Provide detailed context in your queries
4. Use tool-aware prompts

---

## Local vs Cloud Toggle

### Local Mode (Default)
**Pros:**
- 100% private
- No API costs
- No internet required
- Uncensored options
- Full tool access

**Cons:**
- Slower (10-120s)
- Limited by hardware
- Larger models need more RAM

### Cloud Mode (On Demand)
**Pros:**
- Very fast (1-5s)
- High quality
- No local resources
- Always available

**Cons:**
- Requires API key (Claude)
- Costs money (Claude ~$0.01/request)
- Internet required
- Privacy considerations

### How to Toggle

**Via API:**
```javascript
// Use local agent (default)
{
  "message": "Your question",
  "agent_override": "coder"  // Uses local ollama
}

// Use cloud agent
{
  "message": "Your question",
  "agent_override": "consultant"  // Uses Claude API
}
```

**Via UI:**
- Select agent from dropdown
- Local agents: CODER, REASONER, etc.
- Cloud agents: CONSULTANT, VISION_CLOUD

---

## Troubleshooting

### Slow Response Times

**Check if model is loaded:**
```bash
curl http://localhost:11434/api/tags
```

**Pre-load models:**
```bash
ollama run qwen2.5-coder:14b "test"
```

### Agent Not Working

**Verify ollama is running:**
```bash
curl http://localhost:11434/api/version
```

**Restart ollama:**
```bash
pkill ollama && ollama serve &
```

### Tools Not Working

**Check tool imports:**
```python
# In manager.py
from ..tools import (
    code_tools,
    file_tools,
    # ... all 13 tool modules
)
```

**Verify tools_enabled:**
```python
self.agents[AgentType.CODER] = {
    # ...
    "tools_enabled": True,  # Must be True
}
```

---

## Testing Agents

### Test Single Agent
```bash
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello",
    "agent_override": "general"
  }'
```

### Test All Agents
```bash
python3 /tmp/test_all_agents.py
```

### Check Agent Configuration
```bash
curl http://localhost:8010/api/multi-agent/agents | python3 -m json.tool
```

---

## Security Considerations

### SECURITY Agent
- **Uncensored model** - no ethical restrictions
- Use only for authorized security testing
- Has full system access via tools
- Document all security findings

### EXECUTOR Agent
- Has shell command access
- Validate commands before execution
- Use sandbox when possible
- Monitor for malicious use

### Cloud Agents
- API keys transmitted over internet
- Queries sent to external services
- Consider data sensitivity
- Use local for sensitive data

---

## Migration Notes

### From llama.cpp to Ollama (2026-01-14)

**Reason:** llama.cpp was taking >120s per request (timeout), ollama is 10-120s

**Changes:**
- All PC agents switched to ollama
- Same models, different backend
- 10x performance improvement
- All tools remain enabled

**Backward Compatibility:**
- API endpoints unchanged
- Tool system unchanged
- Mobile already using ollama
- Zero breaking changes

---

## Model Storage

**PC Models Location:**
- Ollama: `~/.ollama/models/`
- Total size: ~40GB for all models

**Mobile Models Location:**
- Ollama: `~/models/` (via Termux)
- Total size: ~20GB for mobile models

---

## Future Enhancements

### Phase 2 - Full Tool Execution Framework ✅ COMPLETE (2026-01-14)

**Phase 1:** ✅ Complete
- Agents are **tool-aware** (know tools exist via system prompts)
- All 13 tool modules integrated and available
- `tools_enabled: True` for all agents

**Phase 2:** ✅ Complete
- Agents **execute tools** and receive results
- Multi-turn conversations: Agent → Tool → Agent → User
- Tool chaining: Agent calls tool A, sees result, calls tool B
- **29 tools** auto-discovered and ready to use
- Universal tool registry with zero technical debt
- Comprehensive test suite (9/9 tests passing)

**Completed Implementation:**

✅ **Tool Registry** (`backend/tools/__init__.py`)
- Auto-discovers 29 tools across 5 modules
- Universal execution interface
- Tool schemas for agent awareness
- Usage statistics tracking

✅ **Tool Executor** (`backend/agents/tool_executor.py`)
- Parses 5 different tool call formats
- Executes tools via registry
- Multi-turn conversation support
- Tool execution history

✅ **Agent Integration** (`backend/agents/manager.py`)
- Updated `_execute_with_tools` method
- Full multi-turn tool execution
- Graceful error handling
- Max 3 tool rounds per query

✅ **Testing Suite**
- `test_tool_registry.py` - Registry tests
- `test_tool_execution_framework.py` - Comprehensive framework tests
- All 9/9 tests passing

**Results:**
- **29 functional tools** ready to use
- **Zero technical debt** (clean architecture)
- **Production ready** (all tests passing)
- **Instant scaling** (new tools auto-discovered)

**Documentation:**
- See [TOOL_EXECUTION_FRAMEWORK.md](TOOL_EXECUTION_FRAMEWORK.md) for complete details

---

### Phase 3 - Advanced Tool Features (NEXT)

**Planned Enhancements:**

1. **Parallel Tool Execution**
   - Execute multiple independent tools simultaneously
   - Reduce total execution time by 50-70%

2. **Tool Streaming**
   - Stream tool results as they're generated
   - Better UX for long-running tools (web scraping, large file reads)

3. **Tool Composition**
   - Agents automatically chain tools for complex tasks
   - Example: Search files → Read matching files → Summarize content

4. **Intelligent Tool Selection**
   - Track which tools work best for which queries
   - Auto-suggest tools based on query patterns
   - Learn from tool execution success rates

5. **External Tool Integration**
   - Plugin system for community tools
   - Third-party tool marketplace
   - Easy tool sharing and distribution

6. **Role-Based Tool Access**
   - Security agent gets security tools only
   - Coder agent restricted from system commands
   - Granular permission system

**Priority:** Medium (after Phase 2 stabilization)

---

### Additional Models

- DeepSeek API integration (1M free tokens/day)
- More uncensored options
- Specialized models per task

### Performance

- Model quantization
- Caching optimizations
- Parallel agent execution

---

## See Also

- [Main README](../README.md) - PKN overview
- [CLAUDE.md](../CLAUDE.md) - Development guide
- [API Documentation](API.md) - API reference
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues

---

**Questions?** Check the troubleshooting section or main documentation.
