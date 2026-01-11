# Claude API Setup Guide

**Date:** December 29, 2025
**Status:** ✅ Integration Complete

---

## What You Got

Your CONSULTANT agent now uses **Claude Sonnet 4** with access to **ALL 28 tools**!

This gives your PKN system:
- **Maximum intelligence** for complex reasoning
- **All tools available** (code editing, bash, web search, memory, etc.)
- **Automatic fallback** to local agents if API unavailable
- **Zero code changes** needed - just set one environment variable

---

## Quick Setup (3 Steps)

### Step 1: Get Your Anthropic API Key

1. Go to https://console.anthropic.com/
2. Sign up or log in
3. Navigate to **API Keys** section
4. Click **Create Key**
5. Copy your key (starts with `sk-ant-...`)

**Note:** New accounts get free credits to start!

---

### Step 2: Set Environment Variable

#### On Pop OS (your main system):

**Option A: Permanent (Recommended)**
```bash
# Add to your ~/.bashrc
echo 'export ANTHROPIC_API_KEY="sk-ant-your-key-here"' >> ~/.bashrc
source ~/.bashrc
```

**Option B: Current session only**
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

#### On Termux (Android):

```bash
# Add to ~/.bashrc
echo 'export ANTHROPIC_API_KEY="sk-ant-your-key-here"' >> ~/.bashrc
source ~/.bashrc
```

---

### Step 3: Verify It Works

```bash
cd ~/pkn
python3 -c "
from claude_api import claude_api
print('✅ Claude API available!' if claude_api.is_available() else '❌ API key not set')
"
```

**Expected output:**
```
✅ Claude API available!
```

---

## How It Works

### Automatic Routing

When you ask a question that requires expert consultation:

```
User: "Design a scalable authentication system for my app"
  ↓
PKN classifies as CONSULTANT task
  ↓
If ANTHROPIC_API_KEY is set:
  → Uses Claude Sonnet 4 with ALL 28 tools
  → Maximum intelligence + full capabilities
Else:
  → Falls back to local Reasoning agent
  → Still works, just less powerful
```

### What the CONSULTANT Agent Can Do

**With Claude API enabled:**
- ✅ Read/edit/write code files
- ✅ Execute bash commands
- ✅ Search the web
- ✅ Search documentation (GitHub, Stack Overflow, etc.)
- ✅ Manage processes
- ✅ Save context and code snippets
- ✅ Use ALL 28 tools automatically

**Without API key:**
- ⚠️ Falls back to local reasoning agent
- ⚠️ Limited tools and capabilities
- ⚠️ Still works for basic tasks

---

## Model Options

The integration uses **Claude Sonnet 4** by default (best balance of speed and intelligence).

### Available Models

| Model | Speed | Intelligence | Cost | Use Case |
|-------|-------|--------------|------|----------|
| **Claude Sonnet 4** | Fast | Very High | Medium | **Default - Best for most tasks** |
| Claude Opus 4 | Medium | Maximum | High | Complex reasoning, critical decisions |
| Claude Haiku 3.5 | Very Fast | High | Low | Simple tasks, quick responses |

### Changing the Model

Edit `/home/gh0st/pkn/agent_manager.py` line 632:

```python
# Current (Sonnet 4 - recommended):
model="claude-sonnet-4-20250514",

# For maximum intelligence (Opus 4):
model="claude-opus-4-20250514",

# For speed (Haiku):
model="claude-3-5-haiku-20241022",
```

---

## Cost Information

**Pricing (as of Dec 2025):**

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|-------|---------------------|----------------------|
| Sonnet 4 | $3 | $15 |
| Opus 4 | $15 | $75 |
| Haiku 3.5 | $0.80 | $4 |

**Typical Usage:**
- Simple question: ~500 tokens (~$0.01 with Sonnet)
- Complex task with tools: ~5,000 tokens (~$0.10 with Sonnet)
- Code review: ~10,000 tokens (~$0.20 with Sonnet)

**Budget Tips:**
1. Use Sonnet 4 for most tasks (best value)
2. Reserve Opus 4 for critical decisions only
3. Use local agents for simple tasks (no cost!)

---

## Testing the Integration

### Test 1: Verify Claude API Connection

**In PKN UI:**
```
You: "Help me plan a multi-agent system architecture"
```

**Expected:**
- Routes to CONSULTANT agent
- If API key set: Uses Claude Sonnet 4
- Provides expert-level architectural advice
- May use memory tools to save recommendations

---

### Test 2: Claude with Tools

**In PKN UI:**
```
You: "Review the code in claude_api.py and suggest improvements"
```

**Expected:**
- Uses `read_file` tool to read claude_api.py
- Analyzes code with Claude's intelligence
- Provides detailed code review
- May use `save_snippet` to store good patterns

---

### Test 3: Complex Multi-Tool Task

**In PKN UI:**
```
You: "Research Flask SSE implementations on GitHub, then implement one in our divinenode_server.py"
```

**Expected:**
- Uses `github_search` to find examples
- Uses `fetch_url` to read documentation
- Uses `read_file` to understand current server
- Uses `edit_file` to implement SSE
- Uses `save_context` to document the pattern

---

### Test 4: Fallback Verification

**Without API key set:**
```bash
unset ANTHROPIC_API_KEY
# Then ask CONSULTANT question in PKN UI
```

**Expected:**
```
⚠️ Claude API unavailable (set ANTHROPIC_API_KEY env variable)
Falling back to local reasoning agent.

[Proceeds to answer with local agent]
```

---

## Troubleshooting

### Issue: "Claude API unavailable"

**Cause:** API key not set or invalid

**Solution:**
```bash
# Check if key is set
echo $ANTHROPIC_API_KEY

# If empty or wrong, set it:
export ANTHROPIC_API_KEY="sk-ant-your-actual-key-here"

# Restart DivineNode server:
./pkn_control.sh restart-divinenode
```

---

### Issue: "anthropic package not installed"

**Solution:**
```bash
pip install anthropic
```

---

### Issue: API rate limit errors

**Solution:**
```bash
# Wait a moment between requests
# Or upgrade your Anthropic plan at console.anthropic.com
```

---

### Issue: High costs

**Solutions:**
1. Switch to Haiku for simple tasks (edit agent_manager.py line 632)
2. Use local agents more often (don't overuse CONSULTANT)
3. Set up billing alerts at console.anthropic.com
4. Cache frequently used responses in memory tools

---

## Advanced: Custom Tool Configuration

Want to limit which tools Claude can use?

Edit `/home/gh0st/pkn/agent_manager.py` line 178:

```python
elif agent_type == AgentType.CONSULTANT:
    # Current: ALL tools
    return (code_tools.TOOLS +
           file_tools.TOOLS +
           system_tools.TOOLS +
           web_tools.TOOLS +
           common_tools)

    # Custom: Only safe tools (no bash, no editing)
    return (file_tools.TOOLS +  # Read-only file ops
           web_tools.TOOLS +     # Web research
           common_tools)         # Memory
```

---

## Architecture Details

### How CONSULTANT Routes to Claude

```python
# In agent_manager.py execute_task():

if agent_config['model'] == 'claude_api':
    if claude_api.is_available():
        # Use Claude with all tools
        response, tools_used = await self._execute_claude_with_tools(...)
    else:
        # Fallback to local reasoner
        response, tools_used = await self._execute_with_tools(...)
```

### Tool Execution Loop

```
1. User asks question
2. Claude decides which tool to use
3. Agent executes tool (bash, read_file, etc.)
4. Result fed back to Claude
5. Claude decides:
   - Use another tool, OR
   - Return final answer
6. Max 5 iterations (prevents infinite loops)
```

---

## Security Notes

### API Key Safety

✅ **DO:**
- Store in environment variable (not code)
- Use `.bashrc` or secure secret manager
- Set billing limits at console.anthropic.com

❌ **DON'T:**
- Commit API key to git
- Share in screenshots or logs
- Hard-code in source files

### Tool Safety

The CONSULTANT agent can:
- ✅ Execute bash commands
- ✅ Edit files
- ✅ Access the web

**Recommendations:**
1. Review what tasks you give to CONSULTANT
2. Test in safe environment first
3. Use file backups (tools create `.bak` files automatically)
4. Monitor tool_used in responses

---

## What's Next?

### Immediate (5 mins)
1. Set ANTHROPIC_API_KEY environment variable
2. Start DivineNode server
3. Test CONSULTANT agent with a complex question

### Optional Enhancements
1. Add streaming support for real-time responses
2. Implement usage tracking and cost monitoring
3. Create specialized prompts for different domains
4. Add tool approval workflow (confirm before executing)

---

## Summary

**You now have:**
- ✅ Claude Sonnet 4 integrated as CONSULTANT agent
- ✅ Full access to all 28 tools
- ✅ Automatic fallback if API unavailable
- ✅ Cost-effective default (Sonnet 4)
- ✅ Zero friction - just set env variable

**Your PKN system can now:**
- Handle complex reasoning with Claude's intelligence
- Execute multi-step tasks with tools
- Provide expert-level advice and code review
- Fall back gracefully if API unavailable

**The CONSULTANT agent is your secret weapon for complex tasks!**

---

## Quick Reference

```bash
# Set API key (Pop OS)
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Set API key (Termux)
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Verify it works
python3 -c "from claude_api import claude_api; print(claude_api.is_available())"

# Restart server
cd ~/pkn
./pkn_control.sh restart-divinenode

# Test in UI
firefox http://localhost:8010/pkn.html
# Ask: "Help me design a scalable system architecture"
```

---

*Claude API Integration Complete - December 29, 2025*
*PKN CONSULTANT Agent: MAXIMUM POWER ACTIVATED* 🚀🧠
