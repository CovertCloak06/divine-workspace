# PKN Terminal CLI

**Interactive command-line interface for PKN multi-agent system**

A Claude-like terminal experience for interacting with your AI agents.

---

## Features

### ✅ Interactive Terminal
- Readline support (command history, arrow keys)
- Persistent command history (`.pkn_cli_history`)
- Tab completion
- Color-coded output

### ✅ Multi-Agent Integration
- Automatic agent routing (Coder, Reasoner, Researcher, Executor, General, Consultant)
- Shows which agent handled your request
- Displays tools used
- Execution time tracking

### ✅ Conversation Memory
- Session persistence
- Context-aware responses
- Full conversation history

### ✅ Visual Feedback
- Animated progress indicators
- Color-coded responses
- Agent badges (💻 Coder, 🧠 Reasoner, 🔍 Researcher, etc.)
- Execution metrics

### ✅ Planning Mode (Future)
- Automatic planning for complex tasks
- Step-by-step execution
- Progress tracking

---

## Quick Start

### Start CLI
```bash
# From PKN directory
./pkn-cli

# Or via control script
./pkn_control.sh cli

# Or directly
python3 pkn_cli.py
```

### Basic Usage
```
You » What is Python?
💬 General Assistant (2.3s)

Python is a high-level, interpreted programming language...
```

### Commands
```
You » /help              Show available commands
You » /status            Show system status
You » /planning on       Enable planning mode
You » /thinking off      Hide thinking process
You » /clear             Clear screen
You » /exit              Exit CLI
```

---

## Examples

### Simple Query
```bash
You » what is recursion?

💬 General Assistant (1.8s)
└─ Tools: none

Recursion is a programming technique where a function calls
itself to solve a problem by breaking it down into smaller
instances of the same problem...
```

### Code Request
```bash
You » write a python function to check if a number is prime

💻 Qwen Coder (5.2s)
└─ Tools: code_generation

Here's a function to check if a number is prime:

```python
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True
```

This function efficiently checks primality using trial division
with optimization for small numbers and multiples of 2 and 3.
```

### File Operations
```bash
You » list all python files in this project

⚙️ Executor Agent (0.8s)
└─ Tools: file_search, list_files

Found 14 Python files:
- agent_manager.py (56KB)
- divinenode_server.py (68KB)
- conversation_memory.py (14KB)
- code_context.py (16KB)
- pkn_cli.py (12KB)
...
```

### Research Query
```bash
You » what's the latest news about AI?

🔍 Research Agent (12.5s)
└─ Tools: web_search, web_fetch

Here's what I found about recent AI developments:

1. OpenAI released GPT-4 Turbo with improved capabilities...
2. Google announced Gemini 1.5 with 1M token context...
3. Anthropic released Claude 3 family with vision...
```

---

## Commands Reference

### Chat Commands

| Command | Description |
|---------|-------------|
| `/help` | Show help message with all commands |
| `/status` | Show system status, services, and agent stats |
| `/planning on\|off` | Enable/disable planning mode for complex tasks |
| `/thinking on\|off` | Show/hide agent thinking process |
| `/clear` | Clear terminal screen |
| `/exit`, `/quit`, `/q` | Exit PKN CLI |

### Command-Line Options

```bash
pkn-cli [options]

Options:
  --project-root PATH    Use custom project directory
  --no-planning          Disable planning mode
  --no-thinking          Hide thinking process
  -h, --help            Show help and exit
```

---

## Visual Features

### Color Coding

- **Cyan** - System messages, headers
- **Green** - Success messages, user prompt
- **Yellow** - Warnings, agent badges
- **Red** - Errors
- **Gray** - Metadata, timestamps
- **Bold** - Agent names, emphasis

### Agent Badges

- 💻 **Coder** - Code-related tasks
- 🧠 **Reasoner** - Logical reasoning, planning
- 🔍 **Researcher** - Web searches, research
- ⚙️ **Executor** - System commands
- 💬 **General** - Quick Q&A
- 🎓 **Consultant** - Complex decisions (external LLM)

### Progress Indicators

```
⠋ Initializing PKN...
⠙ Loading agent manager...
⠹ Setting up conversation memory...
✓ PKN initialized
```

---

## Session Management

### Command History

All commands are saved to `.pkn_cli_history` and can be accessed with arrow keys:
- **↑** Previous command
- **↓** Next command
- **Ctrl+R** Search history (if readline available)

### Conversation Context

The CLI maintains conversation context throughout your session:
```bash
You » what is python?
💬 Python is a programming language...

You » give me an example
💻 [Continues from previous context]
```

### Session Info

Each CLI session gets a unique ID for tracking:
```bash
You » /status

System Status:
  Session ID: a7b3c2d1...
  Planning Mode: Enabled
  Show Thinking: Yes
```

---

## Advanced Usage

### Planning Mode (Future Enhancement)

For complex tasks, enable planning mode:
```bash
You » /planning on
✓ Planning mode enabled

You » refactor the authentication system to use JWT tokens

📋 Creating execution plan...

Plan (6 steps):
  1. Analyze current authentication implementation
  2. Design JWT token structure
  3. Implement JWT encoding/decoding
  4. Update login endpoint
  5. Add token validation middleware
  6. Test authentication flow

Executing plan...
[Progress indicators for each step]
```

### Thinking Process

Show agent's reasoning with `/thinking on`:
```bash
You » /thinking on
✓ Showing thinking process

You » optimize this database query

💭 Thinking...
└─ Analyzing query structure...
└─ Identifying bottlenecks...
└─ Considering indexes...
└─ Evaluating JOIN performance...

💻 Qwen Coder (8.2s)
...
```

---

## Keyboard Shortcuts

### Navigation
- **↑/↓** - Command history
- **←/→** - Move cursor
- **Home/End** - Start/end of line
- **Ctrl+A** - Beginning of line
- **Ctrl+E** - End of line

### Editing
- **Backspace** - Delete character before cursor
- **Delete** - Delete character at cursor
- **Ctrl+K** - Delete from cursor to end of line
- **Ctrl+U** - Delete entire line

### Control
- **Ctrl+C** - Interrupt (doesn't exit, use /exit)
- **Ctrl+D** - Exit (EOF)
- **Ctrl+L** - Clear screen

---

## Comparison: Web UI vs Terminal CLI

| Feature | Web UI | Terminal CLI |
|---------|--------|--------------|
| **Interface** | Visual, buttons, forms | Text-based, commands |
| **Access** | Browser required | Terminal only |
| **Speed** | Click through UI | Direct commands |
| **Scripting** | No | Yes (can be automated) |
| **Mobile** | Yes (responsive) | Yes (SSH) |
| **History** | Session-based | Persistent file |
| **Copy/Paste** | Mouse-based | Terminal-native |
| **Multitasking** | Tabs | Tmux/screen |

**Use Web UI when:**
- You want visual feedback
- Working with images
- Prefer clicking over typing
- Need file browser

**Use Terminal CLI when:**
- You live in the terminal
- Want fast, keyboard-driven workflow
- Need to script/automate
- SSH into remote server
- Prefer minimal, distraction-free interface

---

## Troubleshooting

### "Failed to initialize"
```bash
# Check services are running
./pkn_control.sh status

# Start services if needed
./pkn_control.sh start-all
```

### "No module named 'readline'"
Readline is optional but recommended:
```bash
# On Ubuntu/Debian
sudo apt-get install python3-readline

# On macOS (usually included)
# On other systems, basic input still works
```

### "Connection refused"
```bash
# Make sure DivineNode is running
curl http://localhost:8010/health

# Restart if needed
./pkn_control.sh restart-divinenode
```

### Slow responses
```bash
# Check llama.cpp is running
./pkn_control.sh debug-qwen

# Check system load
htop  # or top
```

---

## Development

### Structure

```python
pkn_cli.py
├── Colors          # ANSI color codes
├── ProgressIndicator  # Animated spinners
└── PKNCLI          # Main CLI class
    ├── initialize()       # Setup agents
    ├── handle_message()   # Process user input
    ├── show_status()      # Display status
    └── run()             # Main loop
```

### Extending

Add new commands by modifying the command handler in `run()`:
```python
elif cmd == 'yourcommand':
    # Your command logic here
    print(f"{Colors.GREEN}Command executed{Colors.RESET}")
```

---

## Tips & Tricks

### Quick Start Alias
```bash
# Add to ~/.bashrc or ~/.zshrc
alias pkn='cd /home/gh0st/pkn && ./pkn-cli'

# Then just type:
pkn
```

### Run in Background with Screen
```bash
screen -S pkn
./pkn-cli
# Ctrl+A, D to detach
# screen -r pkn to reattach
```

### Combine with Other Tools
```bash
# Generate code and save to file
echo "write a fibonacci function in python" | ./pkn-cli > fib.py
```

---

## Future Enhancements

### Planned Features
- [ ] Tool chain visualization
- [ ] Multi-line input mode
- [ ] Syntax highlighting for code
- [ ] Export conversation to markdown
- [ ] Voice input/output
- [ ] Image display (iTerm2, kitty)
- [ ] Autocomplete for commands and agents

### Configuration File
Future: `~/.pknrc` for custom settings:
```yaml
planning_mode: on
show_thinking: yes
default_agent: coder
color_scheme: dracula
```

---

## Support

**Issues**: Report bugs to the PKN issue tracker
**Documentation**: See main PKN README
**Logs**: Check `~/.pkn_cli_history` for command history

---

**Enjoy your Claude-like terminal experience!** 🚀
