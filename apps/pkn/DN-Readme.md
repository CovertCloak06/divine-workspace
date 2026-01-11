# Parakleon: Local AI Agent for Software Development

Parakleon is a master local AI agent built on **Qwen2.5-Coder (14B)** via `llama.cpp`, with tool use, persistent memory, and self-improvement capabilities. It runs entirely on your machine and is designed to assist with code writing, debugging, system administration, and continuous self-evolution.

---

`Features`

- **Local Execution**: Runs on your hardware with no external API calls for the LLM.
- **Tool Use**: File reading/writing, command execution, web access, persistent memory.
- **Persistent Memory**: Global and project-specific memory allows cross-session learning.
- **Self-Improvement**: Can analyze and refactor its own code and prompts.
- **Natural Conversation**: Human-readable, concise responses optimized for developer workflows.
- **Dual Interface**: CLI for quick tasks, HTTP API for integration with your UI.

---

`Build Requirements`

### Hardware

- **Minimum**: 8GB RAM (for 14B Q4_K_M quantized model)
- **Recommended**: 16GB+ RAM, GPU acceleration (optional but faster)

### Software

- **Python**: 3.10+
- **Operating System**: Linux (Pop!_OS, Ubuntu), macOS, or Windows (WSL2)
- **Virtual Environment**: venv or conda

---

## Dependencies

All dependencies are in `requirements.txt`:

langchain==0.1.11
langchain-openai==0.1.3
fastapi==0.109.0
uvicorn[standard]==0.27.0
requests==2.31.0
pydantic==2.5.3

text

Install with:

cd /home/gh0st/pkn
source .venv/bin/activate
pip install -r requirements.txt

text

### Additional Requirements

- **llama.cpp server** (via `llama-cpp-python[server]`):

pip install "llama-cpp-python[server]"

text

- **GGUF Model**: Download Qwen2.5-Coder 14B Q4_K_M quantized from [Hugging Face](https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct-GGUF).

---

`Installation & Setup`

### 1. Clone or organize your project

mkdir -p /home/gh0st/pkn
cd /home/gh0st/pkn

text

### 2. Create and activate virtual environment

python3 -m venv .venv
source .venv/bin/activate

text

### 3. Install dependencies

pip install -r requirements.txt
pip install "llama-cpp-python[server]"

text

### 4. Download model

Download Qwen2.5-Coder-14B-Instruct-GGUF (Q4_K_M) and place it at:

/home/gh0st/pkn/llama.cpp/models/Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf

text

### 5. Create memory files

**Global memory** (`~/.parakleon_memory.json`):

{
"user_name": "Gh0st",
"preferences": {
"ui_style": "dark cyberpunk",
"response_style": "concise, conversational"
},
"notes": [
"Parakleon is my local AI coding agent."
]
}

text

**Project memory** (`/home/gh0st/pkn/pkn_memory.json`):

{
"project_name": "Divine Node / Parakleon",
"notes": ["UI style: dark cyberpunk."]
}

text

### 6. Copy scripts

Place these files in `/home/gh0st/pkn`:

- `local_parakleon_agent.py` (main agent)
- `parakleon_api.py` (FastAPI backend)
- `start_parakleon.sh` (startup script)
- `requirements.txt` (dependencies)
- `README.md` (this file)

---

` Usage`

### Quick Start (One Command)

Start all services with:

cd /home/gh0st/pkn
./start_parakleon.sh

text

This will:

1. Activate your virtual environment.
2. Start `llama.cpp` server on port 8000.
3. Start FastAPI backend on port 9000.
4. Display ready indicators.

### CLI Usage

Once services are running, use Parakleon from the command line:

cd /home/gh0st/pkn
source .venv/bin/activate
python3 local_parakleon_agent.py

text

**Example instructions:**

Read global and project memory. Then list files in /home/gh0st/pkn, read pkn.html,
and propose specific code changes to improve the UI with dark cyberpunk aesthetics.

text

### API Usage

Call the HTTP API endpoint:

curl -X POST http://127.0.0.1:9000/agent
-H "Content-Type: application/json"
-d '{"instruction": "List the files in /home/gh0st/pkn and describe the project."}'

text

**JavaScript example** (for your Divine Node UI):

async function askParakleon(instruction) {
const response = await fetch("http://127.0.0.1:9000/agent", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ instruction }),
});
const data = await response.json();
return data.output;
}

// Usage
const answer = await askParakleon("Analyze the Divine Node UI and suggest improvements.");
console.log(answer);

text

---

## Self-Improvement Mode

Ask Parakleon to improve its own code and prompts:

Self-analysis and improvement task:

    Read global and project memory.

    Read your own local_parakleon_agent.py file.

    Analyze your system prompt, tools, and flow for friction points or missed opportunities.

    Propose improvements to:

        Your system prompt (clarity, style, safety).

        Your tool set (new tools, better safety checks).

        Your agent loop (error handling, efficiency).

    After explaining changes, use write_file_with_backup to update local_parakleon_agent.py.

Be explicit about what changed and why.

text

The agent will create a `.bak` backup before overwriting, so you can always rollback.

---

`Memory Structure`

### Global Memory (`~/.parakleon_memory.json`)

Used across all projects. Stores:

- User preferences (style, editing policy).
- Cross-project facts (common patterns, workflows).
- Long-term preferences (response style, tone).

### Project Memory (`/home/gh0st/pkn/pkn_memory.json`)

Project-specific. Stores:

- Project name and type.
- Key file paths and entry points.
- Project-specific notes and decisions.
- Analysis history.

---

`Troubleshooting`

### llama.cpp Server won't start

**Error**: `Error while finding module specification for 'llama_cpp.server'`

**Solution**: Install the server extra:

pip install "llama-cpp-python[server]"

text

### Port already in use

**Error**: `Address already in use` on port 8000 or 9000

**Solution**: The `start_parakleon.sh` script auto-kills existing processes. If manual:

Kill llama.cpp (8000)

fuser -k 8000/tcp
Kill API (9000)

fuser -k 9000/tcp

text

### Model not found

**Error**: `Model path does not exist`

**Solution**: Verify the model is at the correct path:

ls /home/gh0st/pkn/llama.cpp/models/Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf

text

If missing, download from [Hugging Face](https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct-GGUF).

### API returns 500 error

Check that:

1. llama.cpp server is running: `curl http://127.0.0.1:8000/v1/models`
2. API server is running: `curl http://127.0.0.1:9000/health`
3. Model name matches: check `LLAMA_MODEL_NAME` in `local_parakleon_agent.py`

---

`Next Steps`

1. **Integrate with Divine Node UI**: Call `/agent` endpoint from your frontend.
2. **Add streaming**: Modify `parakleon_api.py` to use `SSE` or websockets for live output.
3. **Expand memory**: Store analysis results, common fixes, and project wisdom over time.
4. **Custom tools**: Add project-specific tools (git integration, test runners, etc.).

---

`License`

Local project. Use freely within your environment.

---

**Created**: December 20, 2025  
**Status**: Production-ready  
**Maintained by**: Gh0st (user)

7. requirements.txt

text
langchain==0.1.11
langchain-openai==0.1.3
fastapi==0.109.0
uvicorn[standard]==0.27.0
requests==2.31.0
pydantic==2.5.3
llama-cpp-python[server]==0.2.50

`How to Use Everything`
Step 1: Create/update files

Save all scripts above to /home/gh0st/pkn/:

bash
cd /home/gh0st/pkn

# Replace old agent
# Copy local_parakleon_agent.py (above)

# Copy new API
# Copy parakleon_api.py (above)

# Copy startup script
# Copy start_parakleon.sh (above)
chmod +x start_parakleon.sh

# Copy requirements
# Copy requirements.txt (above)

# Update memory
# Create/update ~/.parakleon_memory.json (above)
# Create/update pkn_memory.json (above)

# Copy README
# Copy README.md (above)

Step 2: Install dependencies

bash
source .venv/bin/activate
pip install -r requirements.txt

Step 3: Start everything

bash
./start_parakleon.sh

Step 4: Use it

    CLI: python3 local_parakleon_agent.py

    API: curl -X POST http://127.0.0.1:9000/agent ...

    UI: Call the API endpoint from your Divine Node frontend

That's it. Parakleon is now a complete, self-improving local agent with persistent memory, tool use, and both CLI and HTTP interfaces.
