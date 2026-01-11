# PKN Quickstart Guide - Complete Reference

**For Users & AI Assistants**

Version: 1.0
Last Updated: 2026-01-02
Platform: PC (Linux) & Android (Termux)

---

## Table of Contents

1. [5-Minute Quick Start](#5-minute-quick-start)
2. [All 7 AI Agents](#all-7-ai-agents)
3. [CLI Usage](#cli-usage)
4. [Web UI Usage](#web-ui-usage)
5. [Art/Image Generation](#artimage-generation)
6. [OSINT Tools](#osint-tools)
7. [Security Agent (Uncensored)](#security-agent-uncensored)
8. [API Reference](#api-reference)
9. [Common Workflows](#common-workflows)
10. [Troubleshooting](#troubleshooting)

---

## 5-Minute Quick Start

### PC (Linux)

```bash
# 1. Start PKN services
cd /home/gh0st/pkn
./pkn_control.sh start-all

# 2. Access Web UI
firefox http://localhost:8010/pkn.html

# 3. Or use CLI
python3 pkn_cli.py
```

**Check Status:**
```bash
./pkn_control.sh status
# Should show:
# ✓ llama.cpp (port 8000)
# ✓ Flask server (port 8010)
```

### Android (Termux)

```bash
# 1. Start PKN
cd ~/pkn
./termux_start.sh

# 2. Access in browser
# Open: http://localhost:8010/pkn.html
```

---

## All 7 AI Agents

PKN uses **intelligent routing** to automatically select the best agent for your task. You can also manually select an agent from the dropdown.

### 1. **Coder Agent** 🖥️

**Best For:**
- Writing code (Python, JavaScript, Bash, etc.)
- Debugging errors and fixing bugs
- Refactoring and optimizing code
- Code reviews and explanations

**Example Queries:**
```
"Write a Python function that checks if a number is prime"
"Debug this error: TypeError: 'str' object is not callable"
"Refactor this code to use list comprehensions"
"Explain how this algorithm works"
```

**Model:** Qwen2.5-Coder-14B-Instruct (PC) / Mistral-7B (Android)
**Uncensored:** YES
**Tools:** Code analysis, file operations, syntax checking
**Speed:** ~8-15s per response

---

### 2. **Reasoner Agent** 🧠

**Best For:**
- Planning multi-step tasks
- Logical problem solving
- Analyzing trade-offs and options
- Breaking down complex problems

**Example Queries:**
```
"Plan an approach to optimize database queries"
"Analyze pros and cons of using Redis vs Memcached"
"What's the best strategy for implementing user authentication?"
"Explain the logic behind this algorithm"
```

**Model:** Qwen2.5-Coder-14B-Instruct (PC) / Mistral-7B (Android)
**Uncensored:** YES
**Tools:** Memory, planning tools
**Speed:** ~8-15s per response

---

### 3. **Researcher Agent** 🔍

**Best For:**
- Web research and documentation lookup
- Finding libraries and frameworks
- Fact-checking and information gathering
- Reading documentation

**Example Queries:**
```
"Search for the latest React documentation on hooks"
"Find information about Python's asyncio library"
"What are the current best practices for REST API design?"
"Research available Python libraries for PDF generation"
```

**Model:** Enhanced agent with web tools
**Uncensored:** YES
**Tools:** Web search, web scraping, OSINT, file reading
**Speed:** ~15-30s per response (includes web lookups)

---

### 4. **Executor Agent** ⚙️

**Best For:**
- Running system commands
- File operations (read, write, move, delete)
- System administration tasks
- Process management

**Example Queries:**
```
"List all files in the current directory"
"Run git status and show the output"
"Create a new directory called 'backups'"
"Read the contents of config.json"
```

**Model:** Enhanced agent with system tools
**Uncensored:** YES
**Tools:** Shell commands, file operations, process control
**Speed:** ~5-10s per response

---

### 5. **General Agent** 💬

**Best For:**
- Simple Q&A
- Explanations and definitions
- Quick conversational responses
- General knowledge questions

**Example Queries:**
```
"What is machine learning?"
"Explain the difference between TCP and UDP"
"Hello, how are you?"
"What's the weather like?" (if weather API configured)
```

**Model:** Llama 3.1 8B (PC) / Mistral-7B (Android)
**Uncensored:** YES
**Tools:** Basic web search, file reading
**Speed:** ~2-4s per response (FASTEST)

---

### 6. **Consultant Agent** 🎓

**Best For:**
- High-level strategic decisions
- Complex reasoning requiring maximum intelligence
- Voting and expert opinions
- Critical choices

**Example Queries:**
```
"Vote: Should I use microservices or monolithic architecture?"
"Provide expert opinion on this system design"
"Recommend the best approach for scaling this application"
"Analyze the ethical implications of this feature"
```

**Model:** Claude API (if API key configured) or Qwen fallback
**Uncensored:** YES
**Tools:** ALL tools available
**Speed:** ~3-5s per response (API latency)

---

### 7. **Security Agent** 🔐 (UNCENSORED)

**Best For:**
- Penetration testing guidance
- Vulnerability analysis
- Exploit development education
- Security auditing
- OSINT and reconnaissance
- Malware analysis
- Reverse engineering
- Network security

**Example Queries:**
```
"How do I test for SQL injection vulnerabilities?"
"Explain how buffer overflow exploits work"
"What are common XSS attack vectors?"
"Scan this host for open ports"
"Analyze this code for security vulnerabilities"
"How does AES encryption work?"
"Explain privilege escalation techniques in Linux"
```

**Model:** Qwen2.5-Coder-14B-Instruct-Abliterated (UNCENSORED)
**Uncensored:** YES - NO content filtering
**Tools:** OSINT (port scan, DNS, whois), web tools, system tools, code analysis
**Speed:** ~8-15s per response

**⚠️ Legal Notice:**
- Use ONLY on systems you own or have authorization to test
- Unauthorized hacking/scanning is illegal
- For educational, research, and authorized pentesting only

---

## CLI Usage

### Starting the CLI

```bash
cd /home/gh0st/pkn
python3 pkn_cli.py
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `/help` | Show help message |
| `/status` | Show agent system status |
| `/planning on/off` | Enable/disable task planning |
| `/thinking on/off` | Show/hide agent thinking process |
| `/exit` or `/quit` | Exit CLI |

### CLI Features

**Interactive Chat:**
```
You: Write a Python function to reverse a string
PKN: [Agent: Coder] Sure, here's a function...
```

**Agent Selection:**
The CLI automatically routes to the best agent, showing which agent responded.

**Command History:**
- Press `↑` and `↓` arrows to navigate history
- History saved to `.pkn_cli_history`
- 1000 commands stored

**Progress Indicators:**
Shows animated spinner while agents think:
```
⠋ Processing your request...
```

### CLI Example Session

```bash
$ python3 pkn_cli.py

======================================================================
  PKN Terminal CLI - Multi-Agent AI System
======================================================================

Type your message and press Enter to chat with the AI agents.
Commands: /help, /planning [on|off], /thinking [on|off], /status, /exit

You: /status

Agent System Status:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Coder Agent (Qwen2.5-Coder-14B)
✓ Reasoner Agent (Qwen2.5-Coder-14B)
✓ Researcher Agent (Enhanced)
✓ Executor Agent (Enhanced)
✓ General Agent (Llama 3.1)
✓ Consultant Agent (Claude API)
✓ Security Agent (Qwen-Abliterated)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You: Write a hello world in Python

⠋ Coder Agent thinking...

[Agent: Coder] Here's a simple Hello World program:

```python
print("Hello, World!")
```

You: /exit
Goodbye!
```

---

## Web UI Usage

### Accessing the Web UI

**PC:**
```
http://localhost:8010/pkn.html
```

**Android:**
```
http://localhost:8010/pkn.html
```

**From Another Device (same WiFi):**
```
http://YOUR_IP:8010/pkn.html
```

### Web UI Features

#### 1. **Chat Interface**

- Type messages in the input box at the bottom
- Press Enter or click Send
- Messages appear in the chat window
- Agent responses show which agent replied

#### 2. **Agent Selection**

Use the dropdown menu to select an agent:
- **Auto** - Intelligent routing (recommended)
- **Coder** - Force code agent
- **Security** - Force security agent
- **Researcher** - Force research agent
- **General** - Force general agent
- etc.

#### 3. **Art Generator Button** 🎨

Click the "Art" button in the sidebar to generate images.

**Limitations:**
- PC only (too slow on Android)
- Takes 3-5 minutes per image on CPU
- Completely private, no internet required

#### 4. **Settings Panel**

Access settings to:
- Change model parameters
- View conversation history
- Clear chat
- Export conversations
- Manage sessions

#### 5. **Agent Quality Monitor**

Shows real-time agent performance:
- Success rate per agent
- Average response time
- Error count
- Last response timestamp

#### 6. **File Upload**

Drag and drop files or click to upload:
- Code files for analysis
- Documents for processing
- Images for analysis (if supported)

#### 7. **Projects Panel**

Manage coding projects:
- Create new projects
- Switch between projects
- View project files
- Auto-save project context

---

## Art/Image Generation

### 🎨 Local AI Image Generation (100% Private)

PKN includes **Stable Diffusion 1.5** running completely locally with NO external APIs.

**Features:**
- ✅ 100% privacy - No internet required
- ✅ Uncensored - Safety filters disabled
- ✅ Unlimited generation - No API costs
- ⚠️ PC only - Too slow on Android CPU

### Using the Image Generator

#### Via Web UI:

1. Click **"Art"** button in sidebar
2. Enter your prompt: `"A cyberpunk city at night with neon lights"`
3. Click **"Generate"**
4. Wait 3-5 minutes (CPU) or 30 seconds (GPU)
5. Image appears in gallery

**Advanced Settings:**
- **Negative Prompt:** Things to avoid in image
- **Steps:** 25-50 (higher = better quality, slower)
- **Size:** 512x512 (standard), 768x768 (larger, slower)

#### Via API:

```bash
curl -X POST http://localhost:8010/api/generate-image \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "A majestic dragon flying over mountains",
    "num_inference_steps": 50,
    "width": 512,
    "height": 512
  }'
```

**Response:**
```json
{
  "image": "data:image/png;base64,iVBORw0KGgoAAAANS..."
}
```

### Image Generation Tips

**Good Prompts:**
```
"A detailed portrait of a warrior, digital art, highly detailed"
"Cyberpunk city street at night, neon signs, rain, cinematic"
"Fantasy landscape with castle, mountains, sunset, 8k"
"Sci-fi spaceship interior, futuristic, detailed, concept art"
```

**Negative Prompts (things to avoid):**
```
"blurry, low quality, distorted, ugly, bad anatomy"
"watermark, text, logo, signature"
"duplicate, multiple, cropped, out of frame"
```

**Performance:**
- **CPU (PC):** ~3-5 minutes per image @ 50 steps
- **GPU (NVIDIA):** ~30-45 seconds per image @ 50 steps
- **Android:** Disabled (use PC remotely via WiFi)

### Privacy Note

Unlike other AI image generators (DALL-E, Midjourney, Stable Diffusion online):
- ✅ Your prompts NEVER leave your machine
- ✅ No cloud uploads
- ✅ No data collection
- ✅ No content filtering (uncensored)
- ✅ No API costs

**Previous Setup (Privacy Violation - NOW FIXED):**
~~Pollinations.ai external API~~ ❌ - This was removed!

**Current Setup (Privacy Protected):**
Local Stable Diffusion 1.5 ✅ - Runs on YOUR machine!

---

## OSINT Tools

PKN includes comprehensive **Open Source Intelligence** tools for ethical reconnaissance.

### Available OSINT Tools

#### 1. **Phone Number Lookup** 📱

```bash
# Via Web UI: Click "Phone Scan" tool

# Via API:
curl -X POST http://localhost:8010/api/phonescan \
  -H "Content-Type: application/json" \
  -d '{"number": "+1-555-123-4567"}'
```

**Returns:**
- Country and region
- Carrier name
- Phone type (mobile, landline, VoIP)
- Timezone
- Formatted numbers (international, E.164)

**Example Output:**
```
Phone Number Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Number: +1-555-123-4567
Valid: ✓ Yes
Country: United States
Carrier: Verizon Wireless
Type: Mobile
Timezones: America/New_York
International: +1 555-123-4567
E.164: +15551234567
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

#### 2. **WHOIS Domain Lookup** 🌐

```python
# Via Security Agent:
"Perform WHOIS lookup on example.com"

# Via API:
curl -X POST http://localhost:8010/api/osint/whois \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Returns:**
- Domain registrar
- Creation/expiration dates
- Nameservers
- Registrant contact info
- Domain status

---

#### 3. **DNS Lookup** 🔍

```python
# Via Security Agent:
"Perform DNS lookup on google.com"

# Via API:
curl -X POST http://localhost:8010/api/osint/dns \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

**Returns:**
- A records (IPv4)
- AAAA records (IPv6)
- MX records (mail servers)
- TXT records (SPF, DKIM, etc.)
- NS records (nameservers)
- CNAME records

---

#### 4. **IP Geolocation** 🌍

```python
# Via Security Agent:
"Get geolocation for IP 8.8.8.8"

# Via API:
curl -X POST http://localhost:8010/api/osint/ip-geo \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

**Returns:**
- Country, region, city
- GPS coordinates
- ISP and organization
- Timezone
- AS number

---

#### 5. **Port Scanning** 🔌

⚠️ **WARNING: Only scan hosts you own or have authorization to test!**

```python
# Via Security Agent:
"Scan common ports on localhost"

# Via API:
curl -X POST http://localhost:8010/api/network/portscan \
  -H "Content-Type: application/json" \
  -d '{
    "host": "localhost",
    "ports": [22, 80, 443, 8080, 8010]
  }'
```

**Returns:**
- Open ports list
- Service names
- Connection time
- Closed/filtered ports

**Common Ports:**
- 22: SSH
- 80: HTTP
- 443: HTTPS
- 3306: MySQL
- 5432: PostgreSQL
- 8080: HTTP Alt
- 8010: PKN Server

---

#### 6. **Reverse DNS Lookup** 🔄

```python
# Via Security Agent:
"Perform reverse DNS on 8.8.8.8"
```

**Returns:**
- Hostname for IP address

---

#### 7. **Subdomain Enumeration** 🔎

```python
# Via Security Agent:
"Enumerate subdomains for example.com"
```

**Returns:**
- List of discovered subdomains
- Common subdomain patterns (www, mail, api, etc.)

**Note:** Basic enumeration only. For comprehensive subdomain discovery, use specialized tools like:
- subfinder
- amass
- assetfinder

---

#### 8. **Email Validation** ✉️

```python
# Via Security Agent:
"Validate email address user@example.com"
```

**Returns:**
- Format validity
- Domain MX records
- Deliverability status

---

#### 9. **Username Search** 👤

```python
# Via Security Agent:
"Search for username 'johndoe' across social media"
```

**Checks:**
- GitHub
- Twitter
- Instagram
- Reddit
- YouTube
- LinkedIn
- Facebook
- TikTok
- Pinterest
- Medium
- Dev.to
- HackerNews

**Returns:**
- Found profiles with URLs
- Not found platforms
- Total checked count

---

#### 10. **Wayback Machine Check** ⏰

```python
# Via Security Agent:
"Check Wayback Machine for example.com"
```

**Returns:**
- Archived snapshots
- Archive URLs
- Snapshot timestamps

---

#### 11. **Web Technology Detection** 🛠️

```python
# Via Security Agent:
"Detect technologies used by https://example.com"
```

**Returns:**
- Server type
- CMS (WordPress, Joomla, Drupal)
- Frameworks (React, Vue, Angular)
- Libraries (jQuery, etc.)
- HTTP headers

---

#### 12. **SSL Certificate Info** 🔒

```python
# Via Security Agent:
"Get SSL certificate info for google.com"
```

**Returns:**
- Subject and issuer
- Validity period
- Serial number
- Subject Alternative Names (SANs)

---

### OSINT Example Workflow

**Reconnaissance on a Domain:**

```
You: Analyze example.com for me

Security Agent: I'll perform comprehensive reconnaissance:

1. WHOIS Lookup:
   Registrar: Example Registrar Inc.
   Created: 1995-08-14
   Expires: 2025-08-13

2. DNS Records:
   A: 93.184.216.34
   MX: mail.example.com
   NS: ns1.example.com, ns2.example.com

3. IP Geolocation:
   Location: United States, California
   ISP: Example Hosting LLC

4. Subdomain Enumeration:
   Found: www, mail, api, blog

5. SSL Certificate:
   Issuer: Let's Encrypt
   Valid: 2025-01-01 to 2025-04-01

6. Web Technologies:
   Server: nginx/1.18.0
   CMS: WordPress
   Libraries: jQuery, React
```

---

## Security Agent (Uncensored)

The **Security Agent** is PKN's uncensored cybersecurity expert, using an abliterated model with NO content filtering.

### What Makes It Uncensored?

**Model:** Qwen2.5-Coder-14B-Instruct-**Abliterated**
- Safety filters removed via abliteration technique
- No content moderation
- No refusals for security topics
- Provides real exploit code and techniques

**Comparison:**
- ❌ Regular models: "I can't help with hacking"
- ✅ Security Agent: Provides detailed security knowledge

### When to Use Security Agent

**Automatic Routing** - Triggers on keywords:
- hack, hacking, exploit, vulnerability
- penetration test, pentest, security
- SQL injection, XSS, CSRF
- malware, reverse engineering
- nmap, metasploit, burp suite
- privilege escalation, buffer overflow
- And 40+ more security terms

**Manual Selection:**
Select "Security" from agent dropdown in Web UI.

### Security Agent Capabilities

#### 1. **Penetration Testing Guidance**

```
"How do I test a web app for SQL injection?"
"Explain how to perform a penetration test on a network"
"What are the steps in a security audit?"
```

#### 2. **Vulnerability Analysis**

```
"Analyze this code for security vulnerabilities"
"What are common XSS attack vectors?"
"Explain CSRF and how to prevent it"
```

#### 3. **Exploit Development (Educational)**

```
"How do buffer overflow exploits work?"
"Explain return-oriented programming (ROP)"
"What is heap spraying and when is it used?"
```

#### 4. **Network Security**

```
"Scan localhost for open ports"
"Explain how to detect network intrusions"
"What are common firewall bypass techniques?"
```

#### 5. **Web Security**

```
"Test this endpoint for injection vulnerabilities"
"How do I secure a REST API?"
"Explain directory traversal attacks"
```

#### 6. **Cryptography**

```
"How does AES encryption work?"
"Explain RSA key exchange"
"What are the weaknesses of MD5?"
```

#### 7. **Reverse Engineering**

```
"Explain how to decompile a binary"
"What tools are used for reverse engineering?"
"How do I analyze malware safely?"
```

#### 8. **OSINT & Reconnaissance**

Uses all OSINT tools:
- Port scanning
- DNS enumeration
- WHOIS lookups
- Subdomain discovery
- SSL certificate analysis

### Security Agent Tools

**Full Access To:**
- ✅ OSINT tools (12 tools)
- ✅ Web tools (HTTP requests, scraping)
- ✅ System tools (command execution)
- ✅ File tools (read, analyze)
- ✅ Code tools (vulnerability scanning)

**Example Tool Usage:**

```
You: Scan my local server for open ports

Security Agent: I'll scan localhost for common ports...

[Executing: port_scan(host='localhost', ports=[21,22,23,25,53,80,443,3306,8080,8010])]

Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Open Ports Found:
✓ Port 22 (SSH) - OPEN
✓ Port 80 (HTTP) - OPEN
✓ Port 8010 (PKN Server) - OPEN

Closed Ports:
✗ Port 21 (FTP) - CLOSED
✗ Port 3306 (MySQL) - CLOSED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Recommendations:
1. SSH on port 22: Ensure key-based auth is enabled
2. HTTP on port 80: Consider adding HTTPS
3. PKN Server on 8010: Only expose on trusted networks
```

### Legal & Ethical Use

⚠️ **CRITICAL:**
- Use ONLY on systems you own or have written authorization to test
- Unauthorized access, scanning, or exploitation is ILLEGAL
- For education, research, and authorized pentesting ONLY
- Respect privacy and terms of service
- Comply with all applicable laws and regulations

**Authorized Use Cases:**
- ✅ Testing your own systems
- ✅ Authorized penetration testing engagements
- ✅ CTF competitions
- ✅ Security research with permission
- ✅ Educational purposes
- ✅ Bug bounty programs (within scope)

**Unauthorized Use:**
- ❌ Hacking systems without permission
- ❌ Scanning networks you don't own
- ❌ Creating malware for malicious purposes
- ❌ Exploiting vulnerabilities for harm
- ❌ Violating computer fraud laws

---

## API Reference

PKN provides a RESTful API for all functions.

### Base URL

```
http://localhost:8010
```

### Authentication

None required for local use. For remote access, consider adding authentication.

---

### Multi-Agent Chat

**Endpoint:** `POST /api/multi-agent/chat`

**Request:**
```json
{
  "message": "Write a Python function to reverse a string",
  "mode": "auto",
  "session_id": "optional-session-id",
  "agent_override": null
}
```

**Parameters:**
- `message` (required): User message
- `mode` (optional): "auto", "coder", "security", etc. Default: "auto"
- `session_id` (optional): Session ID for conversation memory
- `agent_override` (optional): Force specific agent

**Response:**
```json
{
  "response": "Here's a function to reverse a string...",
  "agent_used": "coder",
  "task_id": "uuid-task-id",
  "metadata": {
    "agent_type": "coder",
    "confidence": 0.95,
    "tools_used": ["code_tools"],
    "execution_time": 8.2
  }
}
```

---

### Image Generation

**Endpoint:** `POST /api/generate-image`

**Request:**
```json
{
  "prompt": "A cyberpunk city at night with neon lights",
  "negative_prompt": "blurry, low quality",
  "num_inference_steps": 50,
  "width": 512,
  "height": 512
}
```

**Response:**
```json
{
  "image": "data:image/png;base64,iVBORw0KGgo..."
}
```

**Time:** 3-5 minutes on CPU, 30-45 seconds on GPU

---

### Phone Scan

**Endpoint:** `POST /api/phonescan`

**Request:**
```json
{
  "number": "+1-555-123-4567"
}
```

**Response:**
```json
{
  "number": "+1-555-123-4567",
  "valid": true,
  "country": "United States",
  "carrier": "Verizon Wireless",
  "type": "Mobile",
  "timezones": ["America/New_York"],
  "international_format": "+1 555-123-4567",
  "e164_format": "+15551234567"
}
```

---

### OSINT - WHOIS Lookup

**Endpoint:** `POST /api/osint/whois`

**Request:**
```json
{
  "domain": "example.com"
}
```

**Response:**
```json
{
  "success": true,
  "domain": "example.com",
  "registrar": "Example Registrar Inc.",
  "creation_date": "1995-08-14",
  "expiration_date": "2025-08-13",
  "nameservers": ["ns1.example.com", "ns2.example.com"]
}
```

---

### OSINT - DNS Lookup

**Endpoint:** `POST /api/osint/dns`

**Request:**
```json
{
  "domain": "google.com"
}
```

**Response:**
```json
{
  "success": true,
  "domain": "google.com",
  "records": {
    "A": ["142.250.80.46"],
    "AAAA": ["2607:f8b0:4004:c07::71"],
    "MX": ["smtp.google.com"],
    "TXT": ["v=spf1 ..."]
  }
}
```

---

### OSINT - IP Geolocation

**Endpoint:** `POST /api/osint/ip-geo`

**Request:**
```json
{
  "ip": "8.8.8.8"
}
```

**Response:**
```json
{
  "success": true,
  "ip": "8.8.8.8",
  "country": "United States",
  "city": "Mountain View",
  "isp": "Google LLC",
  "lat": 37.386,
  "lon": -122.084
}
```

---

### Port Scan

**Endpoint:** `POST /api/network/portscan`

⚠️ **Authorization Required**

**Request:**
```json
{
  "host": "localhost",
  "ports": [22, 80, 443, 8080, 8010],
  "timeout": 1.0
}
```

**Response:**
```json
{
  "host": "localhost",
  "results": [
    {"port": 22, "open": true, "rtt_ms": 0.45},
    {"port": 80, "open": true, "rtt_ms": 0.32},
    {"port": 443, "open": false, "reason": "timeout"}
  ]
}
```

---

### Health Check

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0",
  "uptime": 3600,
  "agents_available": 7
}
```

---

## Common Workflows

### Workflow 1: Code Development

**Goal:** Write, debug, and optimize code

```
Step 1: Write Initial Code
You: "Write a Python function to calculate fibonacci numbers"
Agent: Coder Agent responds with code

Step 2: Debug Issues
You: "This code throws RecursionError for large n"
Agent: Coder Agent identifies issue and fixes with memoization

Step 3: Optimize
You: "Can this be optimized further?"
Agent: Coder Agent suggests iterative approach

Step 4: Test
You: "Run this code with n=10"
Agent: Executor Agent runs code and shows output
```

---

### Workflow 2: Security Audit

**Goal:** Audit web application for vulnerabilities

```
Step 1: Reconnaissance
You: "Scan example.com for open ports and services"
Agent: Security Agent performs port scan, DNS lookup, SSL check

Step 2: Vulnerability Analysis
You: "Analyze this login form code for security issues"
Agent: Security Agent identifies SQL injection, no CSRF token

Step 3: Exploitation (Testing)
You: "Show me an example SQL injection payload for testing"
Agent: Security Agent provides payload: ' OR '1'='1

Step 4: Remediation
You: "How do I fix these vulnerabilities?"
Agent: Security Agent provides secure code examples
```

---

### Workflow 3: Research & Implementation

**Goal:** Research and implement a new feature

```
Step 1: Research
You: "Find the best Python library for PDF generation"
Agent: Researcher Agent searches and recommends ReportLab

Step 2: Planning
You: "Plan how to integrate PDF export in my Flask app"
Agent: Reasoner Agent creates step-by-step plan

Step 3: Implementation
You: "Write the code for PDF export endpoint"
Agent: Coder Agent writes Flask route with ReportLab

Step 4: Testing
You: "Test the PDF export with sample data"
Agent: Executor Agent runs test and generates PDF
```

---

### Workflow 4: OSINT Investigation

**Goal:** Gather intelligence on a domain

```
Step 1: Initial Lookup
You: "Perform WHOIS lookup on target.com"
Agent: Security Agent shows registration info

Step 2: DNS Enumeration
You: "Get all DNS records for target.com"
Agent: Security Agent shows A, MX, TXT, NS records

Step 3: Subdomain Discovery
You: "Enumerate subdomains for target.com"
Agent: Security Agent finds www, mail, api, blog

Step 4: Technology Detection
You: "What technologies does target.com use?"
Agent: Security Agent detects nginx, WordPress, React

Step 5: SSL Analysis
You: "Get SSL certificate info for target.com"
Agent: Security Agent shows cert issuer, expiry, SANs
```

---

### Workflow 5: Art Generation

**Goal:** Create AI-generated artwork

```
Step 1: Generate Image
You: Click "Art" button in Web UI
You: Enter prompt: "A dragon flying over mountains, fantasy art"
Agent: Generates 512x512 image in ~4 minutes

Step 2: Refine
You: Add negative prompt: "blurry, low quality, bad anatomy"
You: Increase steps to 50 for better quality
Agent: Generates improved image

Step 3: Variations
You: Try different prompts:
     - "Cyberpunk city at night, neon, rain"
     - "Sci-fi spaceship interior, detailed"
     - "Portrait of a warrior, digital art"

Step 4: Save
Images automatically appear in gallery
Download by right-clicking image
```

---

## Troubleshooting

### Common Issues

#### 1. **PKN Won't Start**

**Problem:** `./pkn_control.sh start-all` fails

**Solutions:**
```bash
# Check if ports are in use
lsof -i :8000
lsof -i :8010

# Kill conflicting processes
pkill -f llama_cpp
pkill -f divinenode_server

# Check logs
tail -f divinenode.log
tail -f llama.log

# Restart
./pkn_control.sh restart-all
```

---

#### 2. **LLM Server Timeout**

**Problem:** "LLM server timeout (120s)"

**Solutions:**
```bash
# Check if llama.cpp is running
./pkn_control.sh status

# Restart llama.cpp
./pkn_control.sh restart-llama

# Test direct connection
curl http://localhost:8000/v1/models

# Reduce n_gpu_layers if GPU memory full
# Edit pkn_control.sh: --n_gpu_layers 30 (instead of 45)
```

---

#### 3. **Image Generation Fails**

**Problem:** Image generation crashes or times out

**Solutions:**
```bash
# Check available RAM
free -h

# If low memory, reduce inference steps
# Use 25 steps instead of 50

# Check if Stable Diffusion is loaded
python3 -c "import local_image_gen; gen = local_image_gen.LocalImageGenerator(); gen.initialize()"

# On Android: Image gen is disabled
# Use PC and access remotely via WiFi
```

---

#### 4. **Agent Routing Wrong**

**Problem:** Wrong agent responds to query

**Solutions:**
- Use explicit agent selection from dropdown
- Use more specific keywords in query
- Add agent name to query: "Coder: write a function..."
- Check agent routing keywords in agent_manager.py

---

#### 5. **OSINT Tools Fail**

**Problem:** Port scan, DNS lookup, or WHOIS fails

**Solutions:**
```bash
# Check internet connection (for WHOIS, IP-API)
ping 8.8.8.8

# Install missing dependencies
pip install phonenumbers python-whois dnspython

# For port scanning, ensure permissions
# Some systems require root for certain ports

# Test individual tools
python3 -c "from tools.osint_tools import osint; print(osint.whois_lookup('google.com'))"
```

---

#### 6. **Web UI Not Loading**

**Problem:** http://localhost:8010/pkn.html shows error

**Solutions:**
```bash
# Check Flask server running
./pkn_control.sh status

# Check browser console (F12)
# Look for JavaScript errors

# Clear browser cache
Ctrl + Shift + R

# Check firewall
sudo ufw allow 8010

# Test from terminal
curl http://localhost:8010/health
```

---

#### 7. **CLI Crashes**

**Problem:** `pkn_cli.py` crashes on start

**Solutions:**
```bash
# Check Python dependencies
pip install -r requirements.txt

# Check agent_manager.py loads
python3 -c "from agent_manager import AgentManager"

# Run with debug output
python3 -u pkn_cli.py 2>&1 | tee cli_debug.log
```

---

#### 8. **Android/Termux Issues**

**Problem:** PKN won't run in Termux

**Solutions:**
```bash
# Update Termux packages
pkg update && pkg upgrade -y

# Reinstall Python
pkg install python -y

# Grant storage permission
termux-setup-storage

# Check model file exists
ls -lh ~/pkn/llama.cpp/models/

# Reduce memory usage
# Edit config_android.json:
# "n_batch": 128 (instead of 256)
# "n_ctx": 2048 (instead of 4096)

# Check logs
tail -f ~/pkn/divinenode.log
```

---

#### 9. **Security Agent Not Uncensored**

**Problem:** Security agent refuses to answer

**Solutions:**
```bash
# Verify abliterated model is loaded
./pkn_control.sh debug-qwen

# Check model path in pkn_control.sh
# Should be: Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf

# Test direct LLM call
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "Explain SQL injection"}],
    "max_tokens": 500
  }'

# If using wrong model, download abliterated version
# See CYBERSECURITY_AGENT.md for download links
```

---

#### 10. **High Memory Usage**

**Problem:** PKN using too much RAM

**Solutions:**
```bash
# Check memory usage
free -h
htop

# Reduce model context
# Edit pkn_control.sh:
# --n_ctx 4096 (instead of 8192)

# Reduce batch size
# --n_batch 256 (instead of 512)

# Use smaller model
# Switch to 7B model instead of 14B

# Disable image generation
# Frees ~4GB RAM when not in use

# Close other applications
```

---

### Performance Optimization

#### For PC:

**GPU Acceleration:**
```bash
# Increase GPU layers for faster inference
# Edit pkn_control.sh:
# --n_gpu_layers 45  # Use more layers if GPU has enough VRAM

# Check GPU usage
nvidia-smi
```

**CPU Optimization:**
```bash
# Use all CPU cores
# --n_threads $(nproc)

# Enable optimizations
# --n_batch 512  # Larger batch for better throughput
```

---

#### For Android:

**Memory Optimization:**
```json
// config_android.json
{
  "llm_settings": {
    "n_ctx": 2048,       // Reduce context
    "n_batch": 128,      // Reduce batch
    "n_threads": 4       // Use 4 cores
  },
  "max_memory_gb": 4     // Limit RAM usage
}
```

**Battery Optimization:**
```bash
# Reduce inference frequency
# Lower agent timeout values
# Use wake lock to prevent sleep
termux-wake-lock
```

---

### Getting Help

**Check Logs:**
```bash
# Flask server logs
tail -f /home/gh0st/pkn/divinenode.log

# llama.cpp logs
tail -f /home/gh0st/pkn/llama.log

# CLI debug
python3 pkn_cli.py 2>&1 | tee debug.log
```

**Test Components:**
```bash
# Test agent manager
python3 -c "from agent_manager import AgentManager; am = AgentManager(); print('OK')"

# Test OSINT tools
python3 -c "from tools.osint_tools import osint; print(osint.whois_lookup('google.com'))"

# Test image generation
python3 test_image_gen.sh
```

**Check System Status:**
```bash
./pkn_control.sh status
./pkn_control.sh debug-qwen
curl http://localhost:8010/health
```

---

## Additional Resources

### Documentation Files

- **COMPLETE_SYSTEM_STATUS.md** - Full system overview
- **CYBERSECURITY_AGENT.md** - Security agent guide
- **ANDROID_VS_PC_MODELS.md** - Model comparison
- **INSTALL_ANDROID.md** - Android installation
- **TRANSFER_INSTRUCTIONS.md** - Transfer methods
- **OSINT_README.md** - OSINT tools guide
- **PKN_CLI_README.md** - CLI documentation
- **CLAUDE.md** - Claude Code integration guide

### Configuration Files

- **config_pc.json** - PC configuration
- **config_android.json** - Android configuration
- **device_config.py** - Auto device detection
- **.env** - Environment variables
- **requirements.txt** - Python dependencies

### Control Scripts

- **pkn_control.sh** - Service management (PC)
- **termux_start.sh** - Startup script (Android)
- **prepare_android.sh** - Package preparation

---

## Quick Reference Card

### Essential Commands

```bash
# Start PKN (PC)
./pkn_control.sh start-all

# Start PKN (Android)
./termux_start.sh

# Check status
./pkn_control.sh status

# Access Web UI
firefox http://localhost:8010/pkn.html

# Use CLI
python3 pkn_cli.py

# View logs
tail -f divinenode.log

# Restart services
./pkn_control.sh restart-all
```

### Agent Quick Select

| Task | Agent | Keyword |
|------|-------|---------|
| Write code | Coder | "code", "function", "debug" |
| Research | Researcher | "search", "find", "docs" |
| Execute commands | Executor | "run", "execute", "list files" |
| Plan strategy | Reasoner | "plan", "analyze", "compare" |
| Security/Hacking | Security | "hack", "exploit", "vuln" |
| Simple Q&A | General | (default) |
| Expert advice | Consultant | "decide", "vote", "recommend" |

### API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/api/multi-agent/chat` | Chat with agents |
| `/api/generate-image` | Generate images |
| `/api/phonescan` | Phone number lookup |
| `/api/osint/whois` | WHOIS lookup |
| `/api/osint/dns` | DNS lookup |
| `/api/osint/ip-geo` | IP geolocation |
| `/api/network/portscan` | Port scanning |
| `/health` | Health check |

---

## System Specifications

### PC Configuration

**Model:** Qwen2.5-Coder-14B-Instruct-Abliterated
**Size:** 8.4 GB
**Format:** GGUF Q4_K_M
**Uncensored:** YES
**Context:** 8192 tokens
**GPU Layers:** 45
**RAM Required:** 12GB+

**Performance:**
- Simple queries: 2-4s
- Code generation: 8-15s
- Image generation (GPU): 30-45s
- Image generation (CPU): 3-5 min

---

### Android Configuration

**Model:** Mistral-7B-Instruct-v0.2
**Size:** 4.1 GB
**Format:** GGUF Q4_K_M
**Uncensored:** YES
**Context:** 4096 tokens
**GPU Layers:** 0 (CPU only)
**RAM Required:** 6GB+

**Performance:**
- Simple queries: 3-5s
- Code generation: 10-18s
- Image generation: Disabled (use PC remotely)

---

## Privacy & Security

### Privacy Features

✅ **100% Local Processing**
- All AI inference runs on YOUR machine
- No cloud uploads
- No external API calls (except optional consultant)
- No data collection
- No telemetry

✅ **Local Image Generation**
- Stable Diffusion runs locally
- Prompts never leave your device
- No content filtering
- No usage tracking

✅ **Uncensored Models**
- Abliterated models with safety filters removed
- No content restrictions
- Full control over responses

### Security Best Practices

🔒 **Network Security**
```bash
# Only expose on localhost
# Edit divinenode_server.py: host='127.0.0.1'

# Or use firewall
sudo ufw deny 8010
sudo ufw allow from 192.168.1.0/24 to any port 8010
```

🔒 **OSINT Tools**
- Only use on authorized targets
- Comply with local laws
- Respect terms of service
- Use responsibly

🔒 **Model Security**
- Models stored locally
- No external model downloads during use
- Verify model checksums
- Use trusted model sources

---

## Version History

**v1.0 (2026-01-02)**
- Initial quickstart guide
- Covers all 7 agents
- Complete API reference
- OSINT tools documentation
- Security agent guide
- Image generation guide
- CLI and Web UI usage
- Troubleshooting section

---

## Support

For issues, questions, or contributions:

1. Check this quickstart guide
2. Review documentation files in `/home/gh0st/pkn/`
3. Check logs: `divinenode.log`, `llama.log`
4. Test components individually
5. Review configuration files

---

**Made with PKN - 100% Private AI System** 🔐🤖
