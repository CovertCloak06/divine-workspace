#!/bin/bash
# PKN System Integrity Check
# Verifies all components are present and properly configured

PKN_DIR="/home/gh0st/pkn"
cd "$PKN_DIR"

echo "========================================"
echo "PKN System Integrity Check"
echo "========================================"
echo ""

PASS=0
FAIL=0

check() {
    if [ "$2" = "exists" ]; then
        if [ -e "$1" ]; then
            echo "✅ $3"
            ((PASS++))
            return 0
        else
            echo "❌ $3 - MISSING: $1"
            ((FAIL++))
            return 1
        fi
    elif [ "$2" = "command" ]; then
        if command -v "$1" &> /dev/null; then
            echo "✅ $3"
            ((PASS++))
            return 0
        else
            echo "❌ $3 - MISSING: $1"
            ((FAIL++))
            return 1
        fi
    fi
}

echo "=== Core Files ==="
check "$PKN_DIR/divinenode_server.py" exists "DivineNode server"
check "$PKN_DIR/agent_manager.py" exists "Agent manager"
check "$PKN_DIR/conversation_memory.py" exists "Conversation memory"
check "$PKN_DIR/pkn_control.sh" exists "Control script"
check "$PKN_DIR/pkn-cli" exists "CLI launcher"
check "$PKN_DIR/pkn_cli.py" exists "CLI application"

echo ""
echo "=== Web Files ==="
check "$PKN_DIR/pkn.html" exists "Main HTML"
check "$PKN_DIR/app.js" exists "Main JavaScript"
check "$PKN_DIR/css/main.css" exists "Main CSS"
check "$PKN_DIR/css/multi_agent.css" exists "Multi-agent CSS"
check "$PKN_DIR/css/file-explorer.css" exists "File explorer CSS"
check "$PKN_DIR/css/osint.css" exists "OSINT CSS"

echo ""
echo "=== JavaScript Modules ==="
check "$PKN_DIR/js/files.js" exists "File manager"
check "$PKN_DIR/js/osint_ui.js" exists "OSINT UI"
check "$PKN_DIR/js/multi_agent_ui.js" exists "Multi-agent UI"
check "$PKN_DIR/js/chat.js" exists "Chat module"
check "$PKN_DIR/js/autocomplete.js" exists "Autocomplete module"

echo ""
echo "=== Tools ==="
check "$PKN_DIR/tools/code_tools.py" exists "Code tools"
check "$PKN_DIR/tools/file_tools.py" exists "File tools"
check "$PKN_DIR/tools/web_tools.py" exists "Web tools"
check "$PKN_DIR/tools/osint_tools.py" exists "OSINT tools"
check "$PKN_DIR/tools/memory_tools.py" exists "Memory tools"

echo ""
echo "=== System Dependencies ==="
check "python3" command "Python 3"
check "curl" command "curl"
check "git" command "git"

echo ""
echo "=== Python Dependencies ==="
if [ -d "$PKN_DIR/.venv" ]; then
    source "$PKN_DIR/.venv/bin/activate"
    python3 -c "import flask" 2>/dev/null && echo "✅ Flask installed" && ((PASS++)) || (echo "❌ Flask missing" && ((FAIL++)))
    python3 -c "import whois" 2>/dev/null && echo "✅ python-whois installed" && ((PASS++)) || (echo "❌ python-whois missing" && ((FAIL++)))
    python3 -c "import dns" 2>/dev/null && echo "✅ dnspython installed" && ((PASS++)) || (echo "❌ dnspython missing" && ((FAIL++)))
    python3 -c "from langchain_core.tools import Tool" 2>/dev/null && echo "✅ LangChain core installed" && ((PASS++)) || (echo "❌ LangChain core missing" && ((FAIL++)))
else
    echo "⚠️  Virtual environment not found"
    ((FAIL++))
fi

echo ""
echo "=== Service Status ==="
if pgrep -f divinenode_server.py > /dev/null; then
    echo "✅ DivineNode running"
    ((PASS++))
else
    echo "❌ DivineNode not running"
    ((FAIL++))
fi

if pgrep -f llama-server > /dev/null || pgrep -f "llama.cpp" > /dev/null; then
    echo "✅ llama.cpp running"
    ((PASS++))
else
    echo "⚠️  llama.cpp not running (optional)"
fi

echo ""
echo "=== Documentation ==="
check "$PKN_DIR/README.md" exists "Main README"
check "$PKN_DIR/OSINT_README.md" exists "OSINT README"
check "$PKN_DIR/PKN_CLI_README.md" exists "CLI README"

echo ""
echo "========================================"
echo "Results: $PASS passed, $FAIL failed"
echo "========================================"

if [ $FAIL -eq 0 ]; then
    echo "✅ All checks passed! System is ready."
    exit 0
else
    echo "⚠️  Some checks failed. Review above for details."
    exit 1
fi
