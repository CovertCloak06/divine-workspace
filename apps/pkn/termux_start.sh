#!/data/data/com.termux/files/usr/bin/bash
# Divine Node Auto-Start Script for Termux
# Called by the Android app to start the backend

set -e

echo "🚀 Starting Divine Node backend..."

# Navigate to PKN directory
cd "$(dirname "$0")" || cd ~/pkn || exit 1

# Set environment variables
export JAVA_HOME=/data/data/com.termux/files/usr
export PATH=$JAVA_HOME/bin:$PATH

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python not installed. Please run: pkg install python"
    exit 1
fi

# Check if Flask is installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "📦 Installing Python dependencies..."
    pip install -r requirements.txt
fi

# Kill any existing server
pkill -f divinenode_server.py 2>/dev/null || true
pkill -f llama-server 2>/dev/null || true

# Start llama.cpp server (if model exists)
if [ -f llama.cpp/models/*.gguf ]; then
    echo "🤖 Starting llama.cpp server..."
    python3 -m llama_cpp.server \
        --model llama.cpp/models/*.gguf \
        --host 0.0.0.0 \
        --port 8000 \
        --chat_format qwen \
        --n_threads 4 \
        --n_ctx 2048 \
        --n_batch 256 \
        > llama.log 2>&1 &

    echo "⏳ Waiting for llama.cpp to start..."
    sleep 5
else
    echo "⚠️  No GGUF model found, skipping llama.cpp"
fi

# Start Flask server
echo "🌐 Starting Flask server..."
python3 divinenode_server.py > divinenode.log 2>&1 &

# Wait for server to be ready
echo "⏳ Waiting for Flask server..."
for i in {1..30}; do
    if curl -s http://localhost:8010/health > /dev/null 2>&1; then
        echo "✅ Backend started successfully!"
        echo "📱 Divine Node is ready at http://localhost:8010"
        exit 0
    fi
    sleep 1
done

echo "❌ Backend failed to start. Check logs:"
echo "   - divinenode.log"
echo "   - llama.log"
exit 1
