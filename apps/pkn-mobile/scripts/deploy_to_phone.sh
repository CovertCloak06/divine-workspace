#!/bin/bash
# Deploy PKN Mobile to Android phone via SSH

set -e

PHONE_IP="$1"
PHONE_USER="${2:-gh0st}"
PHONE_PORT="${3:-8022}"
DEPLOY_DIR="~/pkn-mobile"

if [ -z "$PHONE_IP" ]; then
    echo "Usage: $0 <phone-ip> [username] [port]"
    echo "Example: $0 192.168.1.100 gh0st 8022"
    exit 1
fi

echo "📱 Deploying PKN Mobile to $PHONE_USER@$PHONE_IP:$PHONE_PORT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if SSH is available
if ! command -v ssh &> /dev/null; then
    echo "❌ SSH not found. Please install openssh."
    exit 1
fi

# Check if rsync is available (faster than scp)
if command -v rsync &> /dev/null; then
    SYNC_CMD="rsync -avz --delete --exclude='.env' --exclude='data/' --exclude='__pycache__/'"
else
    SYNC_CMD="scp -r -P $PHONE_PORT"
fi

# Create directory on phone
echo "📁 Creating directory on phone..."
ssh -p "$PHONE_PORT" "$PHONE_USER@$PHONE_IP" "mkdir -p $DEPLOY_DIR"

# Sync files
echo "📤 Syncing files..."
if [ "$SYNC_CMD" = "rsync -avz --delete --exclude='.env' --exclude='data/' --exclude='__pycache__/'" ]; then
    rsync -avz --delete \
        --exclude='.env' \
        --exclude='data/' \
        --exclude='__pycache__/' \
        --exclude='.git/' \
        --exclude='*.pyc' \
        -e "ssh -p $PHONE_PORT" \
        ./ "$PHONE_USER@$PHONE_IP:$DEPLOY_DIR/"
else
    scp -r -P "$PHONE_PORT" \
        backend/ frontend/ scripts/ docs/ \
        requirements.txt package.json README.md .env.example \
        "$PHONE_USER@$PHONE_IP:$DEPLOY_DIR/"
fi

# Install dependencies on phone
echo "📦 Installing dependencies on phone..."
ssh -p "$PHONE_PORT" "$PHONE_USER@$PHONE_IP" << 'ENDSSH'
cd ~/pkn-mobile
pip install -r requirements.txt
echo "✅ Dependencies installed"
ENDSSH

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Deployment complete!"
echo ""
echo "📝 Next steps:"
echo "1. SSH to phone: ssh -p $PHONE_PORT $PHONE_USER@$PHONE_IP"
echo "2. Configure: cd ~/pkn-mobile && cp .env.example .env"
echo "3. Add API key: export OPENAI_API_KEY=sk-..."
echo "4. Run server: python backend/server.py"
echo "5. Access: http://$PHONE_IP:8010"
echo ""
echo "🔗 Or from phone browser: http://localhost:8010"
