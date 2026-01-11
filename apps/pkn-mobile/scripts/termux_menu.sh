#!/data/data/com.termux/files/usr/bin/bash
# PKN Mobile - Termux Launcher
# Place in ~/bin/ for easy access: pkn-mobile

PKN_DIR="$HOME/pkn-mobile"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

clear
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}           ⚡ PKN Mobile - AI Assistant                    ${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ ! -d "$PKN_DIR" ]; then
    echo -e "${YELLOW}⚠️  PKN Mobile not installed at $PKN_DIR${NC}"
    echo ""
    echo "Install now? (y/n)"
    read -r install
    if [ "$install" = "y" ]; then
        echo "Installing dependencies..."
        pkg install python openssh -y
        mkdir -p "$PKN_DIR"
        echo "Download pkn-mobile files to $PKN_DIR and run this script again."
        exit 0
    else
        exit 1
    fi
fi

cd "$PKN_DIR" || exit 1

echo -e "${GREEN}1.${NC} Start Server"
echo -e "${GREEN}2.${NC} Stop Server"
echo -e "${GREEN}3.${NC} Server Status"
echo -e "${GREEN}4.${NC} View Logs"
echo -e "${GREEN}5.${NC} Configure (edit .env)"
echo -e "${GREEN}6.${NC} Update (git pull)"
echo -e "${GREEN}7.${NC} Open in Browser"
echo -e "${GREEN}8.${NC} Exit"
echo ""
echo -n "Select option: "
read -r option

case $option in
    1)
        echo "Starting PKN Mobile..."
        if [ ! -f .env ]; then
            echo -e "${YELLOW}⚠️  .env not found. Creating from example...${NC}"
            cp .env.example .env
            echo "Please edit .env and add your OPENAI_API_KEY"
            exit 1
        fi

        # Load env vars
        export $(cat .env | xargs)

        if [ -z "$OPENAI_API_KEY" ]; then
            echo -e "${YELLOW}⚠️  OPENAI_API_KEY not set in .env${NC}"
            exit 1
        fi

        python backend/server.py &
        echo $! > .pkn.pid
        sleep 2
        echo -e "${GREEN}✅ Server started on port 8010${NC}"
        echo "Access: http://localhost:8010"
        ;;

    2)
        echo "Stopping PKN Mobile..."
        if [ -f .pkn.pid ]; then
            kill $(cat .pkn.pid) 2>/dev/null
            rm .pkn.pid
            echo -e "${GREEN}✅ Server stopped${NC}"
        else
            echo "Server not running (no .pkn.pid file)"
        fi
        ;;

    3)
        if [ -f .pkn.pid ] && kill -0 $(cat .pkn.pid) 2>/dev/null; then
            echo -e "${GREEN}✅ Server is running (PID: $(cat .pkn.pid))${NC}"
            curl -s http://localhost:8010/health | python -m json.tool
        else
            echo "Server is not running"
        fi
        ;;

    4)
        echo "Viewing logs (Ctrl+C to exit)..."
        python backend/server.py 2>&1 | tail -f
        ;;

    5)
        if command -v nano &> /dev/null; then
            nano .env
        elif command -v vim &> /dev/null; then
            vim .env
        else
            echo "No editor found. Install: pkg install nano"
        fi
        ;;

    6)
        echo "Updating PKN Mobile..."
        git pull
        pip install -r requirements.txt
        echo -e "${GREEN}✅ Updated${NC}"
        ;;

    7)
        termux-open-url http://localhost:8010
        ;;

    8)
        echo "Goodbye!"
        exit 0
        ;;

    *)
        echo "Invalid option"
        ;;
esac
