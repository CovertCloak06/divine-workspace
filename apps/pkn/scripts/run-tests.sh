#!/bin/bash
# Test Runner Script for PKN
# Provides easy commands to run different test suites

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PKN_PORT=8010
PKN_PID_FILE="/tmp/pkn-test-server.pid"

# Functions
print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

start_server() {
    print_header "Starting PKN Test Server"

    # Check if server is already running
    if [ -f "$PKN_PID_FILE" ]; then
        PID=$(cat "$PKN_PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            print_warning "Server already running (PID: $PID)"
            return 0
        fi
    fi

    # Start server in background
    echo "Starting server on port $PKN_PORT..."
    python server.py > /tmp/pkn-test-server.log 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$PKN_PID_FILE"

    # Wait for server to be ready
    echo "Waiting for server to be ready..."
    for i in {1..30}; do
        if curl -s "http://localhost:$PKN_PORT/health" > /dev/null 2>&1; then
            print_success "Server ready (PID: $SERVER_PID)"
            return 0
        fi
        sleep 1
    done

    print_error "Server failed to start within 30 seconds"
    cat /tmp/pkn-test-server.log
    exit 1
}

stop_server() {
    if [ -f "$PKN_PID_FILE" ]; then
        PID=$(cat "$PKN_PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            echo "Stopping server (PID: $PID)..."
            kill "$PID"
            rm "$PKN_PID_FILE"
            print_success "Server stopped"
        fi
    fi
}

check_dependencies() {
    print_header "Checking Dependencies"

    # Check Python
    if ! command -v python &> /dev/null; then
        print_error "Python not found"
        exit 1
    fi
    print_success "Python: $(python --version)"

    # Check pytest
    if ! python -c "import pytest" 2>/dev/null; then
        print_warning "pytest not installed. Installing..."
        pip install -r requirements-test.txt
    fi
    print_success "pytest installed"

    # Check playwright
    if ! python -c "from playwright.sync_api import sync_playwright" 2>/dev/null; then
        print_warning "playwright not installed. Installing..."
        pip install playwright
        playwright install chromium
    fi
    print_success "playwright installed"
}

run_e2e() {
    print_header "Running E2E Tests (All 8 Frontend Bugs)"

    start_server

    pytest tests/e2e/test_frontend_bugs.py \
        -v \
        --headed="${HEADED:-false}" \
        --screenshot=on \
        --video="${VIDEO:-retain-on-failure}" \
        "$@"

    TEST_EXIT=$?

    if [ "$KEEP_SERVER" != "true" ]; then
        stop_server
    fi

    return $TEST_EXIT
}

run_visual() {
    print_header "Running Visual Regression Tests"

    start_server

    pytest tests/visual/ \
        -v \
        --headed="${HEADED:-false}" \
        "$@"

    TEST_EXIT=$?

    if [ "$KEEP_SERVER" != "true" ]; then
        stop_server
    fi

    return $TEST_EXIT
}

run_performance() {
    print_header "Running Performance Tests"

    start_server

    pytest tests/performance/ \
        -v \
        -m performance \
        "$@"

    TEST_EXIT=$?

    if [ "$KEEP_SERVER" != "true" ]; then
        stop_server
    fi

    return $TEST_EXIT
}

run_all() {
    print_header "Running All Tests"

    check_dependencies
    start_server

    echo ""
    echo "1/3: E2E Tests..."
    pytest tests/e2e/ -v --headed=false

    echo ""
    echo "2/3: Visual Tests..."
    pytest tests/visual/ -v --headed=false

    echo ""
    echo "3/3: Performance Tests..."
    pytest tests/performance/ -v -m performance

    TEST_EXIT=$?

    stop_server

    if [ $TEST_EXIT -eq 0 ]; then
        print_success "All tests passed!"
    else
        print_error "Some tests failed"
    fi

    return $TEST_EXIT
}

run_lighthouse() {
    print_header "Running Lighthouse Audit"

    start_server

    if command -v lighthouse &> /dev/null; then
        lighthouse "http://localhost:$PKN_PORT" \
            --output=html \
            --output-path=./lighthouse-report.html \
            --preset=desktop \
            --only-categories=performance,accessibility,best-practices

        print_success "Lighthouse report saved to: lighthouse-report.html"

        # Open report if on desktop
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            xdg-open lighthouse-report.html 2>/dev/null || true
        fi
    else
        print_error "Lighthouse CLI not installed"
        echo "Install with: npm install -g lighthouse"
        exit 1
    fi

    if [ "$KEEP_SERVER" != "true" ]; then
        stop_server
    fi
}

update_baselines() {
    print_header "Updating Visual Baseline Screenshots"

    start_server

    pytest tests/visual/ \
        -v \
        --update-snapshots \
        --headed=false

    print_success "Baselines updated in tests/screenshots/baseline/"

    stop_server
}

show_help() {
    cat << EOF
PKN Test Runner
Usage: $0 [command] [options]

Commands:
  e2e           Run E2E tests (all 8 frontend bugs)
  visual        Run visual regression tests
  performance   Run performance tests
  all           Run all test suites
  lighthouse    Run Lighthouse performance audit
  baselines     Update visual regression baselines
  start         Start test server only
  stop          Stop test server only
  help          Show this help message

Options:
  --headed      Run tests in headed mode (show browser)
  --keep-server Don't stop server after tests
  --video       Record videos (on|off|retain-on-failure)

Examples:
  $0 e2e                    # Run E2E tests
  $0 e2e --headed           # Run E2E tests with visible browser
  $0 visual --keep-server   # Run visual tests, keep server running
  $0 all                    # Run all tests
  $0 lighthouse             # Run Lighthouse audit

Environment:
  HEADED=true     Run with visible browser
  KEEP_SERVER=true Don't stop server after tests
  VIDEO=on        Record all test videos

EOF
}

# Main
main() {
    cd "$(dirname "$0")/.."  # Go to project root

    case "${1:-help}" in
        e2e)
            shift
            run_e2e "$@"
            ;;
        visual)
            shift
            run_visual "$@"
            ;;
        performance)
            shift
            run_performance "$@"
            ;;
        all)
            shift
            run_all "$@"
            ;;
        lighthouse)
            run_lighthouse
            ;;
        baselines)
            update_baselines
            ;;
        start)
            start_server
            ;;
        stop)
            stop_server
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Parse flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --headed)
            export HEADED=true
            shift
            ;;
        --keep-server)
            export KEEP_SERVER=true
            shift
            ;;
        --video=*)
            export VIDEO="${1#*=}"
            shift
            ;;
        *)
            break
            ;;
    esac
done

main "$@"
