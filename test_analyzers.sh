#!/bin/bash
# Test script for code quality analyzers

cd /home/gh0st/dvn/divine-workspace

echo "Making scripts executable..."
chmod +x apps/pkn/debugger-extension/*.py

echo ""
echo "Running code quality checks..."
python3 apps/pkn/debugger-extension/run_all_checks.py apps/pkn
