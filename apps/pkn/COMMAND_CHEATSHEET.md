# Command Cheat Sheet for Developers

**Last Updated:** 2026-01-12
**For:** PKN Project + General Development

---

## 📋 Table of Contents

1. [PKN-Specific Commands](#pkn-specific-commands)
2. [System & Process Management](#system--process-management)
3. [File Operations](#file-operations)
4. [Network & HTTP](#network--http)
5. [Git Commands](#git-commands)
6. [SSH & Remote](#ssh--remote)
7. [Python & Package Management](#python--package-management)
8. [Node.js & npm/pnpm](#nodejs--npmnppm)
9. [Text Processing](#text-processing)
10. [Finding & Searching](#finding--searching)

---

## PKN-Specific Commands

### Server Management

```bash
# Start all PKN services
./pkn_control.sh start-all
# What it does: Starts Flask (8010), llama.cpp (8000), Ollama (11434)

# Check what's running
./pkn_control.sh status
# What it does: Shows which services are up/down

# Stop all services
./pkn_control.sh stop-all
# What it does: Cleanly shuts down all PKN processes

# Restart everything
./pkn_control.sh restart
# What it does: Stop then start all services

# Start individual services
./pkn_control.sh start-divinenode  # Just Flask server
./pkn_control.sh start-llama       # Just llama.cpp
./pkn_control.sh start-ollama      # Just Ollama
```

### Health Checks

```bash
# Quick health check
curl http://localhost:8010/health
# What it does: Checks if Flask server responds
# Returns: {"status":"ok"} if working

# Check with more info
curl -i http://localhost:8010/health
# -i = include HTTP headers in output
# Useful for: Seeing status codes (200 = good, 500 = error)

# Silent health check (just status code)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8010/health
# -s = silent (no progress bar)
# -o /dev/null = discard response body
# -w "%{http_code}" = only show HTTP status code
# Returns: 200 (good) or 000 (not responding)
```

### Testing

```bash
# Run all tests
./scripts/run-tests.sh all
# What it does: E2E + visual + performance tests

# Run only E2E tests
./scripts/run-tests.sh e2e
# What it does: Tests all 8 frontend bugs

# Run tests with visible browser (for debugging)
./scripts/run-tests.sh e2e --headed
# --headed = show browser window (vs headless)
# Useful for: Watching tests run, debugging failures

# Run tests and keep server running
./scripts/run-tests.sh e2e --keep-server
# --keep-server = don't stop server after tests
# Useful for: Running multiple test sessions
```

### Logs

```bash
# View Flask server logs (live)
tail -f divinenode.log
# tail = show end of file
# -f = follow (keep watching for new lines)
# Exit with: Ctrl+C

# View last 50 lines of logs
tail -n 50 divinenode.log
# -n 50 = show last 50 lines

# Search logs for errors
grep ERROR divinenode.log
# grep = search for pattern
# Shows: All lines containing "ERROR"

# Search logs with context
grep -C 3 ERROR divinenode.log
# -C 3 = show 3 lines before and after match
# Useful for: Understanding what caused the error
```

---

## System & Process Management

### Finding What's Running

```bash
# Check if a port is in use
lsof -i :8010
# lsof = list open files (ports are "files" in Linux)
# -i :8010 = internet connections on port 8010
# Shows: What process is using the port

# See all Python processes
ps aux | grep python
# ps aux = show all processes
#   a = all users
#   u = user-oriented format
#   x = include processes without terminal
# | grep python = filter for lines with "python"

# See process tree (who started what)
pstree -p
# -p = show process IDs (PIDs)
# Useful for: Understanding parent/child processes

# Kill a process by port
lsof -ti :8010 | xargs kill
# -t = terse output (just PID)
# -i :8010 = port 8010
# | xargs kill = pass PID to kill command

# Force kill if it won't die
lsof -ti :8010 | xargs kill -9
# -9 = SIGKILL (force kill, can't be ignored)
# WARNING: Use only if normal kill doesn't work
```

### System Resources

```bash
# Check CPU and memory usage
htop
# Interactive process viewer
# Keys: F9=kill, F10=quit
# Install with: sudo apt install htop

# Simple CPU/memory check
top
# Built-in version (less pretty than htop)
# Exit with: q

# Check disk space
df -h
# df = disk free
# -h = human-readable (GB, MB vs bytes)

# Check folder size
du -sh /path/to/folder
# du = disk usage
# -s = summary (don't show subdirectories)
# -h = human-readable
```

---

## File Operations

### Listing Files

```bash
# Basic list
ls
# Shows: Files and folders in current directory

# List with details
ls -lh
# -l = long format (permissions, size, date)
# -h = human-readable sizes (1.2K, 5.4M vs bytes)

# List including hidden files
ls -la
# -a = all (including files starting with .)

# List newest files first
ls -lt
# -t = sort by modification time (newest first)

# List files recursively
ls -R
# -R = recursive (show subdirectories too)

# List only directories
ls -d */
# -d = directories
# */ = glob pattern for directories
```

### Copying & Moving

```bash
# Copy file
cp source.txt destination.txt
# What it does: Duplicate file

# Copy folder recursively
cp -r source_folder destination_folder
# -r = recursive (copy all contents)

# Copy and show what's being copied
cp -v source.txt destination.txt
# -v = verbose (show file names)

# Move/rename file
mv old_name.txt new_name.txt
# What it does: Rename or move file

# Move folder
mv old_folder new_folder
# No -r needed (mv works on directories by default)
```

### Deleting

```bash
# Delete file
rm file.txt
# rm = remove

# Delete folder recursively
rm -r folder
# -r = recursive (delete all contents)

# Force delete (no confirmation)
rm -rf folder
# -f = force (don't ask for confirmation)
# WARNING: Dangerous! Can't be undone!

# Safe delete (ask for confirmation)
rm -i file.txt
# -i = interactive (ask before deleting)
```

### Creating

```bash
# Create empty file
touch newfile.txt
# What it does: Creates file if it doesn't exist
# Or: Updates modification time if it does

# Create directory
mkdir newfolder
# mkdir = make directory

# Create nested directories
mkdir -p parent/child/grandchild
# -p = parents (create intermediate folders)
# Without -p: Would fail if parent doesn't exist

# Create file with content
echo "Hello World" > file.txt
# > = redirect output to file (overwrites)

# Append to file
echo "Another line" >> file.txt
# >> = append (doesn't overwrite)
```

---

## Network & HTTP

### Testing Connections

```bash
# Basic HTTP request
curl http://localhost:8010
# Shows: Response body

# Include response headers
curl -i http://localhost:8010
# -i = include headers
# Useful for: Seeing status codes, content type

# Only show headers (no body)
curl -I http://localhost:8010
# -I = HEAD request (headers only)

# Follow redirects
curl -L http://example.com
# -L = follow redirects (301, 302)
# Without -L: Shows redirect response instead

# Save response to file
curl -o output.html http://example.com
# -o = output to file
# -O = save with same filename as URL
```

### POST Requests

```bash
# Send JSON data
curl -X POST http://localhost:8010/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Hello"}'
# -X POST = use POST method
# -H = add header
# -d = data to send
# \ = line continuation (makes long commands readable)

# Send form data
curl -X POST http://example.com/form \
  -d "name=John" \
  -d "email=john@example.com"
# Multiple -d flags = multiple form fields

# Send file
curl -X POST http://localhost:8010/upload \
  -F "file=@/path/to/file.txt"
# -F = form field (multipart/form-data)
# @ = read file from path
```

### Advanced curl

```bash
# Timeout after 10 seconds
curl --max-time 10 http://slow-server.com
# --max-time = maximum time allowed

# Retry on failure
curl --retry 3 http://flaky-server.com
# --retry 3 = retry up to 3 times

# Verbose output (for debugging)
curl -v http://localhost:8010
# -v = verbose (shows full request/response)

# Silent (no progress bar)
curl -s http://localhost:8010
# -s = silent
# Useful for: Scripts, parsing output
```

### Network Info

```bash
# Check if a host is reachable
ping google.com
# Sends ICMP packets
# Exit with: Ctrl+C

# Limit ping count
ping -c 4 google.com
# -c 4 = send 4 packets then stop

# Check open ports on remote host
nc -zv localhost 8010
# nc = netcat
# -z = scan without sending data
# -v = verbose
# Shows: If port is open or closed

# Show network connections
netstat -tuln
# -t = TCP
# -u = UDP
# -l = listening
# -n = numeric (show ports as numbers, not service names)
```

---

## Git Commands

### Basic Operations

```bash
# Check status
git status
# Shows: Modified, staged, untracked files

# Stage files
git add file.txt
# Stages one file

git add .
# Stages all changes in current directory

git add -A
# Stages all changes in entire repository

# Commit changes
git commit -m "Your message here"
# -m = message (commit message)

# Commit all tracked changes (skip staging)
git commit -am "Quick fix"
# -a = all tracked files
# -m = message
# Note: Doesn't include new (untracked) files
```

### Branches

```bash
# List branches
git branch
# Shows: All local branches (* = current)

git branch -a
# -a = all (including remote branches)

# Create new branch
git branch feature-name
# Creates branch but doesn't switch to it

# Switch to branch
git checkout feature-name
# Or use newer command:
git switch feature-name

# Create and switch in one command
git checkout -b feature-name
# -b = create new branch
# Or:
git switch -c feature-name
# -c = create

# Delete branch
git branch -d feature-name
# -d = delete (safe, warns if unmerged)

git branch -D feature-name
# -D = force delete (even if unmerged)
```

### Remote Operations

```bash
# Clone repository
git clone https://github.com/user/repo.git
# Downloads entire repository

# Add remote
git remote add origin https://github.com/user/repo.git
# origin = conventional name for main remote

# List remotes
git remote -v
# -v = verbose (show URLs)

# Fetch updates from remote (doesn't merge)
git fetch origin
# Downloads new commits but doesn't change your files

# Pull updates (fetch + merge)
git pull origin main
# Downloads and merges changes from remote

# Push changes
git push origin main
# Uploads your commits to remote

# Push new branch
git push -u origin feature-name
# -u = set upstream (track this remote branch)
```

### History & Inspection

```bash
# View commit history
git log
# Shows: All commits (newest first)
# Exit with: q

# Compact log (one line per commit)
git log --oneline
# Useful for: Quick overview

# Show last 5 commits
git log -5
# -5 = limit to 5 commits

# Show changes in commit
git show abc123
# abc123 = commit hash (or use HEAD, HEAD~1, etc.)

# Show file history
git log -- file.txt
# -- = separate options from files
# Shows: All commits that touched this file

# See who changed each line
git blame file.txt
# Shows: Who wrote each line and when
```

### Undoing Changes

```bash
# Discard changes in file (restore from last commit)
git checkout -- file.txt
# -- = make sure file.txt is a file, not a branch
# Or use newer command:
git restore file.txt

# Unstage file (keep changes)
git reset file.txt
# Removes from staging area, keeps modifications
# Or:
git restore --staged file.txt

# Undo last commit (keep changes)
git reset HEAD~1
# HEAD~1 = one commit before HEAD
# Changes become unstaged

# Undo last commit (discard changes)
git reset --hard HEAD~1
# --hard = discard all changes
# WARNING: Can't undo this!

# Create new commit that undoes a previous commit
git revert abc123
# Safer than reset (doesn't rewrite history)
```

---

## SSH & Remote

### Connecting

```bash
# Basic SSH connection
ssh user@hostname
# Example: ssh john@192.168.1.100

# SSH with specific port
ssh user@hostname -p 8022
# -p = port (default is 22)

# SSH with password (non-interactive)
sshpass -p 'password' ssh user@hostname
# sshpass = provide password in command
# WARNING: Password visible in process list!
# Better: Use SSH keys

# SSH with options
ssh -o StrictHostKeyChecking=no user@hostname
# -o = option
# StrictHostKeyChecking=no = don't ask about unknown hosts
# Useful for: Scripts, automation
```

### File Transfer

```bash
# Copy file to remote
scp local_file.txt user@hostname:/remote/path/
# scp = secure copy

# Copy file from remote
scp user@hostname:/remote/file.txt local_path/

# Copy folder recursively
scp -r local_folder user@hostname:/remote/path/
# -r = recursive

# Copy with specific port
scp -P 8022 file.txt user@hostname:/path/
# -P = port (uppercase P for scp!)
# Note: SSH uses -p, SCP uses -P

# Copy using sshpass
sshpass -p 'password' scp file.txt user@hostname:/path/
```

### SSH Keys

```bash
# Generate SSH key pair
ssh-keygen -t rsa -b 4096
# -t rsa = key type (RSA)
# -b 4096 = key size (4096 bits = strong)
# Creates: ~/.ssh/id_rsa (private), ~/.ssh/id_rsa.pub (public)

# Copy public key to remote (setup passwordless login)
ssh-copy-id user@hostname
# What it does: Adds your public key to remote's authorized_keys

# SSH with specific key
ssh -i ~/.ssh/custom_key user@hostname
# -i = identity file (private key)
```

---

## Python & Package Management

### Python Basics

```bash
# Check Python version
python3 --version
# Shows: Python 3.x.x

# Run Python script
python3 script.py
# Executes script

# Run Python command directly
python3 -c "print('Hello')"
# -c = command (run code string)

# Start interactive Python
python3
# Opens Python REPL
# Exit with: exit() or Ctrl+D

# Run module as script
python3 -m http.server 8000
# -m = module
# Runs Python's built-in HTTP server on port 8000
```

### pip (Package Manager)

```bash
# Install package
pip install package-name
# Downloads and installs from PyPI

# Install specific version
pip install package-name==1.2.3
# == = exact version

# Install minimum version
pip install package-name>=1.2.0
# >= = this version or newer

# Install from requirements file
pip install -r requirements.txt
# -r = requirements file
# File contains: One package per line

# Upgrade package
pip install --upgrade package-name
# --upgrade = install newer version

# Uninstall package
pip uninstall package-name

# List installed packages
pip list
# Shows: All installed packages

# Show package info
pip show package-name
# Shows: Version, location, dependencies

# Freeze installed packages
pip freeze > requirements.txt
# freeze = output installed packages in requirements format
# > = save to file
```

### Virtual Environments

```bash
# Create virtual environment
python3 -m venv .venv
# -m venv = use venv module
# .venv = directory name (convention)

# Activate virtual environment
source .venv/bin/activate
# After this, pip/python commands use the venv

# Deactivate virtual environment
deactivate
# Returns to system Python

# Delete virtual environment
rm -rf .venv
# Just delete the folder
```

---

## Node.js & npm/pnpm

### npm Basics

```bash
# Install dependencies from package.json
npm install
# Reads package.json, installs all dependencies

# Install specific package
npm install package-name
# Adds to dependencies in package.json

# Install dev dependency
npm install --save-dev package-name
# --save-dev = only needed for development

# Install globally
npm install -g package-name
# -g = global (available system-wide)

# Uninstall package
npm uninstall package-name

# Run script from package.json
npm run script-name
# Example: npm run dev, npm run build

# Update packages
npm update
# Updates all packages within semver range

# Check for outdated packages
npm outdated
# Shows: Packages with newer versions available
```

### pnpm (Better npm)

```bash
# Install pnpm
npm install -g pnpm

# Install dependencies (faster than npm)
pnpm install
# Uses hard links, saves disk space

# Install package
pnpm add package-name

# Install dev dependency
pnpm add -D package-name
# -D = dev dependency

# Run script
pnpm run script-name
# Or just:
pnpm script-name

# Install in workspace
pnpm --filter @scope/package add dependency
# --filter = only affect specific package in monorepo
```

---

## Text Processing

### Viewing Files

```bash
# View entire file
cat file.txt
# cat = concatenate (show file contents)

# View first 10 lines
head file.txt
# head = show beginning

# View first 20 lines
head -n 20 file.txt
# -n 20 = 20 lines

# View last 10 lines
tail file.txt
# tail = show end

# View last 50 lines
tail -n 50 file.txt

# Follow file (watch for new lines)
tail -f file.txt
# -f = follow (like live logs)
# Exit with: Ctrl+C

# View file with paging
less file.txt
# Allows scrolling, searching
# Keys: Space=next page, b=previous, /=search, q=quit

# View line numbers
cat -n file.txt
# -n = number lines
```

### Searching in Files

```bash
# Search for pattern
grep "search_term" file.txt
# Shows: Lines containing "search_term"

# Case-insensitive search
grep -i "search_term" file.txt
# -i = ignore case

# Show line numbers
grep -n "search_term" file.txt
# -n = line numbers

# Show context around matches
grep -C 3 "search_term" file.txt
# -C 3 = show 3 lines before and after match
# -A 3 = after only
# -B 3 = before only

# Search recursively in directory
grep -r "search_term" /path/to/dir
# -r = recursive (search all files in directory)

# Search only specific file types
grep -r --include="*.py" "search_term" .
# --include = file pattern to search

# Exclude directories
grep -r --exclude-dir=node_modules "search_term" .
# --exclude-dir = skip this directory

# Show only filenames (not matches)
grep -l "search_term" *.txt
# -l = list filenames only

# Count matches
grep -c "search_term" file.txt
# -c = count matches

# Invert match (show lines NOT matching)
grep -v "search_term" file.txt
# -v = invert (show non-matches)
```

### Editing Text

```bash
# Replace text in file (sed)
sed 's/old/new/' file.txt
# s = substitute
# Shows result (doesn't change file)

# Replace and save (in-place)
sed -i 's/old/new/' file.txt
# -i = in-place (modify file)

# Replace all occurrences (not just first on each line)
sed 's/old/new/g' file.txt
# g = global (all matches per line)

# Replace in multiple files
sed -i 's/old/new/g' *.txt
# *.txt = all .txt files

# Find and replace with confirmation (interactive)
nano file.txt
# Then: Ctrl+\ to search/replace
# Or use vim: :%s/old/new/gc
```

---

## Finding & Searching

### Finding Files

```bash
# Find by name
find . -name "file.txt"
# . = current directory
# -name = match name exactly

# Find by pattern
find . -name "*.py"
# *.py = all Python files

# Find case-insensitive
find . -iname "*.TXT"
# -iname = ignore case

# Find directories only
find . -type d -name "folder*"
# -type d = directories only
# -type f = files only

# Find and execute command
find . -name "*.log" -delete
# -delete = delete found files
# WARNING: Be careful!

# Find and execute command (safer)
find . -name "*.log" -exec rm {} \;
# -exec = execute command
# {} = placeholder for found file
# \; = end of command

# Find modified in last 7 days
find . -mtime -7
# -mtime -7 = modified less than 7 days ago
# -mtime +7 = modified more than 7 days ago

# Find larger than 100MB
find . -size +100M
# -size +100M = larger than 100 megabytes
# -size -100M = smaller than 100 megabytes
```

### Which & Whereis

```bash
# Find location of command
which python3
# Shows: Path to python3 executable

# Find all related files
whereis python3
# Shows: Binary, source, man page locations

# Check if command exists
command -v python3
# Returns: Path if exists, nothing if not
# Useful for: Scripts (checking prerequisites)
```

---

## Pro Tips & Common Patterns

### Combining Commands (Pipes)

```bash
# Count files in directory
ls | wc -l
# | = pipe (send output to next command)
# wc -l = word count, lines

# Find and count
find . -name "*.py" | wc -l
# Counts Python files

# Sort and remove duplicates
cat file.txt | sort | uniq
# sort = alphabetical order
# uniq = remove duplicate lines

# Show top 10 largest files
du -sh * | sort -hr | head -10
# du -sh * = size of each item
# sort -hr = sort human-readable, reverse (largest first)
# head -10 = first 10 lines
```

### Command History

```bash
# Show command history
history
# Lists all previous commands

# Search command history
history | grep "git"
# Find all git commands you've run

# Re-run command by number
!123
# Runs command #123 from history

# Re-run last command
!!
# Useful for: sudo !! (run last command as sudo)

# Re-run last command starting with...
!git
# Runs most recent command starting with "git"

# Search history interactively
Ctrl+R
# Then start typing - it searches as you type
# Enter = run command
# Ctrl+R again = find next match
```

### Keyboard Shortcuts

```bash
# Ctrl+C = Cancel current command
# Ctrl+Z = Suspend current command (put in background)
# Ctrl+D = End of input / Exit shell
# Ctrl+L = Clear screen (same as `clear`)
# Ctrl+A = Move cursor to start of line
# Ctrl+E = Move cursor to end of line
# Ctrl+U = Delete from cursor to start of line
# Ctrl+K = Delete from cursor to end of line
# Ctrl+W = Delete word before cursor
# Tab = Auto-complete (file names, commands)
# Tab Tab = Show all possible completions
```

### Redirection

```bash
# Save output to file (overwrite)
command > output.txt

# Append output to file
command >> output.txt

# Redirect errors to file
command 2> errors.txt

# Redirect both output and errors
command > output.txt 2>&1
# 2>&1 = redirect stderr (2) to wherever stdout (1) goes

# Discard output
command > /dev/null
# /dev/null = black hole (discards everything)

# Discard errors
command 2> /dev/null

# Input from file
command < input.txt
# < = read input from file instead of keyboard
```

### Background Jobs

```bash
# Run command in background
command &
# & = run in background (shell prompt returns immediately)

# List background jobs
jobs
# Shows: Running background jobs

# Bring job to foreground
fg %1
# %1 = job number (from `jobs` output)

# Send current job to background
Ctrl+Z  # Suspend
bg      # Resume in background

# Kill background job
kill %1
# %1 = job number
```

---

## Quick Reference Cards

### Most Used Commands (Memorize These)

```bash
# Navigation
cd /path/to/dir      # Change directory
pwd                  # Print working directory
ls -lah              # List files (detailed, all, human-readable)

# Files
cp -r source dest    # Copy recursively
mv source dest       # Move/rename
rm -rf folder        # Delete recursively (DANGER!)
mkdir -p a/b/c       # Create nested directories

# Viewing
cat file.txt         # View file
less file.txt        # View with paging
tail -f log.txt      # Follow log file

# Searching
grep -r "term" .     # Search in files
find . -name "*.py"  # Find files

# Network
curl http://url      # HTTP request
ping hostname        # Test connectivity

# Process
ps aux | grep name   # Find process
kill PID             # Kill process
htop                 # System monitor

# Git
git status           # Check status
git add .            # Stage all
git commit -m "msg"  # Commit
git push             # Push to remote
```

### PKN Daily Commands

```bash
# Start working
cd /home/gh0st/dvn/divine-workspace/apps/pkn
./pkn_control.sh start-all

# Check status
./pkn_control.sh status
curl http://localhost:8010/health

# View logs
tail -f divinenode.log

# Run tests
./scripts/run-tests.sh e2e

# Stop when done
./pkn_control.sh stop-all
```

### Emergency Commands

```bash
# Server won't start - kill everything on port
lsof -ti :8010 | xargs kill -9

# Out of disk space - find large files
du -sh /* | sort -hr | head -10

# Something broke - restore from git
git status                    # See what changed
git restore file.txt          # Restore one file
git restore .                 # Restore everything

# Can't remember command - search history
history | grep "keyword"
Ctrl+R  # Interactive search

# System is slow - find CPU hog
htop
# Press F9 to kill process
```

---

## Learning Tips

### How to Remember All This

1. **Don't memorize everything** - Use this cheat sheet!
2. **Learn by doing** - Run commands as you read them
3. **Use `man` command** - `man curl` shows full documentation
4. **Use `--help` flag** - `curl --help` shows quick reference
5. **Practice daily commands** - You'll remember what you use
6. **Create aliases** - Add to `~/.bashrc`:
   ```bash
   alias ll='ls -lah'
   alias gs='git status'
   alias gp='git push'
   ```

### When in Doubt

```bash
# Get help for any command
man command_name         # Full manual
command_name --help      # Quick help
command_name -h          # Short help (some commands)

# Search for command by description
man -k "search term"     # Find related commands
apropos "search term"    # Same thing

# Examples of command usage
tldr command_name        # Install: pip install tldr
# Shows practical examples instead of full manual
```

---

**Last Updated:** 2026-01-12
**Next Update:** Add commands as we discover new useful variations

**Questions?** Ask anytime - I'll add the answer to this cheat sheet!
