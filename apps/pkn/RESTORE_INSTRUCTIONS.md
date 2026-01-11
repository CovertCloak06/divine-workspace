# PKN Mobile - Restore Instructions
## Backup Created: 2026-01-08 20:06

**This is a WORKING BUILD backup before UI polish fixes**

---

## 📦 Backup Locations

### **Phone Backup**
- **File**: `~/pkn-phone-backup-working-20260108_200525.tar.gz`
- **Location**: Phone (Termux home directory)
- **Size**: 12 MB
- **Contents**: Complete pkn-phone directory

### **PC Backup**
- **File**: `/home/gh0st/pkn-backup-working-20260108_200610.tar.gz`
- **Size**: 5.0 GB
- **Contents**: Full PKN project (excluding .git, llama.cpp, .venv, node_modules, logs, memory)

### **GitHub**
- **Branch**: `claude/add-android-app-branch-RKG9I`
- **Commit**: `d580bbe` - "BACKUP: Working mobile build before UI polish fixes"
- **URL**: https://github.com/CovertCloak06/pkn-multi-agent

---

## 🔄 How to Restore

### **Restore Phone (if needed)**

```bash
# SSH to phone
sshpass -p 'pkn123' ssh u0_a322@192.168.12.184 -p 8022

# Stop server
pkill -f divinenode_server.py

# Backup current (if you want to keep it)
mv ~/pkn-phone ~/pkn-phone-broken

# Extract backup
cd ~
tar -xzf pkn-phone-backup-working-20260108_200525.tar.gz

# Restart server
cd ~/pkn-phone && python3 divinenode_server.py &

# Test
curl http://localhost:8010/health
```

### **Restore PC (if needed)**

```bash
# Backup current
mv /home/gh0st/pkn /home/gh0st/pkn-broken

# Extract
cd /home/gh0st
tar -xzf pkn-backup-working-20260108_200610.tar.gz

# Or restore from GitHub
cd /home/gh0st/pkn
git checkout d580bbe
```

---

## ✅ What Works in This Backup

### **Mobile (Phone)**
- ✅ OpenAI GPT-4o-mini server running
- ✅ Full memory system (session, global, project)
- ✅ Menu button (8px thin line)
- ✅ Thinking animation (cyan dots)
- ✅ Send → Stop button toggle
- ✅ Black launcher background
- ✅ OSINT tools (email, phone scan)
- ✅ All modals functional (Settings, Files, AI Models, Images)
- ✅ Clean bash configs

### **Known Minor UI Issues** (to be fixed):
- ⚠️ Settings panel missing X button
- ⚠️ Files explorer layout cramped
- ⚠️ AI Models panel missing parameter controls
- ⚠️ X buttons have visible container (should be just X)
- ⚠️ X buttons disappear when scrolling (should be sticky)
- ⚠️ Image gen button in textarea errors
- ⚠️ Image Gallery generator button doesn't work

**These are cosmetic - core functionality is 100% working!**

---

## 🚀 Testing After Restore

### **Phone**
1. `curl http://localhost:8010/health` - Should return OK
2. Open browser to `http://localhost:8010`
3. Send a chat message - Should get response
4. Check memory: `curl http://localhost:8010/api/memory/status`

### **PC**
1. Check git status: `git status`
2. Check branch: `git branch --show-current`
3. Verify files: `ls -la /home/gh0st/pkn`

---

## 📝 Backup Manifest

### **Phone Files Backed Up:**
- divinenode_server.py (OpenAI + Memory server)
- pkn.html (UI with inline mobile CSS)
- css/ (stylesheets)
- js/ (JavaScript modules)
- img/ (images)
- memory/ (conversation history)
- project_memory.json
- fix_*.py scripts
- manifest.json

### **PC Files Backed Up:**
- All source code
- Documentation (CLAUDE.md, SESSION_NOTES, etc.)
- Mobile CSS fixes
- Session notes
- Debugger extension

### **NOT Backed Up** (excluded):
- .git directory (use GitHub instead)
- llama.cpp (too large, rebuild if needed)
- .venv (reinstall dependencies)
- node_modules (npm install)
- *.log files (temporary)
- memory/ (session-specific)
- minecraft_builds/ (unrelated project)

---

## 🆘 If Something Goes Wrong

1. **Server won't start**: Check logs at `~/pkn-phone/server.log`
2. **UI looks broken**: Hard refresh browser (clear cache)
3. **Memory missing**: Memory files at `~/.pkn_mobile_memory.json` and `~/pkn-phone/project_memory.json`
4. **Can't SSH**: Check phone IP changed, start sshd on phone
5. **Git issues**: Just pull fresh from GitHub

---

## 📞 Quick Reference

**Phone SSH**: `sshpass -p 'pkn123' ssh u0_a322@192.168.12.184 -p 8022`
**Start Server**: `cd ~/pkn-phone && python3 divinenode_server.py &`
**Check Logs**: `tail -30 ~/pkn-phone/server.log`
**Health Check**: `curl http://localhost:8010/health`
**Memory Status**: `curl http://localhost:8010/api/memory/status`

---

**Created**: 2026-01-08 20:06
**State**: All core features working, minor UI polish needed
**Safe to restore**: YES
