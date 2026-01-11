# @divine/scripts

Production Python scripts and utilities for Divine Node ecosystem.

## 📦 What's Included

### 1. **health_check.py** - System Health Monitoring

Comprehensive health checks for all Divine Node services.

**Usage:**
```bash
python3 scripts/health_check.py
```

**Checks:**
- ✅ PKN Server (HTTP endpoint + port 8010)
- ✅ llama.cpp (HTTP health + port 8000)
- ✅ Ollama (port 11434)
- ✅ Code Academy (port 3000)
- ✅ Process status (divinenode_server.py)

**Output:**
- Console health report with ✅/❌ status indicators
- JSON report saved to `/tmp/divine-health.json`
- Exit code 0 (healthy) or 1 (degraded)

**Use Cases:**
- Production health monitoring
- CI/CD pipeline verification
- Cron job for alerts
- Pre-deployment checks

---

### 2. **deploy.py** - Zero-Downtime Deployment

Automated deployment with rollback capability.

**Usage:**
```bash
# Full deployment (with tests)
python3 scripts/deploy.py

# Skip tests (faster)
python3 scripts/deploy.py --skip-tests

# Custom workspace
python3 scripts/deploy.py --workspace /path/to/workspace
```

**Deployment Steps:**
1. 📦 Backup current state
2. 📥 Pull latest code (`git pull`)
3. 📦 Install dependencies (`pnpm install`)
4. 🏗️ Build all apps (`just build`)
5. 🧪 Run tests (`just test`) - optional
6. 🛑 Stop services gracefully
7. 🚀 Start services
8. ✅ Verify deployment (health check)

**Features:**
- Automatic backup before deployment
- Graceful service restart
- Health verification after deployment
- Deployment logs saved to `/tmp/deployment-*.log`
- Rollback support (restore from backup)

**Use Cases:**
- Production deployments
- Staging environment updates
- Automated CI/CD pipelines

---

### 3. **backup.py** - Automated Backups

Creates comprehensive backups of Divine Node data.

**Usage:**
```bash
# Create backup (keep 5 most recent)
python3 scripts/backup.py

# Keep more backups
python3 scripts/backup.py --keep 10

# Custom workspace
python3 scripts/backup.py --workspace /path/to/workspace
```

**What's Backed Up:**
- 📁 PKN memory files (`apps/pkn/memory/`)
- 🔐 Environment variables (`apps/pkn/.env`)
- 📄 Server logs (`divinenode.log`)
- 📊 Code Academy user data
- 🌳 Git state (commit hash, branch, dirty state)

**Backup Location:**
`~/backups/divine-backup-YYYYMMDD-HHMMSS.tar.gz`

**Features:**
- Compressed tar.gz archives
- Automatic cleanup of old backups
- Git state tracking for reproducibility
- Backup metadata in JSON format

**Use Cases:**
- Daily automated backups (cron)
- Pre-deployment safety
- Disaster recovery
- Data migration

---

## 🚀 Quick Start

### Install in Monorepo

The package is already part of the monorepo workspace:

```bash
cd /home/gh0st/dvn/divine-workspace
pnpm install
```

### Run Scripts Directly

```bash
# Health check
python3 packages/divine-scripts/scripts/health_check.py

# Deploy
python3 packages/divine-scripts/scripts/deploy.py

# Backup
python3 packages/divine-scripts/scripts/backup.py
```

### Add to PATH (Optional)

```bash
# Add to ~/.bashrc
export PATH="$PATH:/home/gh0st/dvn/divine-workspace/packages/divine-scripts/scripts"

# Make scripts executable
chmod +x packages/divine-scripts/scripts/*.py

# Now you can run:
health_check.py
deploy.py
backup.py
```

---

## 📅 Recommended Cron Jobs

```bash
# Edit crontab
crontab -e

# Add these lines:

# Daily backup at 2 AM
0 2 * * * python3 /home/gh0st/dvn/divine-workspace/packages/divine-scripts/scripts/backup.py

# Health check every 5 minutes
*/5 * * * * python3 /home/gh0st/dvn/divine-workspace/packages/divine-scripts/scripts/health_check.py

# Weekly deployment (Sundays at 3 AM)
0 3 * * 0 python3 /home/gh0st/dvn/divine-workspace/packages/divine-scripts/scripts/deploy.py
```

---

## 🔧 Dependencies

All scripts use Python 3.10+ standard library, plus:

- `requests` - For HTTP health checks

**Install:**
```bash
pip3 install requests
```

---

## 📊 Integration with Monitoring

### Prometheus/Grafana

Export health check JSON to Prometheus:

```bash
# health_check.py outputs JSON to /tmp/divine-health.json
# Parse with node_exporter textfile collector
```

### Alert Manager

```bash
# In cron:
python3 health_check.py || mail -s "Divine Node Health Alert" admin@example.com < /tmp/divine-health.json
```

### Slack/Discord Webhooks

Extend `health_check.py` to send alerts:

```python
import requests

def send_alert(webhook_url, message):
    requests.post(webhook_url, json={"text": message})
```

---

## 🎯 Production Best Practices

### 1. Always Run Health Checks Before Deployment

```bash
python3 scripts/health_check.py && python3 scripts/deploy.py
```

### 2. Keep Backups Before Major Changes

```bash
python3 scripts/backup.py
# Then make changes
```

### 3. Test Deployments in Staging First

```bash
# On staging server:
python3 scripts/deploy.py --workspace /path/to/staging

# If successful, deploy to production
```

### 4. Monitor Deployment Logs

```bash
# Logs are saved to:
/tmp/deployment-YYYYMMDD-HHMMSS.log

# Review after deployment:
tail -f /tmp/deployment-*.log
```

---

## 🛠️ Extending the Scripts

### Add Custom Health Checks

Edit `health_check.py`:

```python
# Add your custom check
def check_custom_service(self):
    return self.check_http_endpoint("Custom Service", "http://localhost:9999/health")

# In run_all_checks():
self.check_custom_service()
```

### Add Pre/Post Deployment Hooks

Edit `deploy.py`:

```python
def pre_deploy_hook(self):
    """Run before deployment"""
    self.log("Running pre-deploy tasks...")
    # Your code here

def post_deploy_hook(self):
    """Run after deployment"""
    self.log("Running post-deploy tasks...")
    # Your code here

# Add to deploy():
steps.insert(0, ("Pre-Deploy", self.pre_deploy_hook))
steps.append(("Post-Deploy", self.post_deploy_hook))
```

---

## 📖 See Also

- [BUILD_TEMPLATE.md](../../BUILD_TEMPLATE.md) - Monorepo structure
- [MIGRATION_GUIDE.md](../../MIGRATION_GUIDE.md) - Project migration
- [justfile](../../justfile) - Task runner commands

---

## 📝 License

MIT - Part of the Divine Node monorepo

_Production scripts for the Divine Node ecosystem_
