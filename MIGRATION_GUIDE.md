# 🔄 MIGRATION GUIDE - Move ALL Projects to This Monorepo

## ⚠️ MANDATORY: Migrate ALL Existing Projects

**Every project you have MUST be moved into this monorepo structure.**

## 🎯 MIGRATION PHILOSOPHY

**ONE SOURCE OF TRUTH**: After migration, the monorepo is the ONLY development location.

1. ✅ **DO**: Develop in `/home/gh0st/dvn/divine-workspace/apps/your-app/`
2. ❌ **DON'T**: Keep old locations as "active development"
3. ✅ **DO**: Archive old locations as backups
4. ❌ **DON'T**: Maintain parallel development environments
5. ✅ **DO**: Delete old locations after verification

**The monorepo has ALL the tools you need. There is NO reason to work elsewhere.**

---

## 📋 Projects That Need Migration

Based on your existing projects, these MUST be migrated:

```
/home/gh0st/pkn/                        → apps/pkn/
/home/gh0st/pkn/plugins/*               → packages/pkn-plugins/
/home/gh0st/pkn/debugger-extension/     → apps/debugger-extension/
/home/gh0st/dvn/code-academy/           → ✅ DONE (already in apps/)
```

---

## 🚀 Step-by-Step Migration

### 1. PKN (Main Application)

```bash
cd /home/gh0st/dvn/divine-workspace

# Copy PKN
cp -r /home/gh0st/pkn apps/pkn

# Remove old .git
rm -rf apps/pkn/.git

# Update package.json name
cd apps/pkn
# Edit package.json:
{
  "name": "@divine/pkn",
  ...
}

# Remove redundant tooling
rm -f Makefile Taskfile.yml tasks.py .eslintrc.json .prettierrc

# Extend shared config
# Create apps/pkn/biome.json:
{
  "extends": ["@divine/shared-config/biome.json"]
}

# Install dependencies
cd /home/gh0st/dvn/divine-workspace
pnpm install
```

### 2. PKN Plugins (as Shared Package)

```bash
cd /home/gh0st/dvn/divine-workspace

# Create package
mkdir -p packages/pkn-plugins

# Copy plugins
cp -r /home/gh0st/pkn/plugins/* packages/pkn-plugins/

# Create package.json
cd packages/pkn-plugins
cat > package.json <<'EOF'
{
  "name": "@divine/pkn-plugins",
  "version": "1.0.0",
  "description": "Shared PKN plugins",
  "main": "index.js",
  "license": "MIT"
}
EOF

# Use in PKN app
# apps/pkn/package.json:
{
  "dependencies": {
    "@divine/pkn-plugins": "workspace:*"
  }
}
```

### 3. Debugger Extension

```bash
cd /home/gh0st/dvn/divine-workspace

# Copy extension
cp -r /home/gh0st/pkn/debugger-extension apps/debugger-extension

# Remove old .git
rm -rf apps/debugger-extension/.git

# Update package.json
cd apps/debugger-extension
# Edit package.json:
{
  "name": "@divine/debugger-extension",
  ...
}

# Remove redundant tooling
rm -f Makefile .eslintrc.json .prettierrc

# Extend shared config
# Create apps/debugger-extension/biome.json:
{
  "extends": ["@divine/shared-config/biome.json"]
}
```

---

## 🧹 Cleanup Old Locations

**AFTER verifying everything works:**

```bash
# Backup old locations first
mkdir -p ~/backups/pre-monorepo-$(date +%Y%m%d)
cp -r /home/gh0st/pkn ~/backups/pre-monorepo-$(date +%Y%m%d)/
cp -r /home/gh0st/dvn/code-academy ~/backups/pre-monorepo-$(date +%Y%m%d)/

# Then remove old locations
# BE CAREFUL - ONLY AFTER BACKUP AND VERIFICATION
# rm -rf /home/gh0st/pkn
# rm -rf /home/gh0st/dvn/code-academy
```

---

## 📦 Shared Utilities Extraction

If you have code duplicated across projects, extract to packages:

```bash
# Example: Shared UI components
mkdir -p packages/shared-ui
cd packages/shared-ui
pnpm init

# Set name
{
  "name": "@divine/shared-ui",
  "version": "1.0.0"
}

# Move shared components here
# Use in apps:
{
  "dependencies": {
    "@divine/shared-ui": "workspace:*"
  }
}
```

---

## ✅ Verification Checklist

After migration:

```bash
# 1. Check structure
cd /home/gh0st/dvn/divine-workspace
tree -L 2 apps packages

# 2. Install all dependencies
pnpm install

# 3. Check all apps build
just build

# 4. Run all tests
just test

# 5. Start all dev servers
just dev

# 6. Verify shared configs work
just lint
just format
```

---

## 🎯 Final Structure Should Look Like:

```
divine-workspace/
├── apps/
│   ├── code-academy/       ✅ Done
│   ├── pkn/                ⏳ To migrate
│   └── debugger-extension/ ⏳ To migrate
├── packages/
│   ├── shared-config/      ✅ Done
│   ├── pkn-plugins/        ⏳ To create
│   ├── shared-ui/          ⏳ Optional
│   └── shared-utils/       ⏳ Optional
└── ...
```

---

## 🚨 Common Issues

### Issue: pnpm can't find workspace packages

```bash
# Solution: Run from root
cd /home/gh0st/dvn/divine-workspace
pnpm install
```

### Issue: Conflicts with old configs

```bash
# Solution: Remove old configs
rm -f apps/*/.*eslintrc* apps/*/.prettier*
# Use shared config only
```

### Issue: Different Node versions

```bash
# Solution: Use mise
mise install
# Or manually:
# Install Node 20 for all apps
```

---

## 📝 Package.json Template for Apps

```json
{
  "name": "@divine/<app-name>",
  "version": "1.0.0",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "test": "vitest",
    "lint": "biome lint src/",
    "format": "biome format --write src/",
    "format:check": "biome format src/"
  },
  "dependencies": {
    "@divine/shared-utils": "workspace:*"
  },
  "devDependencies": {
    "vite": "^5.0.10"
  }
}
```

---

## 📝 Package.json Template for Packages

```json
{
  "name": "@divine/<package-name>",
  "version": "1.0.0",
  "main": "index.js",
  "exports": {
    ".": "./index.js"
  },
  "license": "MIT"
}
```

---

## ⏰ Migration Timeline

1. **Today**: Migrate PKN and debugger-extension
2. **Verify**: Run `just ci` to ensure everything works
3. **Backup**: Create backups of old locations
4. **Clean**: Remove old standalone projects

---

## 🎯 After Migration

**ALL development happens in `/home/gh0st/dvn/divine-workspace/`**

```bash
# Never do this again:
cd /home/gh0st/pkn && npm install  ❌

# Always do this:
cd /home/gh0st/dvn/divine-workspace
just dev-app pkn  ✅
```

### Cleanup Old Locations

**After you've verified everything works, DELETE the old locations:**

```bash
# 1. Create backup archive first
mkdir -p ~/backups
tar -czf ~/backups/pre-monorepo-$(date +%Y%m%d).tar.gz \
  /home/gh0st/pkn/ \
  /home/gh0st/unexpected-keyboard-fork/ \
  /home/gh0st/dvn/code-academy/

# 2. Verify archive created
ls -lh ~/backups/pre-monorepo-*.tar.gz

# 3. DELETE old locations
rm -rf /home/gh0st/pkn/
rm -rf /home/gh0st/unexpected-keyboard-fork/
rm -rf /home/gh0st/dvn/code-academy/

# 4. Verify only monorepo remains
cd /home/gh0st/dvn/divine-workspace
ls apps/
# Should show: code-academy, pkn, debugger-extension, ghost-keys
```

**No parallel development environments. Monorepo is the ONLY source.**

---

## 📞 Need Help?

1. Read [BUILD_TEMPLATE.md](./BUILD_TEMPLATE.md)
2. Check `just health` output
3. Verify with `just ci`

---

**THIS IS NON-NEGOTIABLE. All projects MUST be in the monorepo.**

_Last updated: 2026-01-11_
