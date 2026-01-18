Secrets audit and cleanup.

## Step 1: Scan Code
Use the **security-auditor** agent to find:
- Hardcoded API keys
- Hardcoded passwords
- Hardcoded tokens
- Connection strings

## Step 2: Check Git History
```bash
git log -p | grep -i "password\|secret\|api_key\|token" | head -100
```

## Step 3: Remediate
For each found secret:
1. **Rotate immediately** (assume compromised)
2. Move to environment variable
3. Update .env.example (without value)
4. Verify .env is in .gitignore

## Step 4: Verify
Use the **env-manager** agent to:
- Document required variables
- Verify proper configuration
- Check nothing is exposed

## Step 5: Prevent
- Add pre-commit hook to scan for secrets
- Use secret scanning tools
