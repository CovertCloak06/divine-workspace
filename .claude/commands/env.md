Set up environment configuration.

## Step 1: Inventory
Use the **env-manager** agent to:
- List all config values needed
- Identify secrets vs non-secrets
- Define per-environment values

## Step 2: Structure
Create:
- .env.example (no secrets)
- .env.local (gitignored)
- Config loading code

## Step 3: Validate
Add config validation:
- Required vars present
- Correct types/formats
- Valid ranges

## Step 4: Document
Use the **docs-writer** agent to document:
- All variables
- Required vs optional
- How to obtain secrets
- Per-environment differences

## Step 5: Secure
Use the **security-auditor** agent to verify:
- .env in .gitignore
- No secrets in code
- No secrets in logs
