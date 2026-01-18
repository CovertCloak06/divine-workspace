Full security audit: $ARGUMENTS

## Step 1: Threat Model
Identify:
- What are we protecting?
- Who might attack?
- What are the attack vectors?

## Step 2: Code Review
Use the **security-auditor** agent to check:
- Authentication
- Authorization
- Input validation
- Output encoding
- Data exposure
- Injection vulnerabilities

## Step 3: Dependencies
```bash
npm audit
# or
pnpm audit
```
Review and update vulnerable packages.

## Step 4: Configuration
Use the **env-manager** agent to verify:
- No secrets in code
- Secure defaults
- No debug modes in prod

## Step 5: Report
Prioritized findings:
- 🔴 Critical (fix immediately)
- 🟠 High (fix before ship)
- 🟡 Medium (fix soon)
- 🟢 Low (fix eventually)

## Step 6: Remediate
For each finding, fix and verify.
