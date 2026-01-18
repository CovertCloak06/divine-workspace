URGENT production hotfix for: $ARGUMENTS

⚠️ **Priority: Speed + Safety. Skip polish.**

## Step 1: Diagnose FAST
Use the **debugger** agent to:
- Find root cause immediately
- Skip deep analysis
- Focus only on the breaking issue

## Step 2: Minimal Fix
Implement the smallest possible fix:
- Don't refactor
- Don't improve other things
- Just fix the bug

## Step 3: Quick Security Check
Use the **security-auditor** agent to verify:
- Fix doesn't introduce vulnerabilities
- No exposed secrets

## Step 4: Smoke Test
Use the **test-writer** agent for:
- One test proving the fix works
- One test for the most likely regression

## Step 5: Ship
- Prepare commit message noting it's a hotfix
- Document follow-up work needed

⚠️ **After deploy:** Schedule proper review with `/project:review`
