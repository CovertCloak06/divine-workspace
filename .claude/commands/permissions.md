Review authorization/permissions: $ARGUMENTS

## Step 1: Map Access
- What resources exist?
- What roles/users exist?
- Who can access what?

## Step 2: Check Enforcement
Use the **security-auditor** agent to verify:
- Every endpoint checks authorization
- Checks happen server-side
- Default is deny

## Step 3: Test Bypass
Try to access resources without proper permission:
- Remove token
- Use other user's token
- Escalate role

## Step 4: Review Logic
- Is permission logic correct?
- Are there edge cases?
- Is it consistent?

## Step 5: Fix
Address any issues found.

## Step 6: Test
Use the **test-writer** agent to add authorization tests.
