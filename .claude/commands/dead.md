Find and remove dead code.

## Step 1: Identify
Look for:
- Unused imports
- Unused variables/functions
- Unreachable code
- Commented-out code
- Deprecated features

## Step 2: Verify
For each candidate:
- Is it truly unused?
- Could it be dynamically accessed?
- Is it needed for future work?

## Step 3: Remove
For confirmed dead code:
1. Delete the code
2. Run tests
3. Build
4. Commit

## Step 4: Review
Use the **code-reviewer** agent to:
- Verify nothing broken
- Check we didn't remove too much

## Step 5: Document
Note any intentionally unused code.
