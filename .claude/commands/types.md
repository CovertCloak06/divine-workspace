Fix TypeScript types: $ARGUMENTS

## Step 1: Identify Issues
Use the **type-surgeon** agent to:
- List all type errors
- Understand root causes
- Prioritize fixes

## Step 2: Fix Strategy
Order:
1. Fix root causes first (cascades)
2. Simple fixes next
3. Complex type design last

## Step 3: Fix
For each issue:
- Fix properly (not just `any`)
- Use type guards if needed
- Add utility types if helpful
- Leverage inference

## Step 4: Verify
- All errors resolved
- No new `any` added
- Types are accurate

## Step 5: Review
Use the **code-reviewer** agent to check:
- Types are meaningful
- Not over-engineered
- Consistent with codebase
