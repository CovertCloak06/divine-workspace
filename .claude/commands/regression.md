Fix regression introduced by recent change: $ARGUMENTS

## Step 1: Identify
Use the **debugger** agent to:
- What broke?
- What commit introduced it?
- What change caused it?

## Step 2: Understand
Why did the change break things?
- Was it an oversight?
- Unexpected interaction?
- Missing test coverage?

## Step 3: Decide
Options:
1. Revert the change
2. Fix forward
3. Both (revert then fix properly)

## Step 4: Implement
Apply the chosen fix.

## Step 5: Prevent
Use the **test-writer** agent to:
- Add test that catches this regression
- Ensure original feature still works
- Test the interaction that broke

## Step 6: Process Improvement
- Why wasn't this caught?
- Do we need better tests?
- Better code review?
