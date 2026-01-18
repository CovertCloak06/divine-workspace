Debug crash/exception: $ARGUMENTS

## Step 1: Get the Stack Trace
Use the **debugger** agent to:
- Capture exact error message
- Get full stack trace
- Identify crash location

## Step 2: Reproduce
- What triggers the crash?
- What inputs cause it?
- What state is required?

## Step 3: Analyze
- What line threw the exception?
- What was the unexpected condition?
- What assumption was violated?

## Step 4: Fix
Address the root cause:
- Handle the unexpected case
- Fix the bad assumption
- Add proper validation

## Step 5: Add Guards
Use the **test-writer** agent to:
- Test the crash scenario
- Add validation to prevent recurrence
- Handle similar edge cases

## Step 6: Review
Use the **code-reviewer** agent to verify:
- Fix is complete
- Error handling is appropriate
- No similar issues elsewhere
