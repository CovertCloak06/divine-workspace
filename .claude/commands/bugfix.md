Complete bug fix workflow for: $ARGUMENTS

## Step 1: Diagnose
Use the **debugger** agent to:
- Get the exact error message/symptom
- Trace to root cause
- Identify affected files and code paths

## Step 2: Assess
Is this a simple bug or a design flaw?
- Simple: Proceed to fix
- Design flaw: Use **architect** agent to plan proper fix

## Step 3: Implement
Fix the issue:
- Make minimal changes to address root cause
- Don't refactor unrelated code
- Add comments if the fix isn't obvious

## Step 4: Prevent Regression
Use the **test-writer** agent to:
- Write a test that would have caught this bug
- Verify the fix works
- Check edge cases

## Step 5: Review
Use the **code-reviewer** agent to verify:
- Fix is correct and complete
- No new issues introduced
- Code quality maintained

## Step 6: Complete
- Summarize what was wrong and how it was fixed
- Prepare commit message
