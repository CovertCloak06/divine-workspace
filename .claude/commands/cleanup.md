Clean up and refactor: $ARGUMENTS

## Step 1: Assess
Use the **refactorer** agent to identify:
- Code smells
- Large files (>200 lines)
- Duplicate code
- Complex functions

## Step 2: Plan
Order changes by safety:
1. Rename things (safest)
2. Extract functions
3. Split files
4. Restructure

## Step 3: Refactor
One change at a time:
1. Make single change
2. Run tests
3. Verify behavior unchanged
4. Commit
5. Next change

## Step 4: Verify
- All tests pass
- Behavior unchanged
- Code is actually cleaner

## Step 5: Review
Use the **code-reviewer** agent to verify improvements.

## Step 6: Test Coverage
Use the **test-writer** agent to add tests if coverage dropped.
