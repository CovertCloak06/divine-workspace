Build new feature: $ARGUMENTS

## Step 1: Clarify Requirements
If vague, use the **product-architect** agent to:
- Define exactly what we're building
- Identify success criteria
- List edge cases to handle

## Step 2: Break Down
Use the **decomposer** agent to:
- Split into small tasks
- Identify dependencies
- Find the MVP

## Step 3: Design
Use the **architect** agent to:
- Plan technical approach
- Define interfaces
- Map file changes

## Step 4: Build
Implement incrementally:
- One piece at a time
- Test after each step
- Commit working states

## Step 5: Test
Use the **test-writer** agent to:
- Write unit tests
- Write integration tests
- Cover edge cases

## Step 6: Review
Use the **code-reviewer** agent to check:
- Code quality
- Consistency
- Potential issues

## Step 7: Security (if applicable)
If touching auth/data/APIs, use **security-auditor** agent.

## Step 8: Document
Use the **docs-writer** agent to:
- Add code comments
- Update README if needed
- Document APIs

## Step 9: Complete
Prepare commit and summarize what was built.
