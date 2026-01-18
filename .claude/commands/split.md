Split large file: $ARGUMENTS

## Step 1: Analyze
Use the **refactorer** agent to:
- Identify logical groupings
- Find natural boundaries
- Map dependencies

## Step 2: Plan
Define new structure:
- What files to create
- What goes in each
- How they connect

## Step 3: Execute
Move code carefully:
1. Create new file
2. Move one piece
3. Update imports
4. Run tests
5. Commit
6. Repeat

## Step 4: Verify
- All tests pass
- No circular dependencies
- Build succeeds
- App works

## Step 5: Review
Use the **code-reviewer** agent to verify:
- Split makes sense
- No accidental changes
- Imports are clean
