Help with undo/revert.

## Uncommitted Changes
```bash
# Undo file
git checkout -- <file>

# Undo all
git checkout -- .

# Undo staged
git reset HEAD <file>
```

## Last Commit (not pushed)
```bash
# Keep changes
git reset --soft HEAD~1

# Discard changes
git reset --hard HEAD~1
```

## Pushed Commit
```bash
# Create revert commit
git revert <commit>
```

## What to undo?
Describe and I'll help.
