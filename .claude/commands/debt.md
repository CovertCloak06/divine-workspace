Address technical debt: $ARGUMENTS

## Step 1: Inventory
Find all debt:
```bash
grep -r "TODO\|FIXME\|HACK\|XXX" --include="*.ts" --include="*.tsx"
```

Also identify:
- Known shortcuts
- Outdated patterns
- Missing tests
- Poor documentation

## Step 2: Assess
Use the **estimator** agent to:
- Estimate effort for each
- Assess risk of not fixing
- Identify quick wins

## Step 3: Prioritize
Use the **prioritizer** agent to:
- Rank by impact/effort
- Identify blockers
- Create action plan

## Step 4: Execute
Pick one item:
1. Plan the fix
2. Implement
3. Test
4. Review

## Step 5: Document
Update inventory.
Celebrate progress.
