Debug memory issue: $ARGUMENTS

## Step 1: Identify
What's the symptom?
- Memory growing over time (leak)
- High memory usage (bloat)
- Out of memory errors

## Step 2: Profile
Use the **performance-analyzer** agent to:
- Take heap snapshots
- Find largest objects
- Track allocations over time

## Step 3: Analyze
Common causes:
- Event listeners not removed
- Closures holding references
- Caching without limits
- Growing arrays/collections

## Step 4: Fix
Address root cause:
- Clean up listeners
- Clear references
- Add cache limits
- Use WeakMap/WeakSet

## Step 5: Verify
- Memory usage stabilizes
- No functional regressions
- Performance acceptable
