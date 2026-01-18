Debug slow operation: $ARGUMENTS

## Step 1: Identify
What exactly is slow?
- Specific operation?
- Under what conditions?
- How slow (numbers)?

## Step 2: Profile
Use the **performance-analyzer** agent to:
- Trace the slow path
- Find where time is spent
- Identify the bottleneck

## Step 3: Analyze
Common causes:
- Database (N+1, missing index)
- Network (blocking, no timeout)
- Computation (algorithm, loops)
- Memory (allocation, GC)

## Step 4: Fix
Address root cause:
- Add index?
- Add caching?
- Batch operations?
- Change algorithm?

## Step 5: Verify
- Measure improvement
- Check for side effects
- Ensure correctness

## Step 6: Prevent
Add monitoring or benchmark test.
