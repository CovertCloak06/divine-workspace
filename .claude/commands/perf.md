Performance optimization: $ARGUMENTS

## Step 1: Baseline
Measure current performance:
- Response times
- Memory usage
- Bundle size (if frontend)
- Specific slow operations

## Step 2: Profile
Use the **performance-analyzer** agent to find:
- Slowest operations
- Memory hogs
- N+1 queries
- Unnecessary work

## Step 3: Prioritize
Focus on:
- Biggest impact
- Most frequently hit
- User-facing operations

## Step 4: Optimize
For top bottleneck:
1. Plan improvement
2. Implement
3. Measure improvement
4. Verify no regressions

## Step 5: Test
Use the **test-writer** agent to:
- Add performance benchmarks
- Ensure functionality unchanged

## Step 6: Document
Record what was optimized and why.
