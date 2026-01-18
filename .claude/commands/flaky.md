Fix flaky/intermittent bug: $ARGUMENTS

## Step 1: Gather Evidence
Use the **debugger** agent to:
- Collect all error variations seen
- Identify patterns (timing? load? data?)
- Look for race conditions or async issues

## Step 2: Reproduce
Try to create reliable reproduction:
- Add logging/instrumentation
- Identify exact trigger conditions
- Create isolated test case if possible

## Step 3: Analyze Root Cause
Common flaky bug causes:
- Race conditions
- Unhandled promises
- Shared mutable state
- Timing dependencies
- Network/external service issues

## Step 4: Fix
Address the actual root cause:
- Add proper synchronization
- Handle async correctly
- Remove timing dependencies
- Add retry logic if appropriate

## Step 5: Verify Stability
Use the **test-writer** agent to:
- Create test that exercises the timing
- Run multiple times to confirm fix
- Add stress tests if applicable

## Step 6: Document
Explain:
- What caused the flakiness
- How the fix addresses it
- How to avoid similar issues
