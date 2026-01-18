Deep investigation (no fix yet): $ARGUMENTS

## DO NOT FIX - Just understand

### Step 1: Gather Context
Use the **debugger** agent to:
- Document all symptoms
- Collect error messages and stack traces
- Map affected areas

### Step 2: Trace the Problem
- What code paths are involved?
- What data/state is involved?
- When did this start happening?

### Step 3: Root Cause Analysis
Ask "why" 5 times:
1. Why does this error occur?
2. Why is that happening?
3. Why did that state get set?
4. Why wasn't this caught?
5. Why was it built this way?

### Step 4: Impact Assessment
- How many users affected?
- What's the severity?
- What's the blast radius of a fix?

### Step 5: Options
Present 2-3 fix approaches:

| Option | Pros | Cons | Effort |
|--------|------|------|--------|
| Quick fix | ... | ... | S |
| Proper fix | ... | ... | M |
| Redesign | ... | ... | L |

### Step 6: Recommendation
Recommend an approach with reasoning.

**Do NOT implement - await approval.**
