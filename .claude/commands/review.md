Comprehensive code review.

## Step 1: Code Quality
Use the **code-reviewer** agent to check:
- Logic correctness
- Error handling
- Code style and clarity
- Files under 200 lines
- No debug code left

## Step 2: Security
Use the **security-auditor** agent to check:
- Input validation
- Authentication/authorization
- Data exposure risks
- Injection vulnerabilities

## Step 3: Performance
Use the **performance-analyzer** agent to check:
- Obvious bottlenecks
- N+1 queries
- Memory issues
- Unnecessary work

## Step 4: Types (if TypeScript)
Use the **type-surgeon** agent to check:
- Type correctness
- No unnecessary `any`
- Type safety

## Step 5: Tests
Use the **test-writer** agent to check:
- Adequate coverage
- Meaningful tests
- Edge cases covered

## Step 6: Accessibility (if UI)
Use the **accessibility-checker** agent to check:
- Semantic HTML
- Keyboard navigation
- ARIA attributes
- Color contrast

## Summary
Provide prioritized feedback:
- 🔴 Critical (must fix)
- 🟡 Important (should fix)
- 🟢 Suggestions (nice to fix)

**Verdict:** Ship it ✅ / Needs changes ⚠️ / Major issues ❌
