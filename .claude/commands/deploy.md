Pre-deployment checklist.

## Code
- [ ] All changes reviewed
- [ ] No debug code
- [ ] No console.logs

## Tests
- [ ] All tests pass
- [ ] Coverage acceptable
- [ ] No skipped tests

## Security
Use the **security-auditor** agent:
- [ ] No exposed secrets
- [ ] Dependencies scanned
- [ ] Auth working

## Build
- [ ] Build succeeds
- [ ] No warnings
- [ ] Assets optimized

## Config
Use the **env-manager** agent:
- [ ] All env vars set
- [ ] Configs correct

## Documentation
- [ ] README updated
- [ ] Changelog updated
- [ ] Migration notes (if needed)

## Ready?
✅ All checked → Deploy
❌ Any unchecked → Fix first
