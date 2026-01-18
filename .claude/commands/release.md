Prepare release.

## Step 1: Code Freeze
- All features merged
- No WIP code

## Step 2: Review
Use the **code-reviewer** agent:
- Review all changes
- Check for debug code
- Verify quality

## Step 3: Security
Use the **security-auditor** agent:
- Vulnerability check
- Dependency scan

## Step 4: Test
- All tests pass
- Manual testing
- Edge cases

## Step 5: Docs
Use the **docs-writer** agent:
- README current
- API docs current
- Migration guide

## Step 6: Changelog
Use the **changelog-writer** agent:
- List changes
- Note breaking changes

## Step 7: Version
- Update version
- Update deps

## Step 8: Release
- Create tag
- Push
- Deploy
