Fix formatting and style issues.

## Step 1: Auto-format
Run the project's formatter:
```bash
# Try common formatters
npm run format || pnpm format || yarn format
npx prettier --write .
```

## Step 2: Lint
Run linter and fix auto-fixable issues:
```bash
npm run lint -- --fix || pnpm lint --fix
```

## Step 3: Manual Fixes
Use the **code-reviewer** agent to fix:
- Remaining lint errors
- Style inconsistencies
- Naming issues

## Step 4: Verify
- All formatting rules pass
- All lint rules pass
- Build succeeds

## Step 5: Commit
Commit formatting changes separately from logic changes.
