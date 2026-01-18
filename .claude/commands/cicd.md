Set up CI/CD pipeline.

## Step 1: Analyze
Use the **devops** agent to determine:
- Build process
- Test requirements
- Deployment targets

## Step 2: Design Pipeline
Stages:
1. Install dependencies
2. Lint
3. Type check
4. Test
5. Build
6. Deploy (per environment)

## Step 3: Implement
Create workflow file for your platform (GitHub Actions, GitLab CI, etc.)

## Step 4: Secrets
Use the **security-auditor** agent to verify:
- Secrets in secure storage
- No exposure in logs
- Proper scoping

## Step 5: Test
- Run on branch
- Verify all stages
- Test failure scenarios

## Step 6: Document
Use the **docs-writer** agent for:
- How pipeline works
- How to deploy
- How to debug failures
