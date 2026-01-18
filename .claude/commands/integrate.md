Integrate external service: $ARGUMENTS

## Step 1: Research
Use web search to:
- Read official documentation
- Find SDKs/libraries
- Understand auth requirements
- Check rate limits and quotas

## Step 2: Plan
Use the **architect** agent to:
- Design integration architecture
- Plan error handling
- Define retry strategy
- Consider caching

## Step 3: Setup
Use the **env-manager** agent to:
- Identify required credentials
- Set up environment variables
- Create .env.example
- Document configuration

## Step 4: Implement
Use **tool-integrator** agent guidance to:
- Create typed client wrapper
- Handle authentication
- Implement proper error handling
- Add retry logic

## Step 5: Test
Use the **test-writer** agent for:
- Unit tests with mocked responses
- Integration tests (if safe)
- Error scenario tests
- Rate limit handling tests

## Step 6: Security Review
Use the **security-auditor** agent to:
- Verify credential handling
- Check data exposure
- Review error messages

## Step 7: Document
Use the **docs-writer** agent for:
- Setup instructions
- Usage examples
- Troubleshooting guide
