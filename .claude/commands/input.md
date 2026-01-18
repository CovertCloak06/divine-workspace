Review input validation: $ARGUMENTS

## Step 1: Map Inputs
Find all user inputs:
- Form fields
- Query parameters
- Request bodies
- Headers
- File uploads

## Step 2: Check Validation
Use the **security-auditor** agent to verify each input:
- Is it validated?
- Is validation sufficient?
- Is it validated server-side?

## Step 3: Test
For each input, try:
- Empty values
- Very long values
- Special characters
- SQL injection
- XSS payloads
- Type mismatches

## Step 4: Fix
Add or improve validation where needed.

## Step 5: Test
Use the **test-writer** agent to add validation tests.
