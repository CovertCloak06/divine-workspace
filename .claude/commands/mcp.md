Build MCP server: $ARGUMENTS

## Step 1: Design
Use the **mcp-builder** agent to:
- Define tools to expose
- Design input schemas
- Plan output formats
- Consider error cases

## Step 2: Structure
```
mcp-server-name/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts
│   ├── tools/
│   │   └── [tool-name].ts
│   └── handlers/
│       └── [handler].ts
├── tests/
└── README.md
```

## Step 3: Implement
Build each tool:
- Input validation
- Core logic
- Error handling
- Type safety

## Step 4: Test
- Test each tool manually
- Add automated tests
- Test error cases

## Step 5: Security
Use the **security-auditor** agent to:
- Review input validation
- Check for dangerous operations
- Verify error messages are safe

## Step 6: Document
Use the **docs-writer** agent for:
- Installation instructions
- Tool descriptions
- Usage examples
- Configuration options
