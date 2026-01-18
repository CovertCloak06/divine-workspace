Optimize bundle size.

## Step 1: Analyze
```bash
npm run build -- --analyze || npx vite-bundle-analyzer
```

## Step 2: Identify Issues
Use the **performance-analyzer** agent to find:
- Large dependencies
- Duplicate code
- Unused exports
- Non-tree-shakeable imports

## Step 3: Optimize
For each issue:
- Replace large deps with smaller alternatives
- Remove unused dependencies
- Use dynamic imports for large chunks
- Configure tree shaking properly

## Step 4: Measure
Compare before/after:
- Total bundle size
- Chunk sizes
- Load time

## Step 5: Document
Note optimizations made and impact.
