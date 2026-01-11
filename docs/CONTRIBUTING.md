# Contributing to Divine Node Workspace

Thank you for your interest in contributing! This guide will help you get started.

## 🚀 Quick Start

```bash
# Fork and clone
git clone <your-fork-url>
cd divine-workspace

# Setup
just setup

# Create branch
git checkout -b feature/my-feature

# Make changes, test, commit
just ci
git commit -m "feat: add my feature"

# Push and create PR
git push origin feature/my-feature
```

## 📜 Code of Conduct

- Be respectful and constructive
- Help others learn and grow
- Focus on what is best for the community
- Show empathy towards other community members

## 🔧 Development Workflow

### 1. Before You Start

**Check existing issues/PRs** to avoid duplicate work:
```bash
# Search issues
gh issue list --search "your topic"

# Search PRs
gh pr list --search "your topic"
```

**Discuss major changes** before implementing:
- Open an issue first
- Get feedback from maintainers
- Agree on approach

### 2. Set Up Development Environment

```bash
# Install dependencies
just setup

# Verify setup
just health
just check-tools

# Run tests
just test
```

**Required Tools:**
- Node.js 18+
- Python 3.10+
- just (command runner)
- Git
- pnpm

**Optional Tools:**
- pre-commit (recommended)
- Biome (linting)

### 3. Create a Branch

**Branch naming convention:**
```
feature/short-description   # New features
fix/bug-description          # Bug fixes
refactor/what-changed        # Code refactoring
docs/what-documented         # Documentation
test/what-tested             # Test additions
chore/what-updated           # Chores (deps, configs)
```

Examples:
```bash
git checkout -b feature/add-python-agent
git checkout -b fix/memory-leak-in-chat
git checkout -b docs/improve-setup-guide
```

### 4. Make Changes

**Follow coding standards:**

✅ **DO:**
- Keep files under 200 lines
- Write tests for new code
- Update documentation
- Follow existing code style
- Run `just ci` before committing

❌ **DON'T:**
- Create monolithic files (>200 lines)
- Skip tests
- Ignore linting errors
- Mix multiple concerns in one PR
- Commit generated files (build artifacts)

### 5. File Size Limit (CRITICAL)

**Every source file MUST be ≤200 lines.**

```bash
# Check file sizes
just check-file-sizes

# If you exceed 200 lines, split the file
# See ARCHITECTURE.md for patterns
```

**Enforced by:**
- Pre-commit hook (before commit)
- CI pipeline (before merge)

**How to split large files:**

```python
# ❌ BAD: 300-line file
# my_module.py (300 lines)

# ✅ GOOD: Split into smaller modules
my_module/
├── __init__.py      # Exports
├── core.py          # Core logic (150 lines)
├── helpers.py       # Helper functions (80 lines)
└── types.py         # Type definitions (50 lines)
```

### 6. Write Tests

**Test coverage required for:**
- New features
- Bug fixes
- Refactored code

**Test types:**
- Unit tests (required)
- Integration tests (if applicable)
- E2E tests (for UI changes)

**Examples:**

```python
# Python unit test
# apps/pkn/tests/unit/test_my_feature.py
def test_my_function():
    result = my_function("input")
    assert result == "expected"
```

```javascript
// JavaScript unit test
// apps/code-academy/tests/unit/my-feature.test.js
import { myFunction } from '../src/my-feature.js';

describe('myFunction', () => {
  it('should return expected result', () => {
    expect(myFunction('input')).toBe('expected');
  });
});
```

**Run tests:**
```bash
just test                 # All tests
just test-app pkn         # PKN tests only
just test-app code-academy # Code Academy tests only
```

### 7. Update Documentation

**Update when:**
- Adding new features
- Changing API endpoints
- Modifying configuration
- Adding new dependencies
- Changing build process

**Files to update:**
- `README.md` (if user-facing)
- `CLAUDE.md` (for AI continuity)
- App-specific `CLAUDE.md`
- `CHANGELOG.md` (add entry)

### 8. Run Pre-commit Checks

```bash
# Full CI pipeline
just ci

# Individual checks
just lint           # Linting
just format         # Formatting
just test           # All tests
just check-file-sizes # File size limits
```

**What pre-commit hooks check:**
- Biome linting/formatting (JavaScript/TypeScript)
- Ruff linting/formatting (Python)
- File size limits (200 lines)
- Secret detection
- Trailing whitespace
- YAML/JSON syntax

### 9. Commit Changes

**Commit message format:**
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Test additions
- `chore`: Chores (deps, configs)
- `perf`: Performance improvements

**Scopes:**
- `pkn`: PKN app
- `code-academy`: Code Academy app
- `pkn-mobile`: PKN Mobile app
- `tooling`: Developer tooling
- `docs`: Documentation
- `deps`: Dependencies

**Examples:**
```bash
git commit -m "feat(pkn): add Python code execution tool

Adds a new tool for executing Python code in sandboxed environment.

- Created backend/tools/python_executor.py
- Added tests in tests/unit/test_python_executor.py
- Updated CLAUDE.md with tool documentation

Closes #123"

git commit -m "fix(code-academy): resolve quiz validation bug

Fixed issue where quiz answers were not being validated correctly
for questions with special characters.

Fixes #456"

git commit -m "docs(pkn): improve deployment guide

Added detailed instructions for deploying PKN with systemd.

- Created docs/DEPLOYMENT.md
- Added systemd service example
- Updated README.md with deployment section"
```

### 10. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/my-feature

# Create PR (using GitHub CLI)
gh pr create --fill

# Or via GitHub web interface
```

**PR template:**
```markdown
## Description
Brief description of what this PR does.

## Changes
- List of changes
- Another change

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] `just ci` passes
- [ ] Files under 200 lines
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
```

## 🎯 Contribution Guidelines

### What We're Looking For

✅ **Good PRs:**
- Focused changes (one feature/fix per PR)
- Well-tested code
- Clear documentation
- Follows coding standards
- Addresses real user needs

❌ **Avoid:**
- Massive PRs (>500 lines changed)
- Multiple unrelated changes
- Missing tests
- Breaking changes without discussion
- Reformatting entire codebase

### Adding New Features

**Before implementing:**
1. Open an issue describing the feature
2. Discuss with maintainers
3. Get approval
4. Create PR

**When implementing:**
- Keep it simple
- Follow existing patterns
- Add tests
- Update documentation
- Consider backwards compatibility

### Fixing Bugs

**Before fixing:**
1. Reproduce the bug
2. Write a failing test
3. Fix the bug
4. Verify test passes

**When submitting:**
- Reference the issue: `Fixes #123`
- Include test case
- Explain root cause
- Verify no regressions

### Improving Documentation

**We welcome:**
- Typo fixes
- Clarifications
- New examples
- Tutorial improvements
- Translation corrections

**How to help:**
- Fix errors you encounter
- Document undocumented features
- Add troubleshooting tips
- Improve README clarity

## 🧪 Testing Guidelines

### Writing Good Tests

**Unit tests should:**
- Test one thing
- Be independent
- Run fast (<1 second)
- Be deterministic (no flaky tests)
- Have clear names

**Example:**
```python
def test_agent_classifies_code_task_correctly():
    """Agent should classify 'write a function' as coder task."""
    manager = AgentManager()
    task = "Write a Python function to calculate fibonacci"
    agent = manager.classify_task(task)
    assert agent == AgentType.CODER
```

### Running Tests Locally

```bash
# All tests
just test

# Specific app
just test-app pkn

# Specific test file
cd apps/pkn
pytest tests/unit/test_agents.py -v

# Watch mode (Code Academy)
cd apps/code-academy
pnpm test:watch
```

### Test Coverage

**Coverage requirements:**
- New features: 80%+ coverage
- Bug fixes: Test for regression
- Refactoring: Maintain existing coverage

**Check coverage:**
```bash
# Python
cd apps/pkn
pytest --cov=backend --cov-report=html

# JavaScript
cd apps/code-academy
pnpm test:coverage
```

## 🔍 Code Review Process

### As a Contributor

**Expect:**
- Constructive feedback
- Requests for changes
- Questions about approach
- Suggestions for improvements

**Respond:**
- Address all comments
- Ask for clarification if needed
- Push updates promptly
- Be open to suggestions

### As a Reviewer

**Review for:**
- Correctness
- Code quality
- Test coverage
- Documentation
- Breaking changes
- Performance implications

**Provide:**
- Specific feedback
- Suggested improvements
- Praise for good work
- Helpful resources

## 🚨 Troubleshooting

### Pre-commit Hooks Failing

```bash
# See what's failing
just pre-commit-all

# Fix formatting issues
just format

# Fix linting issues
just lint

# Update hooks
just pre-commit-update
```

### Tests Failing

```bash
# Run tests with verbose output
just test-app pkn -v

# Run specific test
cd apps/pkn
pytest tests/unit/test_agents.py::test_specific_function -v

# Skip CI (emergency only)
git commit --no-verify
```

### File Size Violations

```bash
# Check which files are too large
just check-file-sizes

# Split large file into modules
# See docs/ARCHITECTURE.md for patterns
```

## 📚 Resources

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues
- [CLAUDE.md](../CLAUDE.md) - AI assistant guide
- [App-specific CLAUDE.md files](../apps/) - Per-app guides

## 🙋 Getting Help

**Questions about:**
- **Features**: Open an issue
- **Bugs**: Open an issue with reproduction steps
- **Development**: Check CLAUDE.md or ask in discussions
- **Architecture**: See ARCHITECTURE.md

## 🎉 Recognition

Contributors will be:
- Listed in CHANGELOG.md
- Mentioned in release notes
- Credited in commits

## 📝 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Divine Node Workspace! 🙏
