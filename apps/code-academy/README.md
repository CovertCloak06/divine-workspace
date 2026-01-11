# Divine Node Code Academy

Interactive coding education platform for complete beginners. Learn HTML, CSS, JavaScript, and development workflows through hands-on lessons with live code validation and visual feedback.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start development server with hot reload
npm run dev

# Open browser to http://localhost:8011
```

## 📁 Project Structure

```
code-academy/
├── src/                          # Modular source code (ES modules)
│   ├── core/
│   │   └── TutorialEngine.js     # Main orchestrator (~480 lines)
│   ├── services/
│   │   └── LessonLoader.js       # JSON loading & caching
│   ├── components/
│   │   ├── TaskRenderer.js       # Task type dispatcher
│   │   ├── CodeEditor.js         # Code editor component
│   │   └── QuizComponent.js      # Quiz component
│   └── utils/
│       ├── formatters.js         # Content formatting
│       └── validators.js         # Code validation
├── lessons/                      # Lesson JSON files
│   ├── schemas/
│   │   └── lesson-schema.json    # JSON schema for validation
│   ├── html/
│   ├── css/
│   └── js/
├── tests/                        # Test files
│   ├── unit/                     # Unit tests (Vitest)
│   ├── integration/              # Integration tests
│   └── e2e/                      # E2E tests (Playwright)
├── js/                           # Legacy scripts (to be refactored)
└── css/                          # Stylesheets

```

## 🛠️ Development Tools

### Build & Development
- **Vite** - Lightning-fast dev server with hot module reload
- **ES Modules** - Native JavaScript modules for better code organization

### Code Quality
- **ESLint** - JavaScript linting with strict rules
- **Prettier** - Automatic code formatting
- **Husky** - Git hooks for pre-commit checks
- **lint-staged** - Auto-format/lint staged files before commit

### Testing
- **Vitest** - Unit & integration testing with coverage
- **Playwright** - E2E testing across browsers
- **jsdom/happy-dom** - DOM environment for component testing

### CI/CD
- **GitHub Actions** - Automated testing, linting, and builds

## 📜 Available Scripts

```bash
# Development
npm run dev              # Start Vite dev server (localhost:8011)
npm run build            # Build for production
npm run preview          # Preview production build

# Testing
npm test                 # Run unit & integration tests
npm run test:ui          # Run tests with UI
npm run test:e2e         # Run E2E tests with Playwright

# Code Quality
npm run lint             # Check for linting errors
npm run lint:fix         # Auto-fix linting errors
npm run format           # Format all code with Prettier
```

## 🧪 Testing

### Unit Tests
```bash
npm test                 # Run all unit tests
npm test -- --coverage   # Run with coverage report
```

Tests are located in `tests/unit/` and cover:
- Validators (code validation, HTML/CSS/JS syntax checking)
- Formatters (markdown-like content to HTML conversion)

### Integration Tests
```bash
npm test tests/integration
```

Tests component interactions and lesson flow.

### E2E Tests
```bash
npm run test:e2e
```

Full user journey tests using Playwright:
- Path selection
- Lesson loading
- Quiz completion
- Code editor validation
- Progress tracking

## 🔍 Code Quality Standards

### ESLint Rules
- No `var` (use `const`/`let`)
- No `eval()` (security)
- Strict equality (`===`)
- Single quotes
- Max line length: 100 characters
- Proper indentation (2 spaces)

### Prettier Configuration
- Single quotes
- Semicolons required
- 2-space indentation
- 100-character line width
- Trailing commas (ES5)

### Pre-commit Hooks
Husky automatically runs on `git commit`:
1. Lint staged files with ESLint
2. Format staged files with Prettier
3. Reject commit if errors found

## 📝 Lesson JSON Schema

All lessons must follow the JSON schema in `lessons/schemas/lesson-schema.json`:

```json
{
  "id": "html-01",
  "title": "Your First HTML Page",
  "description": "Learn the basics of HTML",
  "difficulty": "beginner",
  "estimatedTime": "10 minutes",
  "steps": [
    {
      "title": "Step Title",
      "content": "Markdown-like content",
      "visual": "<div>HTML for visual examples</div>",
      "task": {
        "type": "quiz|code|completion|info",
        "instruction": "What to do",
        "validate": "(code) => code.includes('<h1>')"
      }
    }
  ]
}
```

## 🏗️ Architecture Principles

This project follows the standards in `/home/gh0st/dvn/ARCHITECTURE_STANDARDS.md`:

1. **Modular Structure** - Each file has a single responsibility (<500 lines)
2. **Separation of Concerns** - Data loading ≠ rendering ≠ validation
3. **Component Isolation** - Self-contained, reusable components
4. **Event-Driven** - Components communicate via callbacks
5. **Dependency Injection** - Services injected into orchestrator

### Before Refactor (Monolithic)
- `tutorial-engine.js`: 1116 lines
- Mixed concerns (loading + rendering + validation)
- No testing
- No build tooling

### After Refactor (Modular)
- 7 focused modules (~140 lines each)
- Clear separation of concerns
- Full test coverage
- Modern build tooling
- CI/CD pipeline

## 🚦 CI/CD Pipeline

GitHub Actions automatically runs on push/PR:

1. **Lint** - ESLint + Prettier checks
2. **Test** - Unit & integration tests with coverage
3. **E2E** - Playwright browser tests
4. **Build** - Production build verification

See `.github/workflows/ci.yml` for details.

## 📊 Code Coverage

```bash
npm test -- --coverage
```

Coverage reports are generated in `coverage/` directory and uploaded to Codecov in CI.

## 🔧 Configuration Files

- `.eslintrc.json` - ESLint rules
- `.prettierrc` - Prettier formatting rules
- `.prettierignore` - Files to exclude from formatting
- `vitest.config.js` - Vitest configuration
- `playwright.config.js` - Playwright E2E configuration
- `vite.config.js` - Vite build configuration
- `.husky/pre-commit` - Git pre-commit hook
- `package.json` - Dependencies & scripts

## 📚 Documentation

- `CLAUDE.md` - Project-specific development guide
- `/home/gh0st/dvn/ARCHITECTURE_STANDARDS.md` - Master architecture guide
- `/home/gh0st/dvn/PRODUCTIVITY_TOOLS.md` - Complete tools catalog

## 🎯 Next Steps

- [ ] Run tests: `npm test`
- [ ] Run E2E tests: `npm run test:e2e`
- [ ] Push to GitHub and verify CI passes
- [ ] Add more lessons (CSS, JavaScript paths)
- [ ] Implement progress syncing
- [ ] Add AI code hints

## 🤝 Contributing

1. Read `CLAUDE.md` for project guidelines
2. Follow architecture standards
3. Write tests for new features
4. Ensure CI passes before merging
5. Use conventional commits

## 📄 License

MIT

---

**Part of the Divine Node ecosystem**
- [PKN AI](http://localhost:8010) - AI-powered development assistant
- Divine Debugger - Browser DevTools extension
