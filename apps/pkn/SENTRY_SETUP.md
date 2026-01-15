# Sentry Error Tracking Setup Guide

**Purpose**: Catch all JavaScript errors in production automatically

**Time to setup**: 10 minutes

---

## What is Sentry?

Sentry captures ALL JavaScript errors that occur for your users:
- Stack traces showing exactly where errors happened
- User context (what they were doing when error occurred)
- Session replay (watch video of what happened)
- Performance monitoring (slow API calls, etc.)
- Email/Slack alerts when errors occur

**Free tier**: 5,000 errors/month (plenty for PKN)

---

## Step 1: Create Sentry Account (2 minutes)

1. Go to https://sentry.io/signup/
2. Sign up with email or GitHub
3. Choose "JavaScript" as platform
4. Give project a name: "PKN-Frontend"
5. Copy your DSN (looks like: `https://abc123@o123.ingest.sentry.io/456`)

---

## Step 2: Add Sentry to PKN (5 minutes)

### Option A: Quick Setup (Recommended)

Add this to `pkn.html` **before** closing `</head>` tag:

```html
<!-- Sentry Error Tracking -->
<script
  src="https://js.sentry-cdn.com/YOUR_DSN_HERE.min.js"
  crossorigin="anonymous"
></script>
<script>
  Sentry.init({
    dsn: "YOUR_DSN_HERE",
    release: "pkn@1.0.0",
    environment: "production",

    // Performance monitoring
    integrations: [
      new Sentry.BrowserTracing(),
      new Sentry.Replay({
        maskAllText: false,
        blockAllMedia: false,
      }),
    ],

    // Sample rates
    tracesSampleRate: 0.1,  // 10% of transactions
    replaysSessionSampleRate: 0.1,  // 10% of sessions
    replaysOnErrorSampleRate: 1.0,  // 100% of errors

    // Filter development errors
    beforeSend(event) {
      // Don't send errors from localhost
      if (window.location.hostname === 'localhost') {
        console.log('Sentry (dev):', event);
        return null;
      }
      return event;
    },

    // Ignore harmless errors
    ignoreErrors: [
      'ResizeObserver loop',
      'chrome-extension',
      'NetworkError',
    ],
  });

  // Integrate with PKNLogger
  if (window.pknLogger) {
    const original = window.pknLogger.addLog;
    window.pknLogger.addLog = function(log) {
      original.call(this, log);

      // Send errors to Sentry
      if (log.level === 'error') {
        const err = new Error(log.message);
        err.stack = log.stack;
        Sentry.captureException(err, { extra: log });
      }
    };
  }

  console.info('✅ Sentry error tracking active');
</script>
```

**Replace** `YOUR_DSN_HERE` with your actual Sentry DSN!

### Option B: Module Setup (Advanced)

If you prefer ES modules:

1. Install Sentry SDK:
   ```bash
   npm install @sentry/browser @sentry/tracing
   ```

2. Use the `frontend/js/utils/sentry-init.js` file we created

3. Import in your main app:
   ```javascript
   import './js/utils/sentry-init.js';
   ```

---

## Step 3: Test It Works (1 minute)

Add this button temporarily to test:

```html
<button onclick="throw new Error('Test error for Sentry')">
  Test Sentry
</button>
```

Click it, then check your Sentry dashboard - error should appear within 30 seconds!

---

## Step 4: Configure Alerts (2 minutes)

In Sentry dashboard:

1. Go to **Settings** → **Alerts**
2. Click **Create Alert**
3. Choose **Issues**
4. Set condition: "When a new issue is created"
5. Add action: "Send email to" (your email)
6. Save

Now you'll get emails when new errors occur!

---

## What Sentry Captures

### Automatic:
- ✅ All JavaScript runtime errors
- ✅ Unhandled promise rejections
- ✅ Network request failures (if configured)
- ✅ Performance issues (slow API calls)
- ✅ Console errors (if integrated with PKNLogger)

### Manual (using Sentry API):
```javascript
// Capture custom error
Sentry.captureException(new Error('Something went wrong'));

// Capture message
Sentry.captureMessage('User completed tutorial', 'info');

// Add breadcrumb
Sentry.addBreadcrumb({
  message: 'User clicked send button',
  category: 'ui.click',
});

// Set user context
Sentry.setUser({
  id: 'user-123',
  username: 'john_doe',
});
```

---

## Integration with PKNLogger

Our Sentry setup automatically integrates with PKNLogger:

- **All errors** logged by PKNLogger are sent to Sentry
- **Breadcrumbs** created for all log events (helps trace error cause)
- **Performance** data included (network timings, etc.)

Example error in Sentry dashboard will show:

```
Error: Cannot read property 'x' of undefined
  at sendMessage (app.js:1234)
  at HTMLButtonElement.<anonymous> (app.js:5678)

Breadcrumbs:
  [10:30:15] user-action: Click on send button
  [10:30:15] network: POST /api/multi-agent/chat (pending)
  [10:30:16] error: Cannot read property 'x' of undefined

Context:
  - messages_count: 5
  - sidebar_visible: true
  - logger_active: true
```

---

## Environment Handling

Sentry is configured to:

- ✅ **Skip localhost** - No errors sent from development
- ✅ **Filter noise** - Ignores browser extension errors
- ✅ **Privacy** - Doesn't capture passwords or sensitive data
- ✅ **Performance** - Minimal overhead (<1% CPU)

To change environment:

```javascript
Sentry.init({
  environment: process.env.NODE_ENV || 'production',
  // ...
});
```

---

## Dashboard Features

Once setup, your Sentry dashboard shows:

### Issues Tab:
- List of all errors
- How many users affected
- Last seen, first seen
- Frequency graph

### Performance Tab:
- Slowest API endpoints
- Page load times
- Transaction traces

### Replays Tab:
- Video replay of user sessions
- See exactly what user did before error
- DOM changes, network requests, console logs

---

## Cost

| Plan | Price | Errors/month | Features |
|------|-------|--------------|----------|
| **Developer** | FREE | 5,000 | All features |
| Team | $26/month | 50,000 | Team collaboration |
| Business | $80/month | 100,000 | Advanced features |

For PKN, **free tier is plenty** - you'll likely only see 10-100 errors/month.

---

## Troubleshooting

### "No events showing up"

1. Check DSN is correct
2. Check browser console for Sentry init message
3. Verify `beforeSend` isn't filtering all events
4. Try triggering test error (throw new Error('test'))

### "Too many events"

Increase filtering in `beforeSend`:

```javascript
beforeSend(event) {
  // Only send errors, not warnings
  if (event.level !== 'error') return null;

  return event;
}
```

### "Session replays not working"

Ensure `Replay` integration is enabled:

```javascript
integrations: [
  new Sentry.Replay({
    maskAllText: false,  // Set to true for privacy
    blockAllMedia: false,
  }),
],
replaysOnErrorSampleRate: 1.0,  // Record all errors
```

---

## Best Practices

### DO:
- ✅ Set meaningful release versions (`pkn@1.2.3`)
- ✅ Add user context when available
- ✅ Use breadcrumbs for important events
- ✅ Filter out harmless errors
- ✅ Review errors weekly

### DON'T:
- ❌ Send errors from localhost (costs quota)
- ❌ Capture sensitive data (passwords, API keys)
- ❌ Ignore all errors (defeats the purpose)
- ❌ Set sample rate to 100% (expensive)

---

## Advanced: Source Maps

To see original code in stack traces (not minified):

1. Generate source maps during build:
   ```bash
   # For Vite
   vite build --sourcemap

   # For webpack
   webpack --devtool source-map
   ```

2. Upload to Sentry:
   ```bash
   npm install -g @sentry/cli
   sentry-cli sourcemaps upload --org your-org --project pkn ./dist
   ```

3. Add release to Sentry init:
   ```javascript
   release: "pkn@1.2.3",  // Match uploaded source maps
   ```

---

## Example: Full Error Context

When error occurs, Sentry shows:

```
TypeError: Cannot read properties of undefined (reading 'status')
  in sendMessage at app.js:1234:15

User:
  - IP: 192.168.1.100
  - Browser: Chrome 120
  - OS: Windows 11
  - First seen: 2026-01-11 10:30 AM

Breadcrumbs (last 10 events):
  [10:29:55] navigation: Loaded /pkn.html
  [10:30:00] ui.click: Clicked "Send" button
  [10:30:01] http: POST /api/multi-agent/chat → 500
  [10:30:02] console: Error: API request failed
  [10:30:02] exception: TypeError (this error)

Context:
  - messages_count: 3
  - sidebar_visible: false
  - active_agent: "auto"

Tags:
  - environment: production
  - release: pkn@1.0.0
  - browser: Chrome
```

This gives you **EVERYTHING** needed to fix the bug!

---

## Summary

**Setup time**: 10 minutes
**Cost**: FREE
**Value**: Catches ALL production bugs automatically

**Next**: Add the Sentry snippet to `pkn.html` and start catching errors!

---

**Related Docs**:
- `frontend/js/utils/sentry-init.js` - Module-based setup
- `LOGGING_AND_DEBUGGING_IMPROVEMENTS.md` - Overall logging strategy
- `MANUAL_TESTING_CHECKLIST.md` - Complement to automated error tracking
