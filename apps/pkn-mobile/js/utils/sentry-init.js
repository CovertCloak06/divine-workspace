/**
 * Sentry Error Tracking Integration for PKN
 * Captures all JavaScript errors, performance issues, and user sessions
 *
 * Setup Instructions:
 * 1. Create free account at https://sentry.io
 * 2. Create new project (JavaScript)
 * 3. Copy DSN (Data Source Name)
 * 4. Set SENTRY_DSN environment variable or update DSN below
 * 5. Include this script in pkn.html: <script src="/js/utils/sentry-init.js" type="module"></script>
 */

import * as Sentry from "https://browser.sentry-cdn.com/7.99.0/bundle.tracing.min.js";

// Configuration
const SENTRY_DSN = import.meta.env.VITE_SENTRY_DSN || ""; // Set your Sentry DSN here or in .env
const ENVIRONMENT = import.meta.env.MODE || "development"; // development, staging, production
const RELEASE = "pkn@1.0.0"; // Update with your version

// Initialize Sentry only if DSN is configured
if (SENTRY_DSN) {
    Sentry.init({
        dsn: SENTRY_DSN,

        // Release tracking
        release: RELEASE,
        environment: ENVIRONMENT,

        // Performance Monitoring
        integrations: [
            new Sentry.BrowserTracing({
                // Trace all XHR/fetch requests
                tracePropagationTargets: [
                    "localhost",
                    /^http:\/\/localhost:\d+\/api/,
                    /^\//,
                ],
            }),
            new Sentry.Replay({
                // Session replay for debugging
                maskAllText: false, // Set to true for privacy
                blockAllMedia: false, // Set to true to not capture images/videos
            }),
        ],

        // Performance monitoring - 10% of transactions
        tracesSampleRate: 0.1,

        // Session replay - 10% of sessions, 100% of errors
        replaysSessionSampleRate: 0.1,
        replaysOnErrorSampleRate: 1.0,

        // Error filtering
        beforeSend(event, hint) {
            // Don't send errors in development
            if (ENVIRONMENT === "development") {
                console.log("Sentry event (not sent in dev):", event);
                return null;
            }

            // Filter out known harmless errors
            const errorMessage = event.exception?.values?.[0]?.value || "";

            // Ignore ResizeObserver loop errors (harmless Chrome warning)
            if (errorMessage.includes("ResizeObserver loop")) {
                return null;
            }

            // Ignore script loading errors from extensions
            if (errorMessage.includes("chrome-extension://")) {
                return null;
            }

            return event;
        },

        // Add custom context to all events
        beforeSendTransaction(event) {
            // Add PKN-specific context
            event.contexts = event.contexts || {};
            event.contexts.pkn = {
                logger_active: !!window.pknLogger,
                messages_count: document.querySelectorAll(".message").length,
                sidebar_visible: !document.querySelector(".sidebar")?.classList.contains("hidden"),
            };

            return event;
        },

        // Ignore certain errors
        ignoreErrors: [
            // Browser extensions
            "top.GLOBALS",
            "chrome-extension",
            "moz-extension",
            // Random network errors
            "NetworkError",
            "Failed to fetch",
            // Third-party scripts
            "Cannot redefine property",
        ],

        // Deny URLs to ignore (third-party scripts)
        denyUrls: [
            /extensions\//i,
            /^chrome:\/\//i,
            /^moz-extension:\/\//i,
        ],
    });

    // Set user context (if you have user authentication)
    // Sentry.setUser({
    //     id: "user-id",
    //     username: "username",
    //     email: "user@example.com"
    // });

    // Add custom tags
    Sentry.setTag("app", "pkn");
    Sentry.setTag("component", "frontend");

    console.info("✅ Sentry error tracking initialized");

    // Export for manual error reporting
    window.Sentry = Sentry;

} else {
    console.warn("⚠️ Sentry DSN not configured. Error tracking disabled.");
    console.info("To enable: Set VITE_SENTRY_DSN environment variable");
}

// Helper functions for manual error reporting
export function captureError(error, context = {}) {
    """
    Manually capture an error with additional context
    """
    if (window.Sentry) {
        Sentry.captureException(error, {
            extra: context,
        });
    }
}

export function captureMessage(message, level = "info", context = {}) {
    """
    Capture a message (not an error)
    """
    if (window.Sentry) {
        Sentry.captureMessage(message, {
            level: level, // "info", "warning", "error"
            extra: context,
        });
    }
}

export function addBreadcrumb(message, category = "custom", data = {}) {
    """
    Add a breadcrumb (trail of events leading to error)
    """
    if (window.Sentry) {
        Sentry.addBreadcrumb({
            message: message,
            category: category,
            data: data,
            level: "info",
        });
    }
}

// Integrate with PKNLogger
if (window.pknLogger) {
    // Send critical errors to Sentry
    const originalAddLog = window.pknLogger.addLog.bind(window.pknLogger);

    window.pknLogger.addLog = function(log) {
        // Call original
        originalAddLog(log);

        // Send errors to Sentry
        if (log.level === "error" && window.Sentry) {
            const error = new Error(log.message);
            error.stack = log.stack;

            Sentry.captureException(error, {
                extra: {
                    type: log.type,
                    timestamp: log.timestamp,
                    ...log,
                },
            });
        }

        // Send breadcrumbs for all logs
        if (window.Sentry) {
            Sentry.addBreadcrumb({
                message: log.message,
                category: log.type,
                level: log.level === "error" ? "error" : "info",
                data: log,
            });
        }
    };

    console.info("✅ Sentry integrated with PKNLogger");
}

// Export for use in other modules
export default Sentry;
