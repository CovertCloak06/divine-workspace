/**
 * Error Boundary Handler
 * Catches and handles JavaScript errors gracefully
 */

class ErrorBoundary {
  constructor() {
    this.errors = [];
    this.init();
  }

  init() {
    // Catch global errors
    window.addEventListener('error', (event) => {
      this.handleError({
        message: event.message,
        source: event.filename,
        line: event.lineno,
        column: event.colno,
        error: event.error,
        type: 'runtime-error',
      });
    });

    // Catch unhandled promise rejections
    window.addEventListener('unhandledrejection', (event) => {
      this.handleError({
        message: event.reason?.message || 'Unhandled Promise Rejection',
        error: event.reason,
        type: 'promise-rejection',
      });
    });

    console.log('🛡️ Error boundary initialized');
  }

  handleError(errorInfo) {
    const errorData = {
      ...errorInfo,
      timestamp: Date.now(),
      url: window.location.href,
      userAgent: navigator.userAgent,
    };

    // Store error
    this.errors.push(errorData);

    // Log to console in development
    if (import.meta.env.DEV) {
      console.error('[Error Boundary]', errorData);
    }

    // Send to error tracking service in production
    if (import.meta.env.PROD) {
      this.reportError(errorData);
    }

    // Show user-friendly error message
    this.showErrorUI(errorData);
  }

  reportError(errorData) {
    // In production, send to error tracking service (e.g., Sentry)
    fetch('/api/errors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(errorData),
    }).catch(() => {
      // Silently fail if error reporting fails
    });
  }

  showErrorUI(errorData) {
    // Don't show UI for minor errors
    if (errorData.type === 'resource-error') {
      return;
    }

    // Create error notification
    const notification = document.createElement('div');
    notification.className = 'error-notification';
    notification.innerHTML = `
      <div class="error-notification-content">
        <div class="error-icon">⚠️</div>
        <div class="error-message">
          <strong>Something went wrong</strong>
          <p>We've been notified and are working on a fix.</p>
        </div>
        <button class="error-dismiss" onclick="this.parentElement.parentElement.remove()">✕</button>
      </div>
    `;

    // Add styles if not already present
    if (!document.getElementById('error-boundary-styles')) {
      const style = document.createElement('style');
      style.id = 'error-boundary-styles';
      style.textContent = `
        .error-notification {
          position: fixed;
          top: 20px;
          right: 20px;
          background: rgba(239, 68, 68, 0.95);
          color: white;
          padding: 16px;
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
          z-index: 10000;
          max-width: 400px;
          animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }

        .error-notification-content {
          display: flex;
          align-items: flex-start;
          gap: 12px;
        }

        .error-icon {
          font-size: 24px;
        }

        .error-message strong {
          display: block;
          margin-bottom: 4px;
        }

        .error-message p {
          margin: 0;
          font-size: 14px;
          opacity: 0.9;
        }

        .error-dismiss {
          background: none;
          border: none;
          color: white;
          font-size: 20px;
          cursor: pointer;
          padding: 0;
          margin-left: auto;
        }
      `;
      document.head.appendChild(style);
    }

    document.body.appendChild(notification);

    // Auto-remove after 10 seconds
    setTimeout(() => {
      notification.remove();
    }, 10000);
  }

  getErrors() {
    return this.errors;
  }

  clearErrors() {
    this.errors = [];
  }
}

// Initialize error boundary
const errorBoundary = new ErrorBoundary();

export default errorBoundary;
