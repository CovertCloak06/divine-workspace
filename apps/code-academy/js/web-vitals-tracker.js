/**
 * Web Vitals Tracking
 * Monitors Core Web Vitals (LCP, FID, CLS) for performance insights
 */

import { onCLS, onINP, onLCP, onFCP, onTTFB } from 'web-vitals';

function sendToAnalytics(metric) {
  const body = JSON.stringify(metric);

  // Log to console in development
  if (import.meta.env.DEV) {
    console.log('[Web Vitals]', metric.name, metric.value, metric);
  }

  // In production, send to analytics endpoint
  if (import.meta.env.PROD && navigator.sendBeacon) {
    navigator.sendBeacon('/api/analytics', body);
  }

  // Store locally for debugging
  const vitals = JSON.parse(localStorage.getItem('web-vitals') || '[]');
  vitals.push({
    name: metric.name,
    value: metric.value,
    rating: metric.rating,
    timestamp: Date.now(),
  });

  // Keep only last 50 measurements
  if (vitals.length > 50) {
    vitals.shift();
  }

  localStorage.setItem('web-vitals', JSON.stringify(vitals));
}

// Track all Core Web Vitals
export function initWebVitals() {
  onCLS(sendToAnalytics);
  onINP(sendToAnalytics); // Replaced FID with INP (Interaction to Next Paint)
  onLCP(sendToAnalytics);
  onFCP(sendToAnalytics);
  onTTFB(sendToAnalytics);

  console.log('📊 Web Vitals tracking initialized');
}

// Export function to get current vitals
export function getWebVitals() {
  return JSON.parse(localStorage.getItem('web-vitals') || '[]');
}

// Export function to clear vitals
export function clearWebVitals() {
  localStorage.removeItem('web-vitals');
}
