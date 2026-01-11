/**
 * Event Bus - Central Communication Hub for Plugins
 * Allows plugins to communicate without tight coupling
 * Uses publish/subscribe pattern
 */

class EventBus {
    constructor() {
        this.listeners = new Map();
        this.eventHistory = [];
        this.maxHistorySize = 100;
    }

    /**
     * Subscribe to an event
     * @param {string} eventName - Name of the event to listen for
     * @param {Function} callback - Function to call when event fires
     * @param {object} context - Optional context (this) for callback
     * @returns {Function} Unsubscribe function
     */
    on(eventName, callback, context = null) {
        if (!this.listeners.has(eventName)) {
            this.listeners.set(eventName, []);
        }

        const listener = { callback, context };
        this.listeners.get(eventName).push(listener);

        // Return unsubscribe function
        return () => this.off(eventName, callback);
    }

    /**
     * Subscribe to an event that fires only once
     * @param {string} eventName - Name of the event
     * @param {Function} callback - Function to call
     * @param {object} context - Optional context
     * @returns {Function} Unsubscribe function
     */
    once(eventName, callback, context = null) {
        const wrappedCallback = (...args) => {
            callback.apply(context, args);
            this.off(eventName, wrappedCallback);
        };
        return this.on(eventName, wrappedCallback, context);
    }

    /**
     * Unsubscribe from an event
     * @param {string} eventName - Name of the event
     * @param {Function} callback - Callback to remove (optional - removes all if not provided)
     */
    off(eventName, callback = null) {
        if (!this.listeners.has(eventName)) return;

        if (callback === null) {
            // Remove all listeners for this event
            this.listeners.delete(eventName);
        } else {
            // Remove specific callback
            const listeners = this.listeners.get(eventName);
            const index = listeners.findIndex(l => l.callback === callback);
            if (index !== -1) {
                listeners.splice(index, 1);
            }
            // Clean up if no listeners left
            if (listeners.length === 0) {
                this.listeners.delete(eventName);
            }
        }
    }

    /**
     * Emit an event to all subscribers
     * @param {string} eventName - Name of the event
     * @param {*} data - Data to pass to listeners
     */
    emit(eventName, data = null) {
        // Log to history
        this.eventHistory.push({
            name: eventName,
            data,
            timestamp: Date.now()
        });

        // Trim history if too large
        if (this.eventHistory.length > this.maxHistorySize) {
            this.eventHistory.shift();
        }

        // Call all listeners
        if (this.listeners.has(eventName)) {
            const listeners = this.listeners.get(eventName).slice(); // Clone to avoid modification during iteration
            listeners.forEach(listener => {
                try {
                    listener.callback.call(listener.context, data);
                } catch (error) {
                    console.error(`[EventBus] Error in listener for "${eventName}":`, error);
                }
            });
        }
    }

    /**
     * Get all active event names
     * @returns {Array<string>} Array of event names
     */
    getActiveEvents() {
        return Array.from(this.listeners.keys());
    }

    /**
     * Get listener count for an event
     * @param {string} eventName - Name of the event
     * @returns {number} Number of listeners
     */
    getListenerCount(eventName) {
        return this.listeners.has(eventName) ? this.listeners.get(eventName).length : 0;
    }

    /**
     * Get recent event history
     * @param {number} count - Number of events to return
     * @returns {Array} Recent events
     */
    getHistory(count = 10) {
        return this.eventHistory.slice(-count);
    }

    /**
     * Clear all listeners (useful for cleanup)
     */
    clear() {
        this.listeners.clear();
        console.log('[EventBus] All listeners cleared');
    }

    /**
     * Debug: Log current state
     */
    debug() {
        console.log('[EventBus] Active Events:', this.getActiveEvents());
        this.listeners.forEach((listeners, eventName) => {
            console.log(`  ${eventName}: ${listeners.length} listener(s)`);
        });
    }
}

// Create singleton instance
const eventBus = new EventBus();

// Export both the class and the singleton
export { EventBus, eventBus };
export default eventBus;
