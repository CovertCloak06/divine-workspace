# PKN Plugin System

## Overview

The PKN Plugin System allows you to extend functionality without modifying core code. Plugins are modular, self-contained features that can be enabled/disabled independently.

## Architecture

```
js/
├── event-bus.js         # Central event communication hub
├── plugin-base.js       # Base class all plugins extend
└── plugin-manager.js    # Orchestrates plugin lifecycle

plugins/
└── your-plugin/
    ├── manifest.json    # Plugin metadata and settings schema
    └── plugin.js        # Plugin implementation
```

## Creating a Plugin

### 1. Create Plugin Directory

```bash
mkdir plugins/my-feature
```

### 2. Create manifest.json

```json
{
  "id": "my-feature",
  "name": "My Feature",
  "version": "1.0.0",
  "description": "What your plugin does",
  "author": "Your Name",
  "autoEnable": false,
  "dependencies": [],
  "settings": {
    "someSetting": {
      "type": "text",
      "label": "Setting Label",
      "default": "default value",
      "description": "What this setting does"
    }
  }
}
```

### 3. Create plugin.js

```javascript
import { PluginBase } from '../../js/plugin-base.js';

export class MyFeaturePlugin extends PluginBase {
    async init() {
        await super.init();
        // Initialize your plugin
    }

    async enable() {
        await super.enable();
        // Subscribe to events, inject UI, etc.
    }

    async disable() {
        await super.disable();
        // Clean up
    }
}

export default MyFeaturePlugin;
```

### 4. Register Plugin (in main.js)

```javascript
import { MyFeaturePlugin } from './plugins/my-feature/plugin.js';
import myFeatureManifest from './plugins/my-feature/manifest.json';

// Register plugin
await pluginManager.register(myFeatureManifest, MyFeaturePlugin);
```

## Plugin Lifecycle

1. **Register** - Plugin is added to the system
2. **Init** - Plugin initializes (runs once)
3. **Enable** - Plugin becomes active
4. **Disable** - Plugin becomes inactive
5. **Destroy** - Plugin is removed (cleanup)

## PluginBase API

### Lifecycle Methods (Override These)

- `async init()` - Initialize plugin
- `async enable()` - Activate plugin
- `async disable()` - Deactivate plugin
- `async destroy()` - Cleanup before removal

### Event System

- `subscribe(eventName, callback)` - Listen for events
- `subscribeOnce(eventName, callback)` - Listen once
- `emit(eventName, data)` - Broadcast event
- `unsubscribeAll()` - Remove all subscriptions

### Settings

- `getSetting(key, defaultValue)` - Get setting value
- `setSetting(key, value)` - Set setting value
- `getSettings()` - Get all settings
- `loadSettings(settings)` - Load settings object

### Core API Access

- `showToast(message, duration, type)` - Show notification
- `addChatMessage(role, content)` - Add message to chat
- `getChatMessages()` - Get current messages
- `sendToAgent(message, agent)` - Send to AI agent
- `apiRequest(endpoint, options)` - Make API call

### UI Methods

- `createUI(html, containerId)` - Inject HTML
- `removeUI()` - Remove plugin UI
- `injectCSS(css)` - Add CSS
- `removeCSS()` - Remove CSS

## Event Bus

Central communication hub for plugins.

### Built-in Events

- `app:initialized` - App finished loading
- `message:sent` - User sent a message
- `message:received` - AI response received
- `agent:changed` - Agent selection changed
- `plugin:registered` - Plugin registered
- `plugin:enabled` - Plugin enabled
- `plugin:disabled` - Plugin disabled
- `plugin:settingChanged` - Plugin setting changed
- `pluginManager:initialized` - Plugin system ready

### Custom Events

Create your own events:

```javascript
// Plugin A emits
this.emit('myFeature:actionCompleted', { data: 'something' });

// Plugin B listens
this.subscribe('myFeature:actionCompleted', (data) => {
    console.log('Action completed:', data);
});
```

## Best Practices

### 1. Clean Up After Yourself

```javascript
async destroy() {
    this.removeUI();
    this.removeCSS();
    await super.destroy(); // Unsubscribes all events
}
```

### 2. Use Events for Communication

```javascript
// Don't directly call other plugins
// ❌ pluginManager.getPlugin('other').doSomething();

// Do emit events
// ✅ this.emit('needSomething', { data });
```

### 3. Handle Errors Gracefully

```javascript
async enable() {
    try {
        await super.enable();
        // Your code
    } catch (error) {
        console.error(`[${this.name}] Enable error:`, error);
        this.showToast('Failed to enable feature', 3000, 'error');
    }
}
```

### 4. Respect Enabled State

```javascript
this.subscribe('someEvent', (data) => {
    if (!this.enabled) return; // Don't process if disabled
    // Handle event
});
```

### 5. Keep CSS Scoped

```javascript
getCSS() {
    return `
        /* Scope with plugin class */
        .plugin-my-feature .button {
            /* styles */
        }
    `;
}
```

## Manifest Settings Schema

### Setting Types

```json
{
  "settings": {
    "textSetting": {
      "type": "text",
      "label": "Text Input",
      "default": "value",
      "description": "Help text"
    },
    "numberSetting": {
      "type": "number",
      "label": "Number Input",
      "default": 42,
      "description": "Help text"
    },
    "booleanSetting": {
      "type": "boolean",
      "label": "Checkbox",
      "default": true,
      "description": "Help text"
    },
    "selectSetting": {
      "type": "select",
      "label": "Dropdown",
      "default": "option1",
      "options": ["option1", "option2"],
      "description": "Help text"
    }
  }
}
```

## Example Plugins

Check these plugins for examples:

- `welcome-message` - Shows custom welcome message (basic example)

## Debugging

```javascript
// In browser console
pluginManager.debug();        // View all plugins
eventBus.debug();             // View active events
eventBus.getHistory(20);      // Last 20 events
pluginManager.getPlugin('my-feature'); // Get plugin instance
```

## FAQ

**Q: Can plugins communicate with each other?**
A: Yes, via the event bus. Emit and subscribe to custom events.

**Q: Can I disable plugins?**
A: Yes, in Settings → Plugins. State persists in localStorage.

**Q: How do I update a plugin?**
A: Update plugin files, increment version in manifest.json, refresh page.

**Q: Can plugins add UI to any panel?**
A: Yes, use `createUI(html, containerId)` with any container ID.

**Q: Are plugins sandboxed?**
A: No, plugins have full DOM and API access. Only install trusted plugins.

## Support

- GitHub Issues: [Your repo URL]
- Discord: [Your discord]
- Docs: [Your docs URL]
