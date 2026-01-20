# Divine Node - Final Fixes for Lovable

Copy and paste this ENTIRE prompt into Lovable to complete the rebranding and fixes.

---

## TASK: Rebrand from "Parakleon Studio" to "Divine Node" + Fix Remaining Issues

Please make the following changes across the entire codebase:

### 1. REBRAND: All Visual Names

**Change all instances of:**
- "Parakleon Studio" → "Divine Node"
- "PARAKLEON" → "DIVINE NODE"
- "Parakleon" → "Divine Node" (when referring to the product)
- "Ask Parakleon" → "Ask Divine" or "Ask AI"

**Specific files to update:**

**src/components/layout/TopBar.tsx line 56:**
```tsx
// FROM:
<span className="font-mono font-bold text-base sm:text-lg gradient-text hidden sm:inline">PARAKLEON</span>

// TO:
<span className="font-mono font-bold text-base sm:text-lg gradient-text hidden sm:inline">DIVINE NODE</span>
```

**src/pages/Dashboard.tsx line 444:**
```tsx
// FROM:
Welcome to Parakleon Studio

// TO:
Welcome to Divine Node
```

**src/lib/demo-data.ts line 63:**
```tsx
// FROM:
Welcome to Parakleon Studio

// TO:
Welcome to Divine Node
```

**src/lib/demo-data.ts line 165:**
```tsx
// FROM:
content: 'Welcome to Parakleon Studio. I\'m your AI assistant ready to help with coding, design, and testing.',

// TO:
content: 'Welcome to Divine Node. I\'m your AI command center for orchestrating agents and tools.',
```

**src/pages/Project.tsx line 286:**
```tsx
// FROM:
{ role: 'system', content: 'You are Parakleon, an AI assistant for a security-focused IDE. Help with code, OSINT tools, and project management.' },

// TO:
{ role: 'system', content: 'You are Divine Node, an AI command center with specialized agents for coding, security, OSINT, and project management. The three modules are: Nexus (chat/agents), Forge (IDE), and Shadow (security tools).' },
```

**src/components/modules/forge/ForgeEditor.tsx lines 316-317, 388, 542, 548:**
```tsx
// Change all "Ask Parakleon" to "Ask Divine"
// Change function name handleAskParakleon to handleAskDivine
```

**src/components/modules/forge/ForgeModule.tsx line 325:**
```tsx
// FROM:
Ask Parakleon

// TO:
Ask Divine
```

### 2. REBRAND: LocalStorage Keys

**Change all localStorage key prefixes from "parakleon-" to "divine-node-":**

Update these files:
- `src/hooks/useTheme.tsx` lines 29-30
- `src/hooks/useWorkspace.tsx` line 33
- `src/hooks/useActiveProject.tsx` line 9
- `src/hooks/useGitHubContent.tsx` lines 24, 38, 52, 184, 204, 211
- `src/hooks/useCloaking.tsx` line 66
- `src/components/workspace/WorkspaceShell.tsx` lines 105, 144
- `src/components/workspace/CommandPalette.tsx` line 71
- `src/components/modules/forge/QuickOpen.tsx` line 33
- `src/lib/trusted-sources.ts` line 6
- `src/lib/execution-allowlist.ts` line 179
- `src/lib/guest-identity.ts` line 7
- `src/pages/Dashboard.tsx` lines 90, 137, 255, 266, 401
- `src/pages/Project.tsx` lines 77, 120

**Example change pattern:**
```tsx
// FROM:
const STORAGE_KEY = 'parakleon-cloaking';

// TO:
const STORAGE_KEY = 'divine-node-cloaking';
```

### 3. REBRAND: Config File References

**Change .parakleon/ folder references to .divine-node/:**

**src/pages/Dashboard.tsx lines 209, 212-213, 282, 638, 795:**
```tsx
// FROM:
'.parakleon/studio.json'
'.parakleon/task_templates.json'
'.parakleon/studio.json'

// TO:
'.divine-node/config.json'
'.divine-node/task_templates.json'
'.divine-node/config.json'
```

**src/components/modules/settings/SettingsModule.tsx line 258:**
```tsx
// FROM:
GitHub owners and repos that auto-apply .parakleon configs

// TO:
GitHub owners and repos that auto-apply .divine-node configs
```

### 4. FIX: Agent Models (Replace hardcoded gpt-4)

**src/lib/demo-data.ts - Replace the entire defaultAgents array:**
```tsx
export const defaultAgents = [
  {
    name: 'Router Agent',
    role: 'router' as const,
    model: 'qwen2.5:7b',
    system_prompt: 'You are a routing agent that directs tasks to appropriate specialized agents.',
    enabled: true,
    permissions: { read: true, write: false, execute: false },
  },
  {
    name: 'Reasoning Agent',
    role: 'reasoner' as const,
    model: 'nous-hermes:latest',
    system_prompt: 'You are a reasoning agent that analyzes problems and breaks them into actionable steps.',
    enabled: true,
    permissions: { read: true, write: false, execute: false },
  },
  {
    name: 'Coder Agent',
    role: 'coder' as const,
    model: 'qwen2.5-coder:7b',
    system_prompt: 'You are a coding agent specialized in writing and refactoring code.',
    enabled: true,
    permissions: { read: true, write: true, execute: false },
  },
  {
    name: 'Designer Agent',
    role: 'designer' as const,
    model: 'phi4:latest',
    system_prompt: 'You are a design agent that creates UI/UX designs and styling.',
    enabled: true,
    permissions: { read: true, write: true, execute: false },
  },
  {
    name: 'Tester Agent',
    role: 'tester' as const,
    model: 'qwen2.5-coder:7b',
    system_prompt: 'You are a testing agent that writes and executes tests.',
    enabled: true,
    permissions: { read: true, write: true, execute: true },
  },
  {
    name: 'Security Agent',
    role: 'security' as const,
    model: 'dolphin-phi:latest',
    system_prompt: 'You are a security agent specialized in penetration testing and vulnerability analysis.',
    enabled: true,
    permissions: { read: true, write: true, execute: true },
  },
  {
    name: 'OSINT Agent',
    role: 'osint' as const,
    model: 'phi4:latest',
    system_prompt: 'You are an OSINT agent specialized in open-source intelligence gathering.',
    enabled: true,
    permissions: { read: true, write: false, execute: true },
  },
  {
    name: 'Memory Agent',
    role: 'memory' as const,
    model: 'phi4:latest',
    system_prompt: 'You are a memory agent that manages context and recalls relevant information.',
    enabled: true,
    permissions: { read: true, write: true, execute: false },
  },
  {
    name: 'Tools Agent',
    role: 'tools' as const,
    model: 'phi4:latest',
    system_prompt: 'You are a tools agent that selects and executes appropriate tools for tasks.',
    enabled: true,
    permissions: { read: true, write: false, execute: true },
  },
];
```

**src/components/modules/settings/SettingsModule.tsx line 216:**
```tsx
// FROM:
<p className="text-xs text-muted-foreground">gpt-4</p>

// TO:
<p className="text-xs text-muted-foreground">Local (Ollama)</p>
```

### 5. FIX: Legacy Port References

**src/components/modules/settings/SettingsModule.tsx lines 142 and 165:**
```tsx
// FROM:
defaultValue="http://127.0.0.1:8004"  // line 142
defaultValue="http://127.0.0.1:9004"  // line 165

// TO:
defaultValue="http://127.0.0.1:8010"  // line 142 (use same port, BackendSettings handles the rest)
defaultValue="http://127.0.0.1:8010"  // line 165
```

### 6. UPDATE: Page Titles and Meta

**src/index.html (or equivalent):**
```html
<title>Divine Node</title>
<meta name="description" content="Divine Node - AI Command Center with Nexus, Forge, and Shadow modules" />
```

### 7. UPDATE: Component Descriptions

Wherever you see descriptions mentioning "Parakleon", update them to reference:
- **Divine Node** - The overall platform
- **Nexus** - Chat/Agent orchestration module
- **Forge** - IDE/Code editor module
- **Shadow** - Security tools module

---

## SUMMARY OF CHANGES

| Category | What to Change | Count |
|----------|----------------|-------|
| Visual branding | "Parakleon Studio" → "Divine Node" | ~10 |
| Header | "PARAKLEON" → "DIVINE NODE" | 1 |
| Button labels | "Ask Parakleon" → "Ask Divine" | ~5 |
| LocalStorage keys | "parakleon-" → "divine-node-" | ~20 |
| Config paths | ".parakleon/" → ".divine-node/" | ~6 |
| Agent models | "gpt-4" → Local Ollama models | 5 |
| Legacy ports | 8004/9004 → 8010 | 2 |

**Total: ~50 changes across ~25 files**

---

## IMPORTANT NOTES

1. The module names stay the same: **Nexus**, **Forge**, **Shadow**
2. The project is now called **Divine Node** (not Parakleon Studio)
3. LocalStorage will reset for users (new key prefix) - this is expected
4. All agent models should default to local Ollama models, not GPT-4

Please make all these changes and confirm when complete.

---

## 8. UX REDESIGN: Module-Specific Layouts (IMPORTANT)

Currently, all modules share the same IDE-style layout with project name in the top bar and file explorer in the sidebar. This makes Nexus and Shadow feel cramped and IDE-like when they should feel like their own dedicated apps.

### The Vision

| Module | Layout Style | Sidebar Shows | Top Bar Shows |
|--------|--------------|---------------|---------------|
| **Nexus** | Clean chat app | Only module switcher (minimal) | "Divine Node - Nexus" (no repo name) |
| **Forge** | Full IDE | Module switcher + File explorer + Project info | Repo name, branch, file tabs |
| **Shadow** | Tools dashboard | Module switcher + Tool categories | "Divine Node - Shadow" + Target status |
| **Settings** | Settings page | Module switcher only | "Divine Node - Settings" |

### Changes to WorkspaceSidebar.tsx

Make the sidebar content **conditional based on activeModule**:

```tsx
export function WorkspaceSidebar() {
  const { sidebarOpen, setSidebarOpen } = usePanelState();
  const { activeModule, setActiveModule } = useWorkspace();

  const collapsed = !sidebarOpen;

  // Determine what to show based on module
  const showProjectContext = activeModule === 'forge' || activeModule === 'dashboard';
  const showFileExplorer = activeModule === 'forge';
  const showToolCategories = activeModule === 'shadow';

  return (
    <aside className={cn(
      "bg-sidebar border-r border-sidebar-border flex flex-col shrink-0 transition-all duration-200",
      // Nexus and Settings get minimal sidebar
      (activeModule === 'nexus' || activeModule === 'settings') && !collapsed ? "w-14" :
      collapsed ? "w-14" : "w-52",
    )}>
      {/* Module switcher - always visible */}
      <div className="p-2 border-b border-sidebar-border">
        {modules.map(module => (
          // ... existing module buttons
        ))}
      </div>

      {/* Conditional content based on module */}
      {!collapsed && (
        <ScrollArea className="flex-1">
          {/* Project context - only for Forge/Dashboard */}
          {showProjectContext && (
            <div className="p-3">
              <div className="text-xs font-mono uppercase text-muted-foreground mb-2">
                Project
              </div>
              {/* ... project info */}
            </div>
          )}

          {/* File explorer - only for Forge */}
          {showFileExplorer && (
            <div className="p-3 border-t border-border">
              {/* File tree component */}
            </div>
          )}

          {/* Tool categories - only for Shadow */}
          {showToolCategories && (
            <div className="p-3">
              <div className="text-xs font-mono uppercase text-muted-foreground mb-2">
                Categories
              </div>
              {/* Tool category filters */}
            </div>
          )}
        </ScrollArea>
      )}
    </aside>
  );
}
```

### Changes to WorkspaceTopBar.tsx

Make the top bar content **conditional based on activeModule**:

```tsx
export function WorkspaceTopBar({ project, repoInfo }) {
  const { activeModule } = useWorkspace();

  // Module-specific titles
  const getModuleTitle = () => {
    switch (activeModule) {
      case 'nexus': return 'Nexus';
      case 'forge': return repoInfo ? `${repoInfo.owner}/${repoInfo.repo}` : 'Forge';
      case 'shadow': return 'Shadow';
      case 'settings': return 'Settings';
      case 'dashboard': return project?.name || 'Dashboard';
      default: return 'Divine Node';
    }
  };

  // Only show repo/branch info for Forge
  const showRepoInfo = activeModule === 'forge' && repoInfo;

  // Only show target status for Shadow
  const showTargetStatus = activeModule === 'shadow';

  return (
    <header className="h-12 border-b border-border bg-surface-1 flex items-center px-4">
      {/* Left: Brand + Module title */}
      <div className="flex items-center gap-3">
        <span className="font-mono font-bold gradient-text">DN</span>
        <span className="text-muted-foreground">/</span>
        <span className="font-medium">{getModuleTitle()}</span>

        {/* Repo info - only for Forge */}
        {showRepoInfo && (
          <>
            <Badge variant="outline" className="text-xs">
              {repoInfo.branch}
            </Badge>
          </>
        )}
      </div>

      {/* Center: Forge-only file tabs or Shadow target selector */}
      <div className="flex-1 flex justify-center">
        {activeModule === 'forge' && (
          // File tabs here
        )}
        {showTargetStatus && (
          <TargetSelector />
        )}
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2">
        {/* ... existing actions */}
      </div>
    </header>
  );
}
```

### Module-Specific Styling

**Nexus (Chat):**
- Full-height chat area, no clutter
- Centered conversation
- Agent selector as floating pills or in a collapsible drawer
- No file explorer, no project info

**Forge (IDE):**
- Full IDE experience
- File explorer in sidebar
- Tab bar for open files
- Project/repo name prominently displayed
- Problems panel, terminal, etc.

**Shadow (Tools):**
- Dashboard-style layout
- Tool cards/grid as main content
- Category filters in sidebar or as tabs
- Target status (Termux/Desktop) prominently displayed
- Results vault accessible

### Visual Separation

Each module should feel distinct:

```css
/* Nexus - clean, focused */
[data-module="nexus"] {
  --module-accent: var(--primary);
}

/* Forge - professional IDE */
[data-module="forge"] {
  --module-accent: hsl(210 100% 55%); /* Blue */
}

/* Shadow - tactical */
[data-module="shadow"] {
  --module-accent: hsl(0 100% 60%); /* Red */
}
```

### Navigation Between Modules

The module switcher (Nexus/Forge/Shadow icons) should:
1. Always be visible (left edge or top)
2. Be compact when not needed
3. Expand on hover or when collapsed sidebar is clicked
4. Show active module with accent color

This way:
- **Nexus** = Open it, you're in a chat app
- **Forge** = Open it, you're in VS Code
- **Shadow** = Open it, you're in a security dashboard

---

## 9. REPLACE: Welcome Screen Icon & Message

### Replace Lightning Bolt with Custom Avatar

The welcome screen currently uses a Zap (lightning bolt) icon. Replace it with a custom avatar image.

**Step 1: Add the avatar image to the project**

Upload `dvn-avatar.png` to `public/dvn-avatar.png` or `src/assets/dvn-avatar.png`

**Step 2: Update src/pages/Dashboard.tsx around line 441:**

```tsx
// FROM:
<Zap className="h-12 w-12 text-primary" />

// TO:
<img
  src="/dvn-avatar.png"
  alt="Divine Node"
  className="h-16 w-16 rounded-full ring-2 ring-primary/50"
/>
```

**Step 3: Update other Zap icons used for branding:**

**src/components/layout/TopBar.tsx line 55:**
```tsx
// FROM:
<Zap className="h-5 w-5 sm:h-6 sm:w-6 text-primary" />

// TO:
<img src="/dvn-avatar.png" alt="DN" className="h-6 w-6 rounded-full" />
```

**src/pages/Auth.tsx line 52:**
```tsx
// FROM:
<Zap className="h-8 w-8 text-primary" />

// TO:
<img src="/dvn-avatar.png" alt="Divine Node" className="h-10 w-10 rounded-full" />
```

### Update Welcome Messages

**src/pages/Dashboard.tsx lines 444-447 - Replace the entire welcome section:**

```tsx
// FROM:
Welcome to Parakleon Studio

// TO (more impactful welcome):
<div className="text-center space-y-4">
  <img
    src="/dvn-avatar.png"
    alt="Divine Node"
    className="h-20 w-20 mx-auto rounded-full ring-2 ring-primary/50 shadow-lg shadow-primary/20"
  />
  <h1 className="text-3xl font-bold gradient-text">Divine Node</h1>
  <p className="text-muted-foreground max-w-md mx-auto">
    Your AI command center. Three modules, infinite possibilities.
  </p>
  <div className="flex justify-center gap-6 pt-4">
    <div className="text-center">
      <MessageSquare className="h-6 w-6 mx-auto text-primary mb-1" />
      <span className="text-xs text-muted-foreground">Nexus</span>
    </div>
    <div className="text-center">
      <Code2 className="h-6 w-6 mx-auto text-blue-500 mb-1" />
      <span className="text-xs text-muted-foreground">Forge</span>
    </div>
    <div className="text-center">
      <Shield className="h-6 w-6 mx-auto text-red-500 mb-1" />
      <span className="text-xs text-muted-foreground">Shadow</span>
    </div>
  </div>
</div>
```

**src/lib/demo-data.ts line 165 - Update chat welcome:**
```tsx
// FROM:
content: 'Welcome to Parakleon Studio. I\'m your AI assistant ready to help with coding, design, and testing.',

// TO:
content: 'Welcome to Divine Node. I\'m your AI command center with specialized agents for coding, security, and OSINT. Use Nexus to chat, Forge to code, and Shadow for security tools.',
```

**src/hooks/useNexusChat.ts lines 37, 60, 76 - Update Nexus welcome:**
```tsx
// FROM:
content: 'Welcome to Nexus. I\'m your AI command center for orchestrating agents and tools.',

// TO:
content: 'Welcome to Nexus. Select an agent above or just ask - I\'ll route your request to the right specialist. Try: "scan example.com" or "help me write a Python script".',
```

### Taglines to Use

Pick one for different contexts:

| Context | Tagline |
|---------|---------|
| Dashboard | "Your AI command center. Three modules, infinite possibilities." |
| Nexus | "Chat with specialized agents. Security, coding, OSINT - all in one place." |
| Forge | "AI-powered IDE. Write code, get suggestions, ship faster." |
| Shadow | "214+ security tools. Cloak your tracks. Own the shadows." |
| Auth page | "Divine Node - Where AI meets security." |

---

## 10. PWA SETUP: Progressive Web App Support

Divine Node needs to be installable as a PWA on mobile devices (Android/iOS). Currently there is NO PWA support. Please add it.

### Step 1: Install vite-plugin-pwa

Add to package.json devDependencies:
```json
"vite-plugin-pwa": "^0.20.0"
```

Then run `npm install` or `pnpm install`.

### Step 2: Configure Vite Plugin

**vite.config.ts - Add PWA plugin:**

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import path from 'path'
import { VitePWA } from 'vite-plugin-pwa'

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['dvn-avatar.png', 'favicon.ico'],
      manifest: {
        name: 'Divine Node',
        short_name: 'Divine',
        description: 'AI Command Center - Nexus, Forge, Shadow',
        theme_color: '#0a0a0f',
        background_color: '#0a0a0f',
        display: 'standalone',
        orientation: 'portrait-primary',
        start_url: '/',
        scope: '/',
        icons: [
          {
            src: '/dvn-avatar-192.png',
            sizes: '192x192',
            type: 'image/png',
            purpose: 'any'
          },
          {
            src: '/dvn-avatar-512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'any'
          },
          {
            src: '/dvn-avatar-512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'maskable'
          }
        ],
        categories: ['developer', 'security', 'utilities'],
        shortcuts: [
          {
            name: 'Nexus Chat',
            short_name: 'Nexus',
            url: '/?module=nexus',
            icons: [{ src: '/dvn-avatar-192.png', sizes: '192x192' }]
          },
          {
            name: 'Shadow Tools',
            short_name: 'Shadow',
            url: '/?module=shadow',
            icons: [{ src: '/dvn-avatar-192.png', sizes: '192x192' }]
          }
        ]
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/api\.github\.com\/.*/i,
            handler: 'NetworkFirst',
            options: {
              cacheName: 'github-api-cache',
              expiration: {
                maxEntries: 50,
                maxAgeSeconds: 60 * 60 // 1 hour
              }
            }
          },
          {
            urlPattern: /^https:\/\/fonts\.googleapis\.com\/.*/i,
            handler: 'CacheFirst',
            options: {
              cacheName: 'google-fonts-cache',
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 60 * 60 * 24 * 365 // 1 year
              }
            }
          }
        ]
      }
    })
  ],
  // ... rest of config
})
```

### Step 3: Add PWA Icons

Create these icon files in `/public/`:

| File | Size | Purpose |
|------|------|---------|
| `dvn-avatar-192.png` | 192x192 | Standard app icon |
| `dvn-avatar-512.png` | 512x512 | High-res + maskable |
| `dvn-avatar.png` | Any | Favicon/branding |
| `apple-touch-icon.png` | 180x180 | iOS home screen |

**To generate these from the original avatar:**
```bash
# Using ImageMagick (if available)
convert dvn-avatar.png -resize 192x192 public/dvn-avatar-192.png
convert dvn-avatar.png -resize 512x512 public/dvn-avatar-512.png
convert dvn-avatar.png -resize 180x180 public/apple-touch-icon.png
```

Or use an online tool like https://realfavicongenerator.net/

### Step 4: Update index.html

**index.html - Add PWA meta tags in `<head>`:**

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />

    <!-- PWA Meta Tags -->
    <meta name="theme-color" content="#0a0a0f" />
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
    <meta name="apple-mobile-web-app-title" content="Divine Node" />

    <!-- Icons -->
    <link rel="icon" type="image/png" href="/dvn-avatar.png" />
    <link rel="apple-touch-icon" href="/apple-touch-icon.png" />

    <!-- Manifest -->
    <link rel="manifest" href="/manifest.webmanifest" />

    <title>Divine Node</title>
    <meta name="description" content="Divine Node - AI Command Center with Nexus, Forge, and Shadow modules" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

### Step 5: Add Install Prompt Component (Optional but Recommended)

**Create src/components/pwa/InstallPrompt.tsx:**

```tsx
import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Download, X } from 'lucide-react';

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

export function InstallPrompt() {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [showPrompt, setShowPrompt] = useState(false);

  useEffect(() => {
    const handler = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
      // Show prompt after a delay
      setTimeout(() => setShowPrompt(true), 3000);
    };

    window.addEventListener('beforeinstallprompt', handler);
    return () => window.removeEventListener('beforeinstallprompt', handler);
  }, []);

  const handleInstall = async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === 'accepted') {
      setDeferredPrompt(null);
      setShowPrompt(false);
    }
  };

  const handleDismiss = () => {
    setShowPrompt(false);
    // Don't show again for 7 days
    localStorage.setItem('divine-node-pwa-dismissed', Date.now().toString());
  };

  // Check if dismissed recently
  useEffect(() => {
    const dismissed = localStorage.getItem('divine-node-pwa-dismissed');
    if (dismissed) {
      const daysSince = (Date.now() - parseInt(dismissed)) / (1000 * 60 * 60 * 24);
      if (daysSince < 7) {
        setShowPrompt(false);
      }
    }
  }, []);

  if (!showPrompt || !deferredPrompt) return null;

  return (
    <div className="fixed bottom-4 left-4 right-4 sm:left-auto sm:right-4 sm:w-80 bg-surface-2 border border-border rounded-lg p-4 shadow-xl z-50 animate-in slide-in-from-bottom-4">
      <button
        onClick={handleDismiss}
        className="absolute top-2 right-2 text-muted-foreground hover:text-foreground"
      >
        <X className="h-4 w-4" />
      </button>
      <div className="flex items-start gap-3">
        <img src="/dvn-avatar.png" alt="Divine Node" className="h-12 w-12 rounded-lg" />
        <div className="flex-1">
          <h3 className="font-semibold text-sm">Install Divine Node</h3>
          <p className="text-xs text-muted-foreground mt-1">
            Add to home screen for quick access
          </p>
          <Button size="sm" className="mt-3 w-full" onClick={handleInstall}>
            <Download className="h-4 w-4 mr-2" />
            Install
          </Button>
        </div>
      </div>
    </div>
  );
}
```

### Step 6: Add InstallPrompt to App

**src/App.tsx or src/main.tsx - Add the component:**

```tsx
import { InstallPrompt } from '@/components/pwa/InstallPrompt';

function App() {
  return (
    <>
      {/* ... existing app content */}
      <InstallPrompt />
    </>
  );
}
```

### Step 7: Register Service Worker

**vite-plugin-pwa** handles this automatically with `registerType: 'autoUpdate'`, but you can add manual control if needed.

**src/main.tsx - Optional manual registration:**

```tsx
import { registerSW } from 'virtual:pwa-register';

// Auto-update service worker
const updateSW = registerSW({
  onNeedRefresh() {
    // Show update notification if desired
    if (confirm('New version available. Reload?')) {
      updateSW(true);
    }
  },
  onOfflineReady() {
    console.log('Divine Node is ready for offline use');
  },
});
```

### PWA Testing Checklist

After implementing, verify:

- [ ] Manifest loads: Check DevTools → Application → Manifest
- [ ] Service worker registered: DevTools → Application → Service Workers
- [ ] Install prompt appears on mobile (or desktop Chrome)
- [ ] App works offline (basic caching)
- [ ] Icons display correctly on home screen
- [ ] `theme_color` matches app background

### Mobile Installation

**Android (Chrome):**
1. Visit the deployed site
2. Tap the "Install" banner or menu → "Add to Home screen"
3. App icon appears on home screen

**iOS (Safari):**
1. Visit the deployed site
2. Tap Share → "Add to Home Screen"
3. Confirm the name and tap Add

---

## FINAL SUMMARY

| Section | What to Do |
|---------|------------|
| 1-3 | Rebrand all "Parakleon" → "Divine Node" |
| 4 | Fix agent models (gpt-4 → Ollama) |
| 5 | Fix legacy ports (8004/9004 → 8010) |
| 6 | Update page titles |
| 7 | Update component descriptions |
| 8 | Module-specific layouts (Nexus=chat, Forge=IDE, Shadow=dashboard) |
| 9 | Replace Zap icon with dvn-avatar.png, update messages |
| 10 | Add PWA support for mobile installation |

**Total changes: ~60+ across ~30 files**

Please implement all sections in order and confirm when complete.
