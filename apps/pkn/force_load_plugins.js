// ============================================
// FORCE LOAD PKN PLUGINS - Browser Console
// ============================================
// Open http://localhost:8010/pkn.html
// Press F12 for console
// Copy and paste this entire script
// ============================================

console.clear();
console.log('%c🔧 FORCING PLUGIN SYSTEM RELOAD...', 'color: #ff0; font-size: 18px; font-weight: bold;');

// Force reload main.js with cache busting
const timestamp = Date.now();

async function forceLoadPlugins() {
    try {
        console.log('%c1. Loading Plugin Manager...', 'color: #0ff;');

        // Dynamic import with cache busting
        const { pluginManager } = await import(`./js/plugin-manager.js?v=${timestamp}`);
        window.pluginManager = pluginManager;

        console.log('%c✅ Plugin Manager loaded', 'color: #0f0;');

        console.log('%c2. Loading Plugin UI...', 'color: #0ff;');
        const pluginsUI = await import(`./js/plugins-ui.js?v=${timestamp}`);

        console.log('%c✅ Plugin UI loaded', 'color: #0f0;');

        console.log('%c3. Initializing Plugin Manager...', 'color: #0ff;');
        await pluginManager.init();

        console.log('%c✅ Plugin Manager initialized', 'color: #0f0;');

        console.log('%c4. Registering plugins...', 'color: #0ff;');

        // Load and register all plugins
        const plugins = [
            {
                name: 'Welcome Message',
                manifestPath: './plugins/welcome-message/manifest.json',
                pluginPath: './plugins/welcome-message/plugin.js',
                className: 'WelcomeMessagePlugin'
            },
            {
                name: 'Context Detector',
                manifestPath: './plugins/context-detector/manifest.json',
                pluginPath: './plugins/context-detector/plugin.js',
                className: 'SmartContextDetectorPlugin'
            },
            {
                name: 'Voice I/O',
                manifestPath: './plugins/voice-io/manifest.json',
                pluginPath: './plugins/voice-io/plugin.js',
                className: 'VoiceIOPlugin'
            },
            {
                name: 'Quick Actions',
                manifestPath: './plugins/quick-actions/manifest.json',
                pluginPath: './plugins/quick-actions/plugin.js',
                className: 'QuickActionsPlugin'
            },
            {
                name: 'Agent Memory',
                manifestPath: './plugins/agent-memory/manifest.json',
                pluginPath: './plugins/agent-memory/plugin.js',
                className: 'AgentMemoryPlugin'
            },
            {
                name: 'Meeting Summarizer',
                manifestPath: './plugins/meeting-summarizer/manifest.json',
                pluginPath: './plugins/meeting-summarizer/plugin.js',
                className: 'MeetingSummarizerPlugin'
            },
            {
                name: 'Diff Viewer',
                manifestPath: './plugins/diff-viewer/manifest.json',
                pluginPath: './plugins/diff-viewer/plugin.js',
                className: 'DiffViewerPlugin'
            },
            {
                name: 'Code Sandbox',
                manifestPath: './plugins/code-sandbox/manifest.json',
                pluginPath: './plugins/code-sandbox/plugin.js',
                className: 'CodeSandboxPlugin'
            },
            {
                name: 'Collaboration Theater',
                manifestPath: './plugins/collaboration-theater/manifest.json',
                pluginPath: './plugins/collaboration-theater/plugin.js',
                className: 'CollaborationTheaterPlugin'
            },
            {
                name: 'Dark Web OSINT',
                manifestPath: './plugins/darkweb-osint/manifest.json',
                pluginPath: './plugins/darkweb-osint/plugin.js',
                className: 'DarkWebOSINTPlugin'
            }
        ];

        for (const plugin of plugins) {
            try {
                // Load manifest
                const manifestRes = await fetch(`${plugin.manifestPath}?v=${timestamp}`);
                const manifest = await manifestRes.json();

                // Load plugin module
                const module = await import(`${plugin.pluginPath}?v=${timestamp}`);
                const PluginClass = module[plugin.className] || module.default;

                // Register
                await pluginManager.register(manifest, PluginClass);

                console.log(`%c  ✅ ${plugin.name}`, 'color: #0f0;');
            } catch (error) {
                console.log(`%c  ❌ ${plugin.name}: ${error.message}`, 'color: #f00;');
            }
        }

        const registered = pluginManager.getAllPlugins();
        console.log(`\n%c✅ SUCCESS! ${registered.length} plugins loaded`, 'color: #0f0; font-size: 16px; font-weight: bold;');

        console.log('\n%c📋 Registered Plugins:', 'color: #0ff; font-size: 14px;');
        registered.forEach((p, i) => {
            console.log(`%c  ${i+1}. ${p.manifest.name} (${p.enabled ? 'ENABLED' : 'disabled'})`,
                p.enabled ? 'color: #0f0;' : 'color: #888;');
        });

        console.log('\n%c🎯 Now try:', 'color: #0ff; font-size: 14px;');
        console.log('%c  1. Click sidebar (left edge)', 'color: #fff;');
        console.log('%c  2. Click "🔌 Plugins"', 'color: #fff;');
        console.log('%c  3. Or run: openPluginsManager()', 'color: #fff;');

        // Make openPluginsManager available
        const { openPluginsManager } = await import(`./js/plugins-ui.js?v=${timestamp}`);
        window.openPluginsManager = openPluginsManager;

        console.log('\n%c✅ openPluginsManager() is now available!', 'color: #0f0; font-weight: bold;');

    } catch (error) {
        console.log(`%c❌ FATAL ERROR: ${error.message}`, 'color: #f00; font-size: 16px; font-weight: bold;');
        console.error(error);
    }
}

// Run it
forceLoadPlugins();
