// ============================================
// PKN Plugin System - Browser Console Test
// ============================================
// Copy and paste this into your browser console (F12)
// when you have PKN open at http://localhost:8010/pkn.html

console.log('%c🔌 PKN Plugin System Test', 'color: #0ff; font-size: 20px; font-weight: bold;');
console.log('%c========================================', 'color: #0ff;');

// Wait for plugin manager to be available
setTimeout(() => {
    if (typeof window.pluginManager === 'undefined') {
        console.log('%c❌ Plugin Manager not loaded yet', 'color: #f00;');
        console.log('%cPlease refresh the page and try again', 'color: #ffa500;');
        return;
    }

    const plugins = window.pluginManager.getAllPlugins();

    console.log(`%c✅ Plugin Manager Loaded`, 'color: #0f0;');
    console.log(`%cTotal Plugins: ${plugins.length}`, 'color: #0ff; font-size: 16px;');
    console.log('%c========================================', 'color: #0ff;');

    plugins.forEach((plugin, index) => {
        const status = plugin.enabled ? '✅' : '⚪';
        const autoEnable = plugin.manifest.autoEnable ? ' (AUTO)' : '';
        console.log(
            `%c${status} ${index + 1}. ${plugin.manifest.name}${autoEnable}`,
            `color: ${plugin.enabled ? '#0f0' : '#888'}; font-weight: bold;`
        );
        console.log(`   ID: ${plugin.manifest.id} | v${plugin.manifest.version}`);
        console.log(`   ${plugin.manifest.description}`);
    });

    console.log('%c========================================', 'color: #0ff;');
    console.log('%c📊 Plugin Status Summary:', 'color: #0ff; font-size: 14px;');

    const enabled = plugins.filter(p => p.enabled).length;
    const autoEnabled = plugins.filter(p => p.manifest.autoEnable).length;

    console.log(`%c   Enabled: ${enabled}/${plugins.length}`, 'color: #0f0;');
    console.log(`%c   Auto-Enable: ${autoEnabled}`, 'color: #0ff;');

    console.log('%c========================================', 'color: #0ff;');
    console.log('%c🎯 Try These Commands:', 'color: #0ff; font-size: 14px;');
    console.log('%c   pluginManager.getAllPlugins()', 'color: #ffa500;');
    console.log('%c   pluginManager.enable("plugin-id")', 'color: #ffa500;');
    console.log('%c   pluginManager.disable("plugin-id")', 'color: #ffa500;');
    console.log('%c   window.quickActions (if enabled)', 'color: #ffa500;');
    console.log('%c   window.agentMemory (if enabled)', 'color: #ffa500;');
    console.log('%c========================================', 'color: #0ff;');

    // Test plugin functionality
    console.log('%c🧪 Testing Plugin Functionality...', 'color: #0ff; font-size: 14px;');

    // Test Context Detector
    const contextDetector = plugins.find(p => p.manifest.id === 'context-detector');
    if (contextDetector && contextDetector.enabled) {
        console.log('%c   ✅ Context Detector: Active', 'color: #0f0;');
    }

    // Test Quick Actions
    const quickActions = plugins.find(p => p.manifest.id === 'quick-actions');
    if (quickActions && quickActions.enabled) {
        const workflows = quickActions.instance.builtInActions?.length || 0;
        console.log(`%c   ✅ Quick Actions: ${workflows} workflows ready`, 'color: #0f0;');
    }

    // Test Agent Memory
    const agentMemory = plugins.find(p => p.manifest.id === 'agent-memory');
    if (agentMemory && agentMemory.enabled) {
        const totalMemories = Object.values(agentMemory.instance.memories || {})
            .reduce((sum, arr) => sum + arr.length, 0);
        console.log(`%c   ✅ Agent Memory: ${totalMemories} memories stored`, 'color: #0f0;');
    }

    // Test Event Bus
    if (typeof window.eventBus !== 'undefined') {
        console.log('%c   ✅ Event Bus: Operational', 'color: #0f0;');
    }

    console.log('%c========================================', 'color: #0ff;');
    console.log('%c🎉 All Plugin Tests Complete!', 'color: #0f0; font-size: 16px; font-weight: bold;');

}, 2000);
