// Create the Divine Debugger panel in DevTools
chrome.devtools.panels.create(
    "Divine Debugger",
    "icons/icon48.png",
    "devtools/panel.html",
    function(panel) {
        console.log("Divine Debugger panel created");
    }
);

// Create the PKN Dev Tools panel
chrome.devtools.panels.create(
    "PKN Dev Tools",
    "icons/icon48.png",
    "devtools/devtools-panel.html",
    function(panel) {
        console.log("PKN Dev Tools panel created");
    }
);
