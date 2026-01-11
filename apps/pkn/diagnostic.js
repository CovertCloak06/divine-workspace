// Paste this into browser console (F12)
console.clear();
console.log("=== PKN DIAGNOSTIC ===\n");

// Check 1: toggleSettings function
console.log("1. toggleSettings function:");
console.log("   Type:", typeof window.toggleSettings);
if (typeof window.toggleSettings === 'function') {
    console.log("   ✓ Function exists");
    try {
        window.toggleSettings();
        console.log("   ✓ Function executed successfully");
    } catch(e) {
        console.error("   ✗ Error calling toggleSettings:", e.message);
    }
} else {
    console.error("   ✗ toggleSettings is not defined!");
}

// Check 2: Settings overlay element
console.log("\n2. Settings overlay:");
const settingsOverlay = document.getElementById('settingsOverlay');
if (settingsOverlay) {
    console.log("   ✓ Element exists");
    console.log("   Display:", getComputedStyle(settingsOverlay).display);
    console.log("   Visibility:", getComputedStyle(settingsOverlay).visibility);
} else {
    console.error("   ✗ settingsOverlay element not found!");
}

// Check 3: Mode toggle buttons
console.log("\n3. Mode toggle near input:");
const modeToggle = document.querySelector('.agent-mode-toggle-header');
if (modeToggle) {
    console.log("   Element exists");
    console.log("   Display:", getComputedStyle(modeToggle).display);
    console.log("   Visibility:", getComputedStyle(modeToggle).visibility);
    console.log("   HTML:", modeToggle.innerHTML.substring(0, 100));
} else {
    console.log("   ✓ Mode toggle not found (correctly hidden)");
}

// Check 4: Lightning bolts
console.log("\n4. Lightning bolt count:");
const allText = document.body.innerText;
const lightningCount = (allText.match(/⚡/g) || []).length;
console.log("   Found:", lightningCount, "lightning bolts in page");

const lightningElements = Array.from(document.querySelectorAll('*')).filter(el => 
    el.textContent.includes('⚡') && el.children.length === 0
);
console.log("   Elements containing ⚡:", lightningElements.length);
lightningElements.forEach((el, i) => {
    console.log(`   [${i}] ${el.tagName}.${el.className}:`, el.textContent.trim());
});

// Check 5: Header button backgrounds
console.log("\n5. Header button theme:");
const activeBtn = document.querySelector('.agent-mode-btn.active');
if (activeBtn) {
    const bg = getComputedStyle(activeBtn).backgroundColor;
    console.log("   Active button background:", bg);
    if (bg.includes('0, 255, 255')) {
        console.error("   ✗ Still using cyan!");
    } else {
        console.log("   ✓ Not using cyan");
    }
}

console.log("\n=== END DIAGNOSTIC ===");
