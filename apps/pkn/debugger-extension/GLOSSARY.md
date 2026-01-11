# 📚 Beginner's Glossary - Divine Debugger & Web Development

A visual reference guide for understanding code components, structures, and how they work together.

---

## 📄 File Types

| Extension | Name | Purpose | Contains | Example Use |
|-----------|------|---------|----------|-------------|
| `.html` | HyperText Markup Language | Structure of webpage | Tags, content, layout | `panel.html` - Main UI structure |
| `.css` | Cascading Style Sheets | Visual styling | Colors, sizes, positions | `debugger.css` - How UI looks |
| `.js` | JavaScript | Behavior and logic | Functions, variables, events | `code-analyzer.js` - Analysis logic |
| `.py` | Python | Backend scripts | Data processing, automation | `run_all_checks.py` - Terminal version |
| `.md` | Markdown | Documentation | Text, tables, instructions | `README.md` - Project docs |

---

## 🏗️ HTML Structure

### Basic Document Structure

| Tag | Purpose | Opens/Closes | Contains | Required? |
|-----|---------|--------------|----------|-----------|
| `<html>` | Root element | `<html>` ... `</html>` | Entire webpage | ✅ Yes |
| `<head>` | Document metadata | `<head>` ... `</head>` | Title, CSS links, scripts | ✅ Yes |
| `<body>` | Visible content | `<body>` ... `</body>` | Everything user sees | ✅ Yes |
| `<div>` | Container/section | `<div>` ... `</div>` | Groups other elements | ⚪ Common |
| `<script>` | JavaScript code | `<script>` ... `</script>` | JS code or file link | ⚪ Optional |

**Example Structure:**
```html
<html>                          <!-- Start of document -->
  <head>                        <!-- Document info (invisible) -->
    <title>Page Title</title>   <!-- Browser tab text -->
    <link rel="stylesheet" href="style.css">  <!-- Load CSS -->
  </head>
  <body>                        <!-- Visible content starts -->
    <div id="container">        <!-- Group content in box -->
      <h1>Hello World</h1>      <!-- Big heading -->
      <p>Text here</p>          <!-- Paragraph -->
    </div>
  </body>
</html>
```

### Common HTML Elements

| Element | Purpose | Attributes | Visual Result | Usage in Divine Debugger |
|---------|---------|------------|---------------|--------------------------|
| `<button>` | Clickable button | `id`, `class`, `onclick` | Rectangle you can click | `<button id="runAnalysis">Run</button>` |
| `<input>` | User input field | `type`, `placeholder`, `value` | Box to type in | `<input id="projectUrl" value="http://...">` |
| `<div>` | Container box | `id`, `class`, `style` | Invisible box (until styled) | `<div class="panel">...</div>` |
| `<h1>` - `<h6>` | Headings | `class`, `style` | Large bold text (h1 biggest) | `<h3>Code Analysis</h3>` |
| `<p>` | Paragraph | `class`, `style` | Block of text | `<p>Click button to scan</p>` |
| `<span>` | Inline text | `class`, `style` | Small text section | `<span style="color: red;">Error</span>` |

### Important Attributes

| Attribute | Purpose | Values | Example | How It's Used |
|-----------|---------|--------|---------|---------------|
| `id` | Unique identifier | Any unique name | `id="runAnalysis"` | JavaScript finds element: `getElementById('runAnalysis')` |
| `class` | Style category | Any name(s) | `class="btn-primary"` | CSS targets: `.btn-primary { ... }` |
| `style` | Inline styling | CSS properties | `style="color: red;"` | Direct styling (overrides CSS files) |
| `onclick` | Click handler | JavaScript code | `onclick="runScan()"` | Runs function when clicked |
| `placeholder` | Input hint | Any text | `placeholder="Enter URL"` | Gray text in empty input |

---

## 🎨 CSS Properties

### Layout & Positioning

| Property | What It Controls | Values | Effect | Visual Example |
|----------|------------------|--------|--------|----------------|
| `margin` | Space **outside** element | `10px`, `0 auto`, `-5px` | Pushes element away from others | `margin: 10px;` adds 10px gap around element |
| `margin-left` | Space on **left** side | `20px`, `auto`, `-10px` | (+) moves element RIGHT<br>(-) moves element LEFT | `margin-left: 20px;` shifts element 20px to the right |
| `margin-right` | Space on **right** side | `20px`, `auto`, `-10px` | (+) adds space on right<br>(-) pulls from right | `margin-right: 20px;` adds 20px gap on right |
| `padding` | Space **inside** element | `10px`, `5px 10px` | Pushes content away from edges | `padding: 10px;` creates 10px breathing room inside |
| `padding-left` | Inner space on left | `15px` | Content shifts RIGHT from left edge | `padding-left: 15px;` indents content 15px |
| `width` | Element width | `100px`, `50%`, `auto` | How wide element is | `width: 200px;` makes element 200px wide |
| `height` | Element height | `100px`, `50%`, `auto` | How tall element is | `height: 100px;` makes element 100px tall |
| `position` | Positioning method | `static`, `relative`, `absolute`, `fixed` | How element is placed | `position: fixed;` sticks to screen |
| `top` | Distance from top | `10px`, `50%` | Moves element down from top | `top: 10px;` with `position: absolute` |
| `left` | Distance from left | `10px`, `50%` | Moves element right from left | `left: 20px;` with `position: absolute` |
| `z-index` | Stacking order | `1`, `999`, `-1` | Higher = on top | `z-index: 9999;` appears above everything |

**Visual Guide - Margin vs Padding:**
```
┌─────────────────────────────────┐  ← margin (space around element)
│ ┌─────────────────────────────┐ │
│ │ ┌─────────────────────────┐ │ │  ← padding (space inside element)
│ │ │                         │ │ │
│ │ │    Actual Content       │ │ │
│ │ │                         │ │ │
│ │ └─────────────────────────┘ │ │
│ └─────────────────────────────┘ │
└─────────────────────────────────┘
```

### Appearance & Colors

| Property | What It Controls | Values | Effect | Example |
|----------|------------------|--------|--------|---------|
| `background` | Background color/image | `#00FFFF`, `rgb(0,255,255)`, `url(...)` | Fills element with color | `background: #00FFFF;` (cyan) |
| `background-color` | Background color only | `#111`, `red`, `rgba(0,0,0,0.5)` | Solid color fill | `background-color: #111;` (dark) |
| `color` | Text color | `#00FFFF`, `white`, `rgb(...)` | Changes text color | `color: #00FFFF;` (cyan text) |
| `border` | Element outline | `1px solid #00FFFF` | Draws border around element | `border: 2px solid cyan;` |
| `border-radius` | Corner rounding | `4px`, `50%` | Rounds sharp corners | `border-radius: 8px;` (smooth corners) |
| `opacity` | Transparency | `0` to `1` | 0=invisible, 1=solid | `opacity: 0.5;` (50% see-through) |
| `box-shadow` | Element shadow | `0 2px 4px rgba(...)` | Adds shadow behind element | `box-shadow: 0 4px 8px #000;` |

### Text Styling

| Property | What It Controls | Values | Effect | Example |
|----------|------------------|--------|--------|---------|
| `font-size` | Text size | `12px`, `1.5rem`, `14pt` | Bigger = larger text | `font-size: 16px;` |
| `font-family` | Text typeface | `Arial`, `monospace`, `'Courier New'` | Changes font style | `font-family: monospace;` (code font) |
| `font-weight` | Text thickness | `normal`, `bold`, `400`, `700` | Makes text bolder/lighter | `font-weight: bold;` |
| `text-align` | Horizontal alignment | `left`, `center`, `right` | Where text sits | `text-align: center;` |
| `line-height` | Space between lines | `1.5`, `20px` | Vertical spacing of text | `line-height: 1.6;` (readable) |

### Display & Visibility

| Property | What It Controls | Values | Effect | When to Use |
|----------|------------------|--------|--------|-------------|
| `display` | Element rendering | `block`, `inline`, `none`, `flex`, `grid` | How element behaves | `display: none;` hides element completely |
| `visibility` | Element visibility | `visible`, `hidden` | `hidden` = invisible but takes space | `visibility: hidden;` keeps layout |
| `overflow` | Content overflow | `visible`, `hidden`, `scroll`, `auto` | What happens if content too big | `overflow: auto;` adds scrollbar if needed |

---

## ⚙️ JavaScript Concepts

### Variables & Scope

| Concept | Syntax | Purpose | Scope | Example |
|---------|--------|---------|-------|---------|
| **let** | `let varName = value;` | Declare changeable variable | Block scope | `let count = 0;` |
| **const** | `const NAME = value;` | Declare constant (can't change) | Block scope | `const MAX = 100;` |
| **var** (old) | `var name = value;` | Old-style variable | Function scope | `var x = 5;` (avoid in new code) |
| **window.variable** | `window.myVar = value;` | Global variable | Entire page | `window.ACTIVE_MODEL = 'gpt-4';` |
| **Local scope** | Inside `{ }` | Only accessible in that block | Block | Function/if statement variables |
| **Global scope** | Outside functions | Accessible everywhere | Entire file | Variables at top of file |

**Scope Example:**
```javascript
let globalVar = 'I exist everywhere';  // Global - accessible anywhere

function myFunction() {
    let localVar = 'Only here';  // Local - only in this function
    console.log(globalVar);  // ✅ Works - can access global
    console.log(localVar);   // ✅ Works - in same scope
}

console.log(globalVar);  // ✅ Works - global
console.log(localVar);   // ❌ ERROR - localVar doesn't exist here
```

**Local vs Window Variable:**
```javascript
// WRONG - Creates TWO different variables!
let ACTIVE_MODEL = 'gpt-4';           // Local variable
window.ACTIVE_MODEL = 'claude-3';     // Different window variable

console.log(ACTIVE_MODEL);         // Shows 'gpt-4'
console.log(window.ACTIVE_MODEL);  // Shows 'claude-3' - CONFUSING!

// RIGHT - Use window everywhere
window.ACTIVE_MODEL = 'gpt-4';     // Global variable
window.ACTIVE_MODEL = 'claude-3';  // Same variable updated

console.log(window.ACTIVE_MODEL);  // Shows 'claude-3' - CONSISTENT!
```

### Functions

| Type | Syntax | Purpose | Example | When to Use |
|------|--------|---------|---------|-------------|
| **Function declaration** | `function name() { }` | Define reusable code | `function sayHello() { alert('Hi'); }` | Most common |
| **Arrow function** | `const name = () => { }` | Short function syntax | `const add = (a, b) => a + b;` | Callbacks, short functions |
| **Export function** | `export function name() { }` | Make available to other files | `export function analyze() { }` | Module functions |
| **Async function** | `async function name() { }` | Function that waits for things | `async function loadFiles() { await fetch(...); }` | Network requests, delays |

**Function Parts:**
```javascript
function functionName(parameter1, parameter2) {  // Function declaration
    // Function body - code that runs
    const result = parameter1 + parameter2;      // Do something
    return result;                                // Send value back
}

const answer = functionName(5, 3);  // Call function with arguments
console.log(answer);  // Shows: 8
```

### DOM Manipulation

| Action | Method | Purpose | Returns | Example |
|--------|--------|---------|---------|---------|
| **Find by ID** | `getElementById('id')` | Get element with specific ID | Element or null | `const btn = document.getElementById('runAnalysis');` |
| **Find by class** | `querySelector('.class')` | Get first element with class | Element or null | `const panel = document.querySelector('.panel');` |
| **Find all** | `querySelectorAll('.class')` | Get all matching elements | NodeList (array-like) | `const btns = querySelectorAll('.btn');` |
| **Add class** | `element.classList.add('class')` | Add CSS class to element | undefined | `btn.classList.add('active');` |
| **Remove class** | `element.classList.remove('class')` | Remove CSS class | undefined | `btn.classList.remove('hidden');` |
| **Toggle class** | `element.classList.toggle('class')` | Add if missing, remove if exists | boolean | `menu.classList.toggle('visible');` |
| **Set text** | `element.textContent = 'text'` | Change text inside element | undefined | `output.textContent = 'Done!';` |
| **Set HTML** | `element.innerHTML = '<b>html</b>'` | Change HTML inside element | undefined | `div.innerHTML = '<p>Result</p>';` |
| **Set style** | `element.style.property = 'value'` | Change CSS property | undefined | `btn.style.background = 'red';` |
| **Create element** | `document.createElement('tag')` | Make new element | New element | `const div = document.createElement('div');` |
| **Append element** | `parent.appendChild(child)` | Add element inside another | Appended element | `body.appendChild(div);` |
| **Remove element** | `element.remove()` | Delete element from page | undefined | `overlay.remove();` |

**DOM Example:**
```javascript
// Find existing element
const button = document.getElementById('myButton');  // Get button

// Change its appearance
button.style.background = '#00FFFF';  // Make it cyan
button.classList.add('active');       // Add 'active' class

// Create new element
const div = document.createElement('div');  // Make new div
div.textContent = 'Hello!';                 // Put text in it
div.className = 'message';                  // Give it a class

// Add to page
document.body.appendChild(div);  // Add div to bottom of page
```

### Events

| Event | When It Fires | Common Elements | Handler Example |
|-------|---------------|-----------------|-----------------|
| `click` | Element is clicked | Buttons, links, divs | `button.onclick = () => alert('Clicked!');` |
| `change` | Input value changes | Input, select, textarea | `input.onchange = (e) => console.log(e.target.value);` |
| `submit` | Form is submitted | Forms | `form.onsubmit = (e) => e.preventDefault();` |
| `load` | Page/resource loaded | Window, img, script | `window.onload = () => console.log('Ready');` |
| `keydown` | Key is pressed | Input, body | `input.onkeydown = (e) => console.log(e.key);` |

**Event Listener Example:**
```javascript
// Method 1: Direct assignment (one handler only)
button.onclick = function() {
    console.log('Button clicked!');
};

// Method 2: addEventListener (can have multiple)
button.addEventListener('click', function(event) {
    console.log('Clicked!', event.target);  // event = details about click
});

// Arrow function version
button.addEventListener('click', (e) => {
    e.stopPropagation();  // Stop event from bubbling up
    doSomething();
});
```

---

## 🔍 Code Analysis Components

### Analysis Classes

| Class/File | Purpose | Methods | Data Stored | Used By |
|------------|---------|---------|-------------|---------|
| **CodeAnalyzer** | Core analysis engine | `findDuplicateFunctions()`<br>`findScopeMismatches()`<br>`findMissingSelectors()` | `this.files` (loaded code)<br>`this.projectUrl` (server URL) | `analysis-ui.js` |
| **AnalysisUI** | User interface handler | `runFullAnalysis()`<br>`displayResults()`<br>`toggleExplanations()` | `this.analyzer` (CodeAnalyzer instance)<br>`this.showExplanations` (learning mode on/off) | `panel.html` buttons |

### Analysis Results Structure

| Result Type | Data Structure | Contains | Example |
|-------------|----------------|----------|---------|
| **Duplicate Functions** | `{ functionName: [locations] }` | Array of `{file, line, code}` | `{ closeHistoryMenu: [{file: 'app.js', line: 2229, code: 'function closeHistoryMenu()'}] }` |
| **Scope Mismatches** | `{ varName: {local: [], window: []} }` | Arrays of filenames | `{ ACTIVE_MODEL: {local: ['app.js'], window: ['js/models.js']} }` |
| **Missing Selectors** | `{ ids: {...}, classes: {...} }` | Maps of selector name to locations | `{ ids: {menuOverlay: [{file: 'app.js', line: 2252}]} }` |

### File Loading Process

| Step | Action | Code Location | Purpose |
|------|--------|---------------|---------|
| 1. **Get URL** | Read input field | `analysis-ui.js:45` | User enters project URL |
| 2. **Fetch files** | `fetch()` each file | `code-analyzer.js:30-42` | Download JS/HTML/CSS from server |
| 3. **Store content** | `this.files[filename] = text` | `code-analyzer.js:39` | Cache file content for analysis |
| 4. **Run analysis** | Call analysis methods | `code-analyzer.js:191-198` | Process cached files |
| 5. **Display results** | Build HTML output | `analysis-ui.js:104-165` | Show visual results to user |

---

## 📊 Common Patterns in Codebase

### Import/Export Pattern (Modules)

```javascript
// === File: js/utils.js (Export) ===
export function closeHistoryMenu() {  // Export makes available to other files
    // Function code here
}

export function showToast(message) {
    // Function code here
}

// === File: js/main.js (Import) ===
import { closeHistoryMenu, showToast } from './utils.js';  // Import from utils

closeHistoryMenu();  // Can now use imported function
showToast('Hello!');
```

### Event Handler Pattern

```javascript
// === Get element ===
const button = document.getElementById('runAnalysis');

// === Add click handler ===
button.addEventListener('click', async () => {  // async allows await
    // 1. Show loading
    output.innerHTML = 'Loading...';

    // 2. Do work
    const results = await analyzer.analyzeAll();  // Wait for analysis

    // 3. Show results
    displayResults(results);
});
```

### Class Pattern

```javascript
class MyClass {
    constructor() {  // Runs when creating new instance
        this.property = 'value';  // Store data on instance
        this.init();  // Call setup method
    }

    init() {  // Setup method
        // Initialize things
    }

    myMethod() {  // Regular method
        console.log(this.property);  // Access instance data
    }
}

// Usage
const instance = new MyClass();  // Create instance (calls constructor)
instance.myMethod();  // Call method
```

### Async/Await Pattern

```javascript
// === Old way (callback hell) ===
fetch(url).then(response => {
    return response.text();
}).then(text => {
    console.log(text);
}).catch(error => {
    console.error(error);
});

// === Modern way (async/await) ===
async function loadFile(url) {  // Mark function as async
    try {
        const response = await fetch(url);  // Wait for fetch
        const text = await response.text();  // Wait for text
        console.log(text);
    } catch (error) {
        console.error(error);
    }
}
```

---

## 🎨 Divine Debugger Color Scheme

| Color | Hex Code | RGB | Usage | Visual |
|-------|----------|-----|-------|--------|
| **Cyan** | `#00FFFF` | `rgb(0, 255, 255)` | Primary theme, highlights, borders | 🟦 Bright blue-green |
| **Dark** | `#111111` | `rgb(17, 17, 17)` | Backgrounds, panels | ⬛ Near black |
| **Gray** | `#888888` | `rgb(136, 136, 136)` | Secondary text, hints | ▪️ Medium gray |
| **Red** | `#FF3333` | `rgb(255, 51, 51)` | Errors, critical issues | 🟥 Bright red |
| **Orange** | `#FF8800` | `rgb(255, 136, 0)` | Warnings, medium issues | 🟧 Orange |
| **Green** | `#00FF00` | `rgb(0, 255, 0)` | Success, no issues | 🟩 Bright green |
| **Yellow** | `#FFFF00` | `rgb(255, 255, 0)` | Caution, minor issues | 🟨 Yellow |

---

## 🔧 Troubleshooting Reference

| Issue | Likely Cause | How to Check | Solution |
|-------|--------------|--------------|----------|
| Element not found (null) | Wrong ID or class | `console.log(document.getElementById('id'))` | Check HTML for correct ID spelling |
| Function not defined | Not imported or typo | Check imports at top of file | Add import or fix spelling |
| Scope mismatch bug | Using both local and window.var | Run scope analysis check | Use window.var everywhere |
| CSS not applying | Wrong selector or specificity | Check browser DevTools Elements tab | Add `!important` or fix selector |
| Click not working | Handler not attached | `console.log(element.onclick)` | Check addEventListener call |
| File not loading | Wrong URL or CORS | Check browser Network tab | Verify server is running |

---

## 📖 Quick Reference Cards

### CSS Positioning

```
position: static   (default - normal flow)
position: relative (offset from normal position, keeps space)
position: absolute (offset from parent, no space in flow)
position: fixed    (offset from viewport, scrolls with page)
position: sticky   (switches between relative and fixed)
```

### JavaScript Comparison

```
==   (equal value, type coercion)      5 == '5'  → true
===  (equal value AND type)            5 === '5' → false (RECOMMENDED)
!=   (not equal, type coercion)
!==  (not equal value OR type)         (RECOMMENDED)
>    (greater than)
<    (less than)
>=   (greater than or equal)
<=   (less than or equal)
```

### CSS Measurement Units

```
px   - pixels (absolute size)           width: 100px
%    - percentage of parent              width: 50%
rem  - relative to root font size        font-size: 1.5rem
em   - relative to parent font size      font-size: 1.2em
vh   - percentage of viewport height     height: 100vh
vw   - percentage of viewport width      width: 100vw
```

---

## 🎓 Learning Path

**Beginner** → **Intermediate** → **Advanced**

1. **Start Here**: HTML structure, basic CSS
2. **Then**: JavaScript variables, functions, DOM
3. **Next**: Events, async/await, modules
4. **Finally**: Classes, advanced patterns, architecture

Use Divine Debugger's Code Analysis to learn by fixing real issues in your code!

---

**This glossary grows with you - bookmark it and refer back often! 📚**
