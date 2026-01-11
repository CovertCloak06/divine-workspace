# Parakleon / Divine Node UI

Single‑page web UI for the Parakleon AI assistant running on phone (Termux) or desktop. It’s a static HTML/CSS/JS app; any simple web server that can serve files will work.

---

## 1. File layout and purpose

Root `pkn` folder:

- `pkn.html`  
  Main HTML page. Defines structure: sidebar, header, chat messages, input box, buttons. References external CSS/JS via `<link>` and `<script>` tags.

- `app.js`  
  Core UI + chat logic:  
  - Handles sending messages, showing “thinking” dots, rendering AI responses with code blocks.  
  - Manages chat history, favorites, archive, backup, settings, sidebar toggles.  
  - Builds the OpenAI/Ollama payload and calls the model API.

- `config.js`  
  Holds configuration in `window.PARAKLEON_CONFIG`:  
  - `OPENAI_API_KEY`, `OPENAI_MODEL`, `OLLAMA_BASE_URL`.  
  This keeps secrets and settings out of the main logic file.

- `tools.js`  
  Parakleon tools namespace (`window.ParakleonTools`):  
  - `phoneScan()` calls your local PhoneScan API and injects results as system messages.  
  - `networkInfo()` and `ipInfo()` are stubs for future tools.

- `css/main.css`  
  All styling for the UI: layout, fonts, neon theme, sidebar, buttons, message bubbles, code blocks, responsive mobile tweaks.

- `img/`  
  Contains images referenced in `pkn.html`:  
  - `logo.png` – main header icon.  
  - `icsword.png` – sidebar icon.  
  - `pkchaticon.png` – small AI avatar next to assistant messages.

- `package.json` (optional)  
  Node/npm metadata. Useful if you later add a dev server or bundler, but not required for the current static build.

- `README_PARAKLEON_UI.md`  
  This file.

---

## 2. Key HTML tags in `pkn.html`

- `<!DOCTYPE html>` – Declares HTML5 document type so browsers render in standards mode.  
- `<html lang="en">` – Root element; `lang` helps accessibility and search engines.  
- `<head>...</head>` – Metadata, not shown on the page:
  - `<meta charset="UTF-8">` – Use UTF‑8 encoding.
  - `<meta name="viewport" ...>` – Make layout responsive on mobile.
  - `<title>` – Tab/window title.
  - `<link rel="stylesheet" href="css/main.css">` – Attach external CSS file.
- `<body>...</body>` – Everything visible to the user.
- `<div>` – Generic container; used for layout sections (`container`, `sidebar`, `main`, `messages`, etc.).
- `<button>` – Clickable buttons: Send, Phone Scan, Network, IP Info, Upload File, Settings, etc.
- `<input type="text">` – Chat input field; you type prompts here.
- `<input type="file">` – Hidden file chooser used by “Upload File”.
- `<img>` – Displays the logo and icons (`src` points into `img/`).
- `<script src="...">` – Loads JavaScript files at the bottom of `body`:
  - `tools.js` → `config.js` → `app.js`.  
  The browser executes them in this order.

---

## 3. Setup on phone (Android + Termux)

1. Install Termux and basic tools:
pkg update
pkg install python git
2. Create the project folder on internal storage:
cd /sdcard
mkdir -p pkn/css pkn/img
3. Copy files into place (from editor, USB, adb, or git):

- `pkn.html`, `app.js`, `config.js`, `tools.js` → `/sdcard/pkn`
- `main.css` → `/sdcard/pkn/css`
- `logo.png`, `icsword.png`, `pkchaticon.png` → `/sdcard/pkn/img`

4. Run a local web server from Termux:
cd /sdcard/pkn
python -m http.server 8010
5. Open in the phone browser:

- Go to `http://127.0.0.1:8010/pkn.html`.

---

## 4. Setup on desktop (Linux/Windows/macOS)

1. Copy the same `pkn` folder to your machine.  
2. Open a terminal in the `pkn` folder.  
3. Start a simple HTTP server:
python -m http.server 8010
4. In the desktop browser, open:

- `http://127.0.0.1:8010/pkn.html`

---

## 5. Moving files between phone and computer

### Option A: USB (MTP)

- Connect phone via USB, enable file transfer.
- On the PC, open the device storage and drag the `pkn` folder to/from `/sdcard`.

### Option B: ADB (command line)

From the PC with Android platform tools installed:

- Phone → PC:
adb pull /sdcard/pkn ./pkn-from-phone
- PC → Phone:
adb push ./pkn /sdcard/pkn
### Option C: SSH / rsync via Termux (wireless)

- Run an SSH server on the PC.
- From Termux:
rsync -avz /sdcard/pkn user@PC_HOST:~/pkn
Reverse the source/target to sync back to the phone.

---

## 6. Dependencies and commands

### Runtime dependencies

- A modern web browser (mobile or desktop).
- Model backends:
- OpenAI API reachable from the device.
- Optional local Ollama server at `OLLAMA_BASE_URL` if using `ollama:*` models.

### Tools on phone / PC

- Python 3 (for `python -m http.server`) or any equivalent static file server.
- Termux on Android if running on phone.

### Typical commands used for this build

Create directories:
mkdir -p /sdcard/pkn/css /sdcard/pkn/img
Run local dev server from project root:
cd /sdcard/pkn
python -m http.server 8010
Optional Node/npm usage (if you expand later):

- `npm init` – create `package.json`.
- `npm install <package>` – add dependencies.
- `npm run <script>` – run scripts defined in `package.json`.

---
