// ===========================================
// PARAKLEON TOOLS MODULE (tools.js)
// ===========================================
// Cross-references:
// - HTML: pkn.html (action buttons and network menu)
// - CSS: main.css (.network-menu styling and animations)
// - App: app.js (addMessage function for system messages)
// - Server: divinenode_server.py (/phonescan and /network endpoints)
// - Config: config.js (PARAKLEON_API_BASE for API calls)
//
// Functionality:
// - PhoneScan: Phone number validation and carrier lookup
// - Network tools: IP geolocation, DNS lookup, port scanning
// - File operations: Upload, download, management
// - Integration with main chat interface
// ===========================================

// Parakleon Tools Module – PhoneScan + Network Stubs
window.ParakleonTools = {
    async phoneScan() {
        // Prompt for a phone number and validate before sending to the backend
        const number = prompt('Enter phone number (with country code, e.g. +15551234567):');
        if (!number) return;

        const trimmed = String(number).trim();

        // Basic client-side validation rules
        const isPlusPrefixed = trimmed.startsWith('+');
        const digitsOnly = trimmed.replace(/[^0-9]/g, '');
        const minDigits = digitsOnly.length >= 8;

        if (!isPlusPrefixed || !minDigits) {
            const friendly = !trimmed
                ? 'Please enter a phone number.'
                : 'Invalid phone number. Enter the full international number including the + and country code (for example: +14155552671).';
            if (typeof addMessage === 'function') {
                addMessage(friendly, 'system', true);
            } else {
                alert(friendly);
            }
            return;
        }

        const confirmUse = confirm(
            'Use PhoneScan only on numbers you are legally allowed to investigate. Continue?'
        );
        if (!confirmUse) return;

        try {
            const res = await fetch('/api/phonescan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ number: trimmed })
            });

            if (!res.ok) {
                // Try to extract backend message if available
                let serverMsg = '';
                try {
                    const json = await res.json();
                    serverMsg = json.error || json.summary || JSON.stringify(json);
                } catch (e) {
                    serverMsg = `HTTP ${res.status}`;
                }

                // Map backend errors to friendly messages
                let userMsg;
                if (res.status === 400) {
                    if (serverMsg && serverMsg.toLowerCase().includes('no phone')) {
                        userMsg = 'Please enter a phone number.';
                    } else if (serverMsg && serverMsg.toLowerCase().includes('invalid phone')) {
                        userMsg = 'Invalid phone number format. Include the country code starting with + (example: +14155552671).';
                    } else {
                        userMsg = serverMsg || `PhoneScan failed (400).`;
                    }
                } else {
                    userMsg = `PhoneScan error: ${serverMsg}`;
                }

                if (typeof addMessage === 'function') {
                    addMessage(userMsg, 'system', true);
                } else {
                    alert(userMsg);
                }
                return;
            }

            const data = await res.json();
            const summary = data.summary || JSON.stringify(data, null, 2);
            if (typeof addMessage === 'function') {
                addMessage('PhoneScan Result:\n' + summary, 'system', true);
            }
        } catch (err) {
            // Network or fetch-level errors
            const errorMsg = (err && err.message && err.message.includes('Failed to fetch'))
                ? "Can't reach PhoneScan service — make sure the backend is running (run: python3 divinenode_server.py)."
                : 'PhoneScan error: ' + (err.message || 'Request failed');
            if (typeof addMessage === 'function') {
                addMessage(errorMsg, 'system', true);
            } else {
                alert(errorMsg);
            }
        }
    },

    networkInfo() {
        addMessage('Network module coming soon.', 'system', true);
    },

    async ipInfo() {
        // Fetch public IP and geo info using ipapi.co
        try {
            const resp = await fetch('https://ipapi.co/json/');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const json = await resp.json();

            const parts = [];
            if (json.ip) parts.push(`IP: ${json.ip}`);
            if (json.city || json.region || json.country_name) {
                parts.push(`Location: ${[json.city, json.region, json.country_name].filter(Boolean).join(', ')}`);
            }
            if (json.org) parts.push(`Org: ${json.org}`);
            if (json.timezone) parts.push(`Timezone: ${json.timezone}`);

            const message = parts.join(' | ');
            if (typeof addMessage === 'function') {
                addMessage('IP Info: ' + message, 'system', true);
            } else {
                alert('IP Info: ' + message);
            }
        } catch (err) {
            const friendly = "Can't fetch IP information right now. Try again or check your network.";
            if (typeof addMessage === 'function') {
                addMessage(friendly + (err.message ? ` (${err.message})` : ''), 'system', true);
            } else {
                alert(friendly + (err.message ? ` (${err.message})` : ''));
            }
        }
    },

    async dnsLookup() {
        const domain = prompt('Enter domain to lookup (example: example.com):');
        if (!domain) return;
        const d = domain.trim();
        if (!d) {
            addMessage('Please enter a domain name.', 'system', true);
            return;
        }

        // Prefer backend-powered DNS if available
        if (window.ParakleonTools && window.ParakleonTools.backendAvailable) {
            try {
                const resp = await fetch(window.PARAKLEON_API_BASE + '/api/network/dns', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: d })
                });
                if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                const json = await resp.json();
                if (json.addresses && json.addresses.length) {
                    addMessage(`DNS A records for ${d}: ${json.addresses.join(', ')}`, 'system', true);
                } else if (json.error) {
                    addMessage(`DNS lookup failed: ${json.error}`, 'system', true);
                } else {
                    addMessage(`No A records found for ${d}.`, 'system', true);
                }
            } catch (err) {
                addMessage(`DNS lookup failed: ${err.message || 'request failed'}`, 'system', true);
            }
            return;
        }

        // Fallback to public DoH if backend not present
        try {
            const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(d)}&type=A`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const json = await resp.json();

            const answers = (json.Answer || []).filter(a => a && a.data).map(a => a.data);
            const msg = answers.length ? `DNS A records for ${d}: ${answers.join(', ')}` : `No A records found for ${d}.`;
            addMessage(msg, 'system', true);
        } catch (err) {
            addMessage(`DNS lookup failed: ${err.message || 'request failed'}`, 'system', true);
        }
    },

    async httpHeaders() {
        const url = prompt('Enter URL to check (include scheme, e.g. https://example.com):');
        if (!url) return;
        const u = url.trim();
        if (!u) {
            addMessage('Please enter a URL.', 'system', true);
            return;
        }

        try {
            // Try HEAD first to get status and headers
            let resp;
            try {
                resp = await fetch(u, { method: 'HEAD' });
            } catch (e) {
                // Some servers block HEAD; try GET as fallback
                resp = await fetch(u, { method: 'GET' });
            }

            if (!resp) throw new Error('No response');
            if (!resp.ok) {
                addMessage(`HTTP ${resp.status} ${resp.statusText} for ${u}`, 'system', true);
                return;
            }

            // Try to extract a few headers - may be blocked by CORS on some sites
            const headers = [];
            try {
                const h = resp.headers;
                ['content-type', 'server', 'content-length', 'last-modified', 'cache-control'].forEach(k => {
                    const v = h.get(k);
                    if (v) headers.push(`${k}: ${v}`);
                });
            } catch (e) {
                // ignore header extraction errors
            }

            const headerMsg = headers.length ? headers.join(' | ') : 'Headers not available (may be blocked by CORS).';
            addMessage(`HTTP check for ${u} → status ${resp.status}. ${headerMsg}`, 'system', true);
        } catch (err) {
            addMessage(`HTTP check failed: ${err.message || 'request failed'}`, 'system', true);
        }
    }

    ,

    async ping(host) {
        let h = host;
        if (!h) {
            h = prompt('Enter host to ping (hostname or IP):');
            if (!h) return;
            h = h.trim();
        }
        try {
            const resp = await fetch(window.PARAKLEON_API_BASE + '/api/network/ping', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host: h, count: 4 })
            });
            if (!resp.ok) {
                const j = await resp.json().catch(()=>({}));
                addMessage(`Ping failed: ${j.error || 'HTTP ' + resp.status}`, 'system', true);
                return;
            }
            const json = await resp.json();
            const out = json.stdout || json.stderr || '';
            addMessage(`Ping ${h} →\n${out}`, 'system', true);
        } catch (err) {
            addMessage(`Ping request failed: ${err.message || 'request failed'}`, 'system', true);
        }
    },

    async portScan(host) {
        let h = host;
        if (!h) {
            h = prompt('Enter host to port-scan (hostname or IP):');
            if (!h) return;
            h = h.trim();
        }
        const portsInput = prompt('Enter comma-separated ports (or leave blank for defaults 22,80,443,8080):');
        let ports = null;
        if (portsInput && portsInput.trim()) {
            ports = portsInput.split(',').map(s => parseInt(s.trim())).filter(Boolean);
        }

        try {
            const resp = await fetch(window.PARAKLEON_API_BASE + '/api/network/portscan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host: h, ports })
            });
            if (!resp.ok) {
                const j = await resp.json().catch(()=>({}));
                addMessage(`Port scan failed: ${j.error || 'HTTP ' + resp.status}`, 'system', true);
                return;
            }
            const json = await resp.json();
            const lines = (json.results || []).map(r => `${r.port}: ${r.open ? 'open' : 'closed'}${r.rtt_ms ? ' ('+r.rtt_ms+'ms)' : ''}`);
            addMessage(`Port scan ${h} →\n${lines.join('\n')}`, 'system', true);
        } catch (err) {
            addMessage(`Port scan request failed: ${err.message || 'request failed'}`, 'system', true);
        }
    }
};

// API base URL for backend services (empty = same server)
window.PARAKLEON_API_BASE = '';

// Detect backend availability (set a flag on ParakleonTools)
(async function detectBackend() {
    try {
        const res = await fetch('/health');
        if (res.ok) {
            window.ParakleonTools.backendAvailable = true;
        } else {
            window.ParakleonTools.backendAvailable = false;
        }
    } catch (e) {
        window.ParakleonTools.backendAvailable = false;
    }
})();

// Document storage/upload helpers
window.ParakleonTools.uploadDocument = async function() {
    // Use existing hidden file input if present
    const fileInput = document.getElementById('fileInput') || (() => {
        const el = document.createElement('input');
        el.type = 'file';
        el.id = 'fileInput';
        el.style.display = 'none';
        document.body.appendChild(el);
        return el;
    })();

    return new Promise((resolve) => {
        const onChange = async () => {
            const files = fileInput.files;
            if (!files || !files.length) {
                resolve();
                return;
            }
            let successCount = 0;
            let lastFilename = null;
            for (let i = 0; i < files.length; i++) {
                const fd = new FormData();
                fd.append('file', files[i]);
                try {
                    const resp = await fetch(window.PARAKLEON_API_BASE + '/api/files/upload', { method: 'POST', body: fd });
                    const j = await resp.json().catch(()=>({}));
                    if (resp.ok) {
                        successCount += 1;
                        lastFilename = j.filename || files[i].name;
                        addMessage(`Stored file: ${j.filename || files[i].name} (id: ${j.id || 'unknown'})`, 'system', true);
                    } else {
                        addMessage(`Upload failed: ${j.error || resp.status}`, 'system', true);
                    }
                } catch (e) {
                    addMessage(`Upload error: ${e.message || e}`, 'system', true);
                }
            }
            fileInput.value = '';
            fileInput.removeEventListener('change', onChange);
            // Auto-refresh the files panel if the hook exists
            try {
                if (window.ParakleonTools && typeof window.ParakleonTools._refreshFilesPanel === 'function') {
                    window.ParakleonTools._refreshFilesPanel();
                }
                // Optionally open the files panel after upload when configured
                if (window.ParakleonTools && window.ParakleonTools.openFilesAfterUpload) {
                    if (typeof showFilesPanel === 'function') showFilesPanel();
                }
                // If any uploads succeeded and the files panel is closed, show a brief toast
                try {
                    const panel = document.getElementById('filesPanel');
                    if (successCount > 0 && panel && panel.classList.contains('hidden')) {
                        if (window.ParakleonTools && typeof window.ParakleonTools.showToast === 'function') {
                            const msg = successCount === 1 ? `Stored ${lastFilename}` : `Stored ${successCount} files`;
                            window.ParakleonTools.showToast(msg, 3500);
                        }
                    }
                } catch (e) { /* ignore */ }
            } catch (e) {
                // ignore refresh errors
                console.warn('Files panel refresh failed', e);
            }
            resolve();
        };
        fileInput.addEventListener('change', onChange);
        fileInput.click();
    });
};

window.ParakleonTools.listDocuments = async function() {
    try {
        const resp = await fetch(window.PARAKLEON_API_BASE + '/api/files/list');
        if (!resp.ok) throw new Error('Failed to list');
        const j = await resp.json();
        const files = j.files || [];
        if (!files.length) {
            addMessage('No stored documents.', 'system', true);
            return files;
        }
        const list = files.map((f, idx) => `${idx+1}. ${f.filename} (id: ${f.id})`).join('\n');
        addMessage('Stored documents:\n' + list, 'system', true);
        return files;
    } catch (e) {
        addMessage('List documents failed: ' + (e.message || e), 'system', true);
        return [];
    }
};

window.ParakleonTools.summarizeDocument = async function() {
    try {
        const files = await window.ParakleonTools.listDocuments();
        if (!files || !files.length) return;
        let choice = 1;
        if (files.length > 1) {
            const promptText = files.map((f, i) => `${i+1}: ${f.filename}`).join('\n') + '\nEnter number to summarize:';
            const num = prompt(promptText, '1');
            if (!num) return;
            choice = parseInt(num);
            if (isNaN(choice) || choice < 1 || choice > files.length) choice = 1;
        }
        const file = files[choice-1];
        const resp = await fetch(`/api/files/${file.id}/summary`);
        const j = await resp.json();
        if (!resp.ok) {
            addMessage(`Summary failed: ${j.error || resp.status}`, 'system', true);
            return;
        }
        const msg = `Summary for ${j.filename}:\n${j.summary}\n\nKeywords: ${ (j.keywords||[]).join(', ') }`;
        addMessage(msg, 'system', true);
    } catch (e) {
        addMessage('Summarize failed: ' + (e.message || e), 'system', true);
    }
};

// Files panel UI helpers
function toggleFilesPanel() {
    const panel = document.getElementById('filesPanel');
    if (!panel) return;
    if (panel.classList.contains('hidden')) {
        showFilesPanel();
    } else {
        hideFilesPanel();
    }
}

function showFilesPanel() {
    const panel = document.getElementById('filesPanel');
    if (!panel) return;
    panel.classList.remove('hidden');
    panel.setAttribute('aria-hidden', 'false');
    // load files
    fetchFilesAndRender();
}

function hideFilesPanel() {
    const panel = document.getElementById('filesPanel');
    if (!panel) return;
    panel.classList.add('hidden');
    panel.setAttribute('aria-hidden', 'true');
}

async function fetchFilesAndRender() {
    const listEl = document.getElementById('filesList');
    const previewEl = document.getElementById('filePreviewContent');
    if (!listEl) return;
    listEl.innerHTML = 'Loading...';
    try {
        const resp = await fetch(window.PARAKLEON_API_BASE + '/api/files/list');
        if (!resp.ok) throw new Error('Failed to fetch');
        const j = await resp.json();
        const files = j.files || [];
        if (!files.length) {
            listEl.innerHTML = '<div class="file-empty">No documents stored.</div>';
            if (previewEl) previewEl.textContent = 'Upload a document to see a preview here.';
            return;
        }
        listEl.innerHTML = '';
        files.forEach(f => {
            const item = document.createElement('div');
            item.className = 'file-item';
            item.innerHTML = `<div class="file-name">${escapeHtml(f.filename)}</div><div class="meta">${(new Date((f.uploaded_at||0)*1000)).toLocaleString()} • ${f.size} bytes</div>`;
            item.addEventListener('click', () => {
                renderFilePreview(f);
            });
            listEl.appendChild(item);
        });
        if (previewEl) previewEl.textContent = 'Select a file to preview';
    } catch (e) {
        listEl.innerHTML = `<div class="file-error">Error: ${e.message || e}</div>`;
        if (previewEl) previewEl.textContent = '';
    }
}

async function renderFilePreview(fileMeta) {
    const previewEl = document.getElementById('filePreviewContent');
    if (!previewEl) return;
    previewEl.textContent = 'Loading preview...';
    try {
        // try to fetch summary endpoint first
        const sresp = await fetch(`/api/files/${fileMeta.id}/summary`);
        if (sresp.ok) {
            const sj = await sresp.json();
            previewEl.innerHTML = `<div><strong>${escapeHtml(sj.filename)}</strong></div><div class="file-preview-text">${escapeHtml(sj.summary)}</div><div class="file-preview-keywords">Keywords: ${ (sj.keywords||[]).map(escapeHtml).join(', ') }</div><div class="file-actions"><button class="file-action-btn" onclick="(function(){window.ParakleonTools.summarizeDocument();})();">Summarize (again)</button><a class="file-action-btn" href="/uploads/${encodeURIComponent(fileMeta.stored_name)}" target="_blank">Download</a></div>`;
            return;
        }
        // fallback: attempt to fetch raw file for small text files
        const path = `/uploads/${encodeURIComponent(fileMeta.stored_name)}`;
        const fresp = await fetch(path);
        if (!fresp.ok) throw new Error('Could not fetch file');
        const text = await fresp.text();
        previewEl.innerHTML = `<div><strong>${escapeHtml(fileMeta.filename)}</strong></div><div class="file-preview-text">${escapeHtml(text.slice(0,3000))}</div><div class="file-actions"><button class="file-action-btn" onclick="(function(){window.ParakleonTools.summarizeDocument();})();">Summarize</button><a class="file-action-btn" href="${path}" target="_blank">Download</a></div>`;
    } catch (e) {
        previewEl.textContent = `Preview failed: ${e.message || e}`;
    }
}

function escapeHtml(s) {
    if (!s) return '';
    return String(s).replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c]; });
}

// Allow uploadDocument to refresh panel after upload
// Toast helper: brief unobtrusive notifications
window.ParakleonTools.showToast = function(message, timeout = 3500) {
    try {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        const t = document.createElement('div');
        t.className = 'toast';
        t.textContent = message;
        container.appendChild(t);
        // show
        requestAnimationFrame(() => t.classList.add('toast--visible'));
        // hide after timeout
        setTimeout(() => {
            t.classList.remove('toast--visible');
            t.addEventListener('transitionend', () => t.remove(), { once: true });
        }, timeout);
    } catch (e) {
        console.warn('showToast error', e);
    }
};

window.ParakleonTools._refreshFilesPanel = fetchFilesAndRender;
