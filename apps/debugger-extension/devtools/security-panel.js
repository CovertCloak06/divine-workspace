/**
 * Divine Debugger - Security Analysis Panel
 * Browser-based security tools for analyzing web pages
 */

export default class SecurityPanel {
    constructor(executeCallback) {
        this.execute = executeCallback;
        this.results = {};
    }

    /**
     * Run all security checks on the current page
     */
    async runFullScan() {
        this.results = {
            headers: await this.analyzeHeaders(),
            cookies: await this.analyzeCookies(),
            forms: await this.analyzeForms(),
            storage: await this.analyzeStorage(),
            scripts: await this.analyzeScripts(),
            links: await this.analyzeLinks(),
            meta: await this.analyzeMetaTags(),
        };
        return this.results;
    }

    /**
     * Analyze HTTP security headers
     */
    analyzeHeaders() {
        return new Promise((resolve) => {
            const code = `
                (function() {
                    const headers = {};
                    const securityHeaders = [
                        'content-security-policy',
                        'x-frame-options',
                        'x-content-type-options',
                        'x-xss-protection',
                        'strict-transport-security',
                        'referrer-policy',
                        'permissions-policy',
                        'cross-origin-opener-policy',
                        'cross-origin-embedder-policy'
                    ];

                    // Get headers via performance API
                    const entries = performance.getEntriesByType('navigation');
                    if (entries.length > 0) {
                        const navEntry = entries[0];
                        headers.protocol = location.protocol;
                        headers.isSecure = location.protocol === 'https:';
                    }

                    // Check meta CSP
                    const metaCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                    if (metaCSP) {
                        headers.cspMeta = metaCSP.content;
                    }

                    return {
                        url: location.href,
                        protocol: location.protocol,
                        isSecure: location.protocol === 'https:',
                        cspMeta: headers.cspMeta || null
                    };
                })();
            `;
            this.execute(code, (result) => resolve(result || {}));
        });
    }

    /**
     * Analyze cookies for security issues
     */
    analyzeCookies() {
        return new Promise((resolve) => {
            const code = `
                (function() {
                    const cookies = document.cookie.split(';').filter(c => c.trim());
                    const analysis = {
                        count: cookies.length,
                        cookies: [],
                        issues: []
                    };

                    cookies.forEach(cookie => {
                        const [name, value] = cookie.trim().split('=');
                        const cookieInfo = {
                            name: name,
                            valueLength: (value || '').length,
                            hasValue: !!value
                        };

                        // Check for sensitive-looking names
                        const sensitivePatterns = ['session', 'token', 'auth', 'key', 'secret', 'pass', 'jwt'];
                        const isSensitive = sensitivePatterns.some(p => name.toLowerCase().includes(p));

                        if (isSensitive) {
                            cookieInfo.sensitive = true;
                            analysis.issues.push({
                                type: 'sensitive_cookie',
                                message: 'Cookie "' + name + '" appears sensitive - ensure HttpOnly and Secure flags',
                                severity: 'medium'
                            });
                        }

                        analysis.cookies.push(cookieInfo);
                    });

                    return analysis;
                })();
            `;
            this.execute(code, (result) => resolve(result || { count: 0, cookies: [], issues: [] }));
        });
    }

    /**
     * Analyze forms for security issues
     */
    analyzeForms() {
        return new Promise((resolve) => {
            const code = `
                (function() {
                    const forms = Array.from(document.querySelectorAll('form'));
                    const analysis = {
                        count: forms.length,
                        forms: [],
                        issues: []
                    };

                    forms.forEach((form, idx) => {
                        const formInfo = {
                            index: idx,
                            action: form.action || 'none',
                            method: form.method || 'GET',
                            hasCSRF: false,
                            hasPasswordField: false,
                            isSecureAction: true,
                            inputCount: form.querySelectorAll('input').length
                        };

                        // Check for CSRF token
                        const csrfInputs = form.querySelectorAll('input[name*="csrf"], input[name*="token"], input[name*="_token"]');
                        formInfo.hasCSRF = csrfInputs.length > 0;

                        // Check for password fields
                        formInfo.hasPasswordField = form.querySelectorAll('input[type="password"]').length > 0;

                        // Check if action is HTTPS
                        if (form.action && form.action.startsWith('http:')) {
                            formInfo.isSecureAction = false;
                            analysis.issues.push({
                                type: 'insecure_form_action',
                                message: 'Form ' + idx + ' submits to HTTP (insecure)',
                                severity: 'high'
                            });
                        }

                        // Check autocomplete on password fields
                        const pwFields = form.querySelectorAll('input[type="password"]');
                        pwFields.forEach(pw => {
                            if (pw.autocomplete !== 'off' && pw.autocomplete !== 'new-password') {
                                analysis.issues.push({
                                    type: 'autocomplete_enabled',
                                    message: 'Password field in form ' + idx + ' has autocomplete enabled',
                                    severity: 'low'
                                });
                            }
                        });

                        // Missing CSRF on POST form
                        if (formInfo.method.toUpperCase() === 'POST' && !formInfo.hasCSRF) {
                            analysis.issues.push({
                                type: 'missing_csrf',
                                message: 'POST form ' + idx + ' may be missing CSRF protection',
                                severity: 'medium'
                            });
                        }

                        analysis.forms.push(formInfo);
                    });

                    return analysis;
                })();
            `;
            this.execute(code, (result) => resolve(result || { count: 0, forms: [], issues: [] }));
        });
    }

    /**
     * Analyze localStorage and sessionStorage
     */
    analyzeStorage() {
        return new Promise((resolve) => {
            const code = `
                (function() {
                    const analysis = {
                        localStorage: { count: 0, items: [], issues: [] },
                        sessionStorage: { count: 0, items: [], issues: [] }
                    };

                    const sensitivePatterns = ['token', 'auth', 'session', 'key', 'secret', 'password', 'jwt', 'api'];

                    // Analyze localStorage
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        const value = localStorage.getItem(key);
                        const item = {
                            key: key,
                            valueLength: value ? value.length : 0,
                            valuePreview: value ? value.substring(0, 50) : ''
                        };

                        const isSensitive = sensitivePatterns.some(p => key.toLowerCase().includes(p));
                        if (isSensitive) {
                            item.sensitive = true;
                            analysis.localStorage.issues.push({
                                type: 'sensitive_storage',
                                message: 'localStorage key "' + key + '" may contain sensitive data',
                                severity: 'medium'
                            });
                        }

                        // Check if value looks like JWT
                        if (value && value.match(/^eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*$/)) {
                            item.isJWT = true;
                            analysis.localStorage.issues.push({
                                type: 'jwt_in_storage',
                                message: 'JWT token found in localStorage ("' + key + '") - consider HttpOnly cookies',
                                severity: 'medium'
                            });
                        }

                        analysis.localStorage.items.push(item);
                    }
                    analysis.localStorage.count = localStorage.length;

                    // Analyze sessionStorage
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        const value = sessionStorage.getItem(key);
                        const item = {
                            key: key,
                            valueLength: value ? value.length : 0,
                            valuePreview: value ? value.substring(0, 50) : ''
                        };

                        const isSensitive = sensitivePatterns.some(p => key.toLowerCase().includes(p));
                        if (isSensitive) {
                            item.sensitive = true;
                            analysis.sessionStorage.issues.push({
                                type: 'sensitive_storage',
                                message: 'sessionStorage key "' + key + '" may contain sensitive data',
                                severity: 'low'
                            });
                        }

                        analysis.sessionStorage.items.push(item);
                    }
                    analysis.sessionStorage.count = sessionStorage.length;

                    return analysis;
                })();
            `;
            this.execute(code, (result) => resolve(result || { localStorage: { count: 0 }, sessionStorage: { count: 0 } }));
        });
    }

    /**
     * Analyze scripts on the page
     */
    analyzeScripts() {
        return new Promise((resolve) => {
            const code = `
                (function() {
                    const scripts = Array.from(document.querySelectorAll('script'));
                    const analysis = {
                        total: scripts.length,
                        inline: 0,
                        external: 0,
                        scripts: [],
                        issues: []
                    };

                    scripts.forEach((script, idx) => {
                        const scriptInfo = {
                            index: idx,
                            type: script.type || 'text/javascript',
                            isInline: !script.src,
                            src: script.src || null,
                            hasNonce: !!script.nonce,
                            hasIntegrity: !!script.integrity,
                            async: script.async,
                            defer: script.defer
                        };

                        if (script.src) {
                            analysis.external++;

                            // Check for HTTP scripts on HTTPS page
                            if (location.protocol === 'https:' && script.src.startsWith('http:')) {
                                analysis.issues.push({
                                    type: 'mixed_content',
                                    message: 'HTTP script loaded on HTTPS page: ' + script.src.substring(0, 50),
                                    severity: 'high'
                                });
                            }

                            // Check for missing SRI
                            if (!script.integrity && !script.src.includes(location.hostname)) {
                                analysis.issues.push({
                                    type: 'missing_sri',
                                    message: 'External script missing integrity check: ' + script.src.substring(0, 50),
                                    severity: 'low'
                                });
                            }
                        } else {
                            analysis.inline++;
                            scriptInfo.contentPreview = script.textContent.substring(0, 100);

                            // Check for dangerous patterns in inline scripts
                            const dangerous = ['eval(', 'innerHTML', 'document.write', 'outerHTML'];
                            dangerous.forEach(pattern => {
                                if (script.textContent.includes(pattern)) {
                                    analysis.issues.push({
                                        type: 'dangerous_pattern',
                                        message: 'Inline script ' + idx + ' uses potentially dangerous: ' + pattern,
                                        severity: 'medium'
                                    });
                                }
                            });
                        }

                        analysis.scripts.push(scriptInfo);
                    });

                    return analysis;
                })();
            `;
            this.execute(code, (result) => resolve(result || { total: 0, inline: 0, external: 0 }));
        });
    }

    /**
     * Analyze links and external resources
     */
    analyzeLinks() {
        return new Promise((resolve) => {
            const code = `
                (function() {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    const analysis = {
                        total: links.length,
                        internal: 0,
                        external: 0,
                        issues: []
                    };

                    const currentHost = location.hostname;

                    links.forEach((link, idx) => {
                        try {
                            const url = new URL(link.href, location.origin);

                            if (url.hostname === currentHost) {
                                analysis.internal++;
                            } else {
                                analysis.external++;

                                // Check for target="_blank" without rel="noopener"
                                if (link.target === '_blank') {
                                    const rel = link.rel || '';
                                    if (!rel.includes('noopener') && !rel.includes('noreferrer')) {
                                        analysis.issues.push({
                                            type: 'target_blank_vulnerability',
                                            message: 'External link missing rel="noopener": ' + url.hostname,
                                            severity: 'low'
                                        });
                                    }
                                }
                            }

                            // Check for javascript: URLs
                            if (link.href.startsWith('javascript:')) {
                                analysis.issues.push({
                                    type: 'javascript_url',
                                    message: 'Link uses javascript: URL protocol',
                                    severity: 'medium'
                                });
                            }
                        } catch (e) {}
                    });

                    return analysis;
                })();
            `;
            this.execute(code, (result) => resolve(result || { total: 0, internal: 0, external: 0 }));
        });
    }

    /**
     * Analyze meta tags for security-relevant info
     */
    analyzeMetaTags() {
        return new Promise((resolve) => {
            const code = `
                (function() {
                    const metas = Array.from(document.querySelectorAll('meta'));
                    const analysis = {
                        total: metas.length,
                        security: {},
                        issues: []
                    };

                    metas.forEach(meta => {
                        const name = (meta.name || meta.httpEquiv || '').toLowerCase();
                        const content = meta.content || '';

                        // Security-relevant meta tags
                        if (name === 'referrer') {
                            analysis.security.referrer = content;
                        }
                        if (meta.httpEquiv && meta.httpEquiv.toLowerCase() === 'content-security-policy') {
                            analysis.security.csp = content;
                        }
                        if (meta.httpEquiv && meta.httpEquiv.toLowerCase() === 'x-frame-options') {
                            analysis.security.xFrameOptions = content;
                        }
                        if (name === 'robots' && content.includes('noindex')) {
                            analysis.security.noindex = true;
                        }
                    });

                    // Check for missing viewport (clickjacking)
                    if (!document.querySelector('meta[name="viewport"]')) {
                        analysis.issues.push({
                            type: 'missing_viewport',
                            message: 'Missing viewport meta tag',
                            severity: 'low'
                        });
                    }

                    return analysis;
                })();
            `;
            this.execute(code, (result) => resolve(result || { total: 0, security: {} }));
        });
    }

    /**
     * Calculate overall security score
     */
    calculateScore(results) {
        let score = 100;
        let issues = [];

        // Collect all issues
        Object.values(results).forEach(category => {
            if (category && category.issues) {
                issues = issues.concat(category.issues);
            }
        });

        // Deduct points based on severity
        issues.forEach(issue => {
            switch (issue.severity) {
                case 'high': score -= 15; break;
                case 'medium': score -= 8; break;
                case 'low': score -= 3; break;
            }
        });

        // Bonus for HTTPS
        if (results.headers && results.headers.isSecure) {
            score += 5;
        }

        return {
            score: Math.max(0, Math.min(100, score)),
            grade: this.scoreToGrade(score),
            issueCount: issues.length,
            issues: issues
        };
    }

    scoreToGrade(score) {
        if (score >= 90) return 'A';
        if (score >= 80) return 'B';
        if (score >= 70) return 'C';
        if (score >= 60) return 'D';
        return 'F';
    }

    /**
     * Generate HTML report
     */
    generateReport(results) {
        const score = this.calculateScore(results);
        const gradeColors = { A: '#4ade80', B: '#a3e635', C: '#fbbf24', D: '#f97316', F: '#ef4444' };

        return `
            <div class="security-report">
                <div class="security-score" style="text-align:center;padding:15px;background:rgba(0,0,0,0.3);border-radius:8px;margin-bottom:15px;">
                    <div style="font-size:48px;color:${gradeColors[score.grade]};font-weight:bold;">${score.grade}</div>
                    <div style="font-size:14px;color:#888;">Score: ${score.score}/100</div>
                    <div style="font-size:12px;color:#666;">${score.issueCount} issue(s) found</div>
                </div>

                <div class="security-summary">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;">
                        <div>Protocol: <span style="color:${results.headers?.isSecure ? '#4ade80' : '#ef4444'}">${results.headers?.protocol || 'unknown'}</span></div>
                        <div>Cookies: <span style="color:#00ffff">${results.cookies?.count || 0}</span></div>
                        <div>Forms: <span style="color:#00ffff">${results.forms?.count || 0}</span></div>
                        <div>Scripts: <span style="color:#00ffff">${results.scripts?.total || 0}</span></div>
                        <div>Links: <span style="color:#00ffff">${results.links?.total || 0}</span></div>
                        <div>Storage Items: <span style="color:#00ffff">${(results.storage?.localStorage?.count || 0) + (results.storage?.sessionStorage?.count || 0)}</span></div>
                    </div>
                </div>

                ${score.issues.length > 0 ? `
                    <div class="security-issues" style="margin-top:15px;">
                        <div style="font-weight:bold;margin-bottom:8px;color:#f59e0b;">Issues Found:</div>
                        ${score.issues.map(issue => `
                            <div style="padding:8px;margin-bottom:5px;background:rgba(${issue.severity === 'high' ? '239,68,68' : issue.severity === 'medium' ? '245,158,11' : '156,163,175'},0.1);border-left:3px solid ${issue.severity === 'high' ? '#ef4444' : issue.severity === 'medium' ? '#f59e0b' : '#9ca3af'};border-radius:0 4px 4px 0;font-size:11px;">
                                <span style="color:${issue.severity === 'high' ? '#ef4444' : issue.severity === 'medium' ? '#f59e0b' : '#9ca3af'};font-weight:bold;">[${issue.severity.toUpperCase()}]</span>
                                ${issue.message}
                            </div>
                        `).join('')}
                    </div>
                ` : '<div style="color:#4ade80;margin-top:15px;">No security issues detected!</div>'}
            </div>
        `;
    }
}
