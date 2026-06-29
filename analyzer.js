/**
 * =============================================================================
 * UNFURL ADVANCED JS SECURITY ANALYSIS ENGINE
 * =============================================================================
 * Implements client-side heuristics, Levenshtein brand spoofing detection,
 * Shannon Entropy calculation, Homograph script inspection, and Python backend telemetry.
 */

// Global state & config
const PYTHON_API_URL = (window.location.origin && window.location.origin !== 'null' && window.location.protocol.startsWith('http'))
    ? `${window.location.origin}/api`
    : 'http://localhost:8000/api';
let isPythonBackendConnected = false;

// Targeted high-profile brands for Levenshtein fuzzy match spoof detection
const KNOWN_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'netflix', 'amazon', 
    'facebook', 'instagram', 'binance', 'coinbase', 'metamask', 'wellsfargo', 'steampowered'
];

// Test bench presets
const PRESETS = {
    'homograph': 'https://pаypal.com/signin-verification', // 'а' is Cyrillic (U+0430)
    'punycode': 'https://xn--80ak6aa92e.com/secure/login',
    'ip': 'http://192.168.1.100:8080/admin/login.php?session=active',
    'creds': 'https://admin:secret123Pass@auth-portal.net/checkout',
    'subdomains': 'https://login.paypal.com.account-update.security-check.attacker-site.xyz/verify',
    'safe': 'https://github.com/google/antigravity'
};

// Auto-check Python backend availability on load
document.addEventListener('DOMContentLoaded', () => {
    checkPythonBackend();
    setInterval(checkPythonBackend, 10000); // Poll every 10 seconds
});

function loadPreset(key) {
    const input = document.getElementById('urlInput');
    input.value = PRESETS[key];
    analyzeURL();
}

function clearAll() {
    document.getElementById('urlInput').value = '';
    const results = document.getElementById('resultsSection');
    results.classList.remove('visible');
    setTimeout(() => { results.style.display = 'none'; }, 300);
}

/**
 * Checks if the Python REST API server is running on localhost:8000
 */
async function checkPythonBackend() {
    const statusTag = document.getElementById('pythonStatusTag');
    if (!statusTag) return;

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);
        
        const response = await fetch(`${PYTHON_API_URL}/health`, { 
            signal: controller.signal 
        });
        clearTimeout(timeoutId);

        if (response.ok) {
            isPythonBackendConnected = true;
            statusTag.className = 'status-tag connected';
            statusTag.innerHTML = `<span>⚡</span> Python Telemetry API: Connected`;
        } else {
            throw new Error();
        }
    } catch (e) {
        isPythonBackendConnected = false;
        statusTag.className = 'status-tag offline';
        statusTag.innerHTML = `<span>🔒</span> Python Telemetry API: Offline (Client-Only Mode)`;
    }
}

/* --------------------------------------------------------------------------
   ADVANCED ALGORITHMIC HELPERS
   -------------------------------------------------------------------------- */

/**
 * Calculates Levenshtein Distance between two strings to detect typosquatting.
 */
function levenshteinDistance(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1, // substitution
                    matrix[i][j - 1] + 1,     // insertion
                    matrix[i - 1][j] + 1      // deletion
                );
            }
        }
    }
    return matrix[b.length][a.length];
}

/**
 * Evaluates domain against top target brands to flag fuzzy spoofing (e.g., paypa1 vs paypal).
 */
function detectBrandSpoofing(hostname) {
    const domainParts = hostname.toLowerCase().split('.');
    const sld = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : domainParts[0];

    const matches = [];
    KNOWN_BRANDS.forEach(brand => {
        // Exact match on official SLD is safe, skip
        if (sld === brand) return;

        const distance = levenshteinDistance(sld, brand);
        // Distance of 1 or 2 edits strongly indicates typosquatting / brand spoofing
        if (distance > 0 && distance <= 2) {
            matches.push({ brand, distance });
        }
    });

    return matches;
}

/**
 * Calculates Shannon Entropy of domain string on client side.
 */
function calculateEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
        const char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(3));
}

/* --------------------------------------------------------------------------
   MAIN ANALYSIS ENGINE
   -------------------------------------------------------------------------- */
async function analyzeURL() {
    const rawInput = document.getElementById('urlInput').value.trim();
    if (!rawInput) return;

    let processingUrl = rawInput;
    let missingProtocolAssumed = false;

    if (!/^https?:\/\//i.test(processingUrl) && !/^ftp:\/\//i.test(processingUrl)) {
        processingUrl = 'http://' + processingUrl;
        missingProtocolAssumed = true;
    }

    let urlObj;
    try {
        urlObj = new URL(processingUrl);
    } catch (err) {
        alert('Invalid URL structure! Please check link formatting.');
        return;
    }

    // Safe URI Decoding
    let decodedUrl = rawInput;
    try {
        decodedUrl = decodeURIComponent(rawInput);
    } catch (e) {
        decodedUrl = rawInput + ' [Malformed URI Encoding]';
    }

    // Client-Side Subroutines
    const decomposition = parseURLComponents(urlObj);
    const homographResult = analyzeHomographAndScripts(urlObj.hostname);
    const brandSpoofs = detectBrandSpoofing(urlObj.hostname);
    const clientEntropy = calculateEntropy(urlObj.hostname);
    
    const heuristicsResult = runSecurityHeuristics(
        urlObj, rawInput, decodedUrl, missingProtocolAssumed, homographResult, brandSpoofs, clientEntropy
    );

    // Initial render with client analysis
    renderResults(rawInput, decodedUrl, decomposition, homographResult, heuristicsResult);

    // If Python Telemetry service is active, fetch deep backend analysis asynchronously!
    if (isPythonBackendConnected) {
        fetchPythonTelemetry(rawInput);
    } else {
        renderPythonPanelFallback();
    }
}

function parseURLComponents(urlObj) {
    const params = [];
    urlObj.searchParams.forEach((value, key) => {
        params.push({ key, value });
    });

    return {
        protocol: urlObj.protocol,
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? '443 (default)' : '80 (default)'),
        pathname: urlObj.pathname,
        params: params,
        hash: urlObj.hash || 'None'
    };
}

function analyzeHomographAndScripts(hostname) {
    const isPunycode = hostname.toLowerCase().startsWith('xn--') || hostname.toLowerCase().includes('.xn--');
    const charAnalysis = [];
    let hasCyrillic = false;
    let hasGreek = false;
    let hasLatin = false;

    for (const ch of hostname) {
        if (ch === '.') continue;
        const codePoint = ch.codePointAt(0);
        const hexCode = 'U+' + codePoint.toString(16).toUpperCase().padStart(4, '0');
        
        let script = 'Other';
        if (/[\p{Script=Latin}]/u.test(ch)) {
            script = 'Latin';
            hasLatin = true;
        } else if (/[\p{Script=Cyrillic}]/u.test(ch)) {
            script = 'Cyrillic';
            hasCyrillic = true;
        } else if (/[\p{Script=Greek}]/u.test(ch)) {
            script = 'Greek';
            hasGreek = true;
        } else if (/[\p{Script=Common}]/u.test(ch)) {
            script = 'Common';
        }

        const isSuspicious = (script === 'Cyrillic' || script === 'Greek');

        charAnalysis.push({
            glyph: ch,
            hex: hexCode,
            script: script,
            isSuspicious: isSuspicious
        });
    }

    const isMixedScript = hasLatin && (hasCyrillic || hasGreek);

    return {
        isPunycode,
        isMixedScript,
        charAnalysis
    };
}

function runSecurityHeuristics(urlObj, rawInput, decodedUrl, missingProtocolAssumed, homographResult, brandSpoofs, clientEntropy) {
    const audit = [];
    let totalRiskPoints = 0;

    // Rule 1: Protocol Check
    if (urlObj.protocol === 'http:') {
        audit.push({
            state: 'danger', icon: '⚠️', title: 'Insecure Protocol (HTTP)',
            desc: missingProtocolAssumed ? 'No protocol specified; HTTP assumed. High risk.' : 'Unencrypted HTTP transport.'
        });
        totalRiskPoints += 25;
    } else {
        audit.push({ state: 'safe', icon: '✅', title: 'Secure Protocol (HTTPS)', desc: 'Uses TLS encryption.' });
    }

    // Rule 2: Host Identity & Raw IP
    const isRawIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname) || urlObj.hostname.startsWith('[');
    if (isRawIP) {
        audit.push({
            state: 'danger', icon: '🚨', title: 'Raw IP Hostname Detected',
            desc: `Host (${urlObj.hostname}) is a raw IP. Bypasses domain reputation filters.`
        });
        totalRiskPoints += 35;
    }

    // Rule 3: Levenshtein Brand Spoofing
    if (brandSpoofs.length > 0) {
        const spoofDetails = brandSpoofs.map(s => `${s.brand} (edit distance: ${s.distance})`).join(', ');
        audit.push({
            state: 'danger', icon: '🎯', title: 'Fuzzy Brand Typosquatting Match',
            desc: `ALERT: Domain visually closely mimics major brand(s): ${spoofDetails}.`
        });
        totalRiskPoints += 45;
    }

    // Rule 4: Shannon Entropy / DGA Check
    if (clientEntropy > 3.8) {
        audit.push({
            state: 'warn', icon: '🎲', title: 'High Shannon Entropy (Potential DGA)',
            desc: `Domain randomness entropy score is ${clientEntropy} (>3.8). Common in algorithmically generated malware domains.`
        });
        totalRiskPoints += 20;
    }

    // Rule 5: Credential Stealing Syntax
    if (rawInput.includes('@')) {
        audit.push({
            state: 'danger', icon: '🔑', title: 'Credential Stealing / Authority Override',
            desc: 'Contains user:pass@ host override syntax.'
        });
        totalRiskPoints += 40;
    }

    // Rule 6: Homograph Check
    if (homographResult.isMixedScript) {
        audit.push({
            state: 'danger', icon: '🔤', title: 'Homograph Spoofing Attack',
            desc: 'Mixed Latin and Cyrillic/Greek character sets detected!'
        });
        totalRiskPoints += 50;
    } else if (homographResult.isPunycode) {
        audit.push({
            state: 'warn', icon: '🌐', title: 'Punycode IDN Domain',
            desc: 'Domain uses IDN Punycode encoding (xn--).'
        });
        totalRiskPoints += 25;
    }

    return {
        audit,
        riskScore: Math.min(100, totalRiskPoints)
    };
}

/* --------------------------------------------------------------------------
   PYTHON TELEMETRY INTEGRATION
   -------------------------------------------------------------------------- */
async function fetchPythonTelemetry(targetUrl) {
    const pythonPanel = document.getElementById('pythonTelemetryContent');
    if (!pythonPanel) return;

    pythonPanel.innerHTML = `<div style="color: var(--accent-cyan);">⏳ Querying local Python security engine (DNS, SSL, Headers)...</div>`;

    try {
        const response = await fetch(`${PYTHON_API_URL}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: targetUrl })
        });

        if (!response.ok) throw new Error('Backend response error');

        const data = await response.json();
        renderPythonPanelSuccess(data);
    } catch (err) {
        renderPythonPanelFallback();
    }
}

function renderPythonPanelSuccess(data) {
    const pythonPanel = document.getElementById('pythonTelemetryContent');
    const dns = data.dns_telemetry;
    const sslData = data.ssl_telemetry;
    const httpData = data.http_telemetry;

    const dnsIpBadges = dns.dns_success 
        ? dns.resolved_ips.map(ip => `<span class="tech-badge">${ip}</span>`).join(' ')
        : `<span class="tech-badge danger">DNS Failed</span>`;

    const sslStatus = sslData.has_ssl
        ? `<span style="color: var(--state-safe);">✓ Active (${sslData.version}) | Issuer: ${escapeHTML(sslData.issuer || 'Unknown')}</span>`
        : `<span style="color: var(--state-warn);">⚠️ ${escapeHTML(sslData.error || 'No TLS Connection')}</span>`;

    const secHeaders = httpData.security_headers;
    const headerBadges = secHeaders
        ? `
            <span class="badge ${secHeaders.strict_transport_security ? 'pass' : 'fail'}">HSTS</span>
            <span class="badge ${secHeaders.content_security_policy ? 'pass' : 'fail'}">CSP</span>
            <span class="badge ${secHeaders.x_frame_options ? 'pass' : 'fail'}">X-Frame</span>
          `
        : 'N/A';

    pythonPanel.innerHTML = `
        <div class="telemetry-grid">
            <div class="telemetry-item">
                <div class="telemetry-label">DNS Resolution & IPs</div>
                <div class="telemetry-val">${dnsIpBadges} ${dns.is_private_ip ? '<span class="tech-badge danger">SSRF / Private IP</span>' : ''}</div>
            </div>
            <div class="telemetry-item">
                <div class="telemetry-label">SSL/TLS Inspection</div>
                <div class="telemetry-val" style="font-size: 0.85rem;">${sslStatus}</div>
            </div>
            <div class="telemetry-item">
                <div class="telemetry-label">HTTP Security Controls</div>
                <div class="telemetry-val">${headerBadges} <span style="font-size: 0.8rem; color: var(--text-dim); margin-left: 0.5rem;">Server: ${escapeHTML(httpData.server_header || 'Unknown')}</span></div>
            </div>
            <div class="telemetry-item">
                <div class="telemetry-label">Backend Entropy Score</div>
                <div class="telemetry-val">${data.entropy.score} ${data.entropy.is_high_entropy ? '<span class="tech-badge warn">High Entropy</span>' : ''}</div>
            </div>
        </div>
    `;
}

function renderPythonPanelFallback() {
    const pythonPanel = document.getElementById('pythonTelemetryContent');
    if (!pythonPanel) return;
    pythonPanel.innerHTML = `
        <div style="color: var(--text-dim); font-size: 0.85rem;">
            ℹ️ Python Telemetry Service is offline. Run <code style="color: var(--accent-cyan);">python server.py</code> in terminal to enable live DNS resolution, SSL certificate auditing, and HTTP security header telemetry.
        </div>
    `;
}

/* --------------------------------------------------------------------------
   UI RENDERER
   -------------------------------------------------------------------------- */
function renderResults(rawInput, decodedUrl, comp, homograph, heuristics) {
    const resultsSec = document.getElementById('resultsSection');
    resultsSec.style.display = 'block';
    setTimeout(() => { resultsSec.classList.add('visible'); }, 20);

    const banner = document.getElementById('verdictBanner');
    const vTitle = document.getElementById('verdictTitle');
    const vDesc = document.getElementById('verdictDesc');
    const vIcon = document.getElementById('verdictIcon');
    const scoreVal = document.getElementById('riskScoreValue');

    banner.className = 'verdict-banner';
    scoreVal.textContent = heuristics.riskScore;

    if (heuristics.riskScore >= 40) {
        banner.classList.add('state-danger');
        vIcon.textContent = '🚨';
        vTitle.textContent = 'HIGH RISK / MALICIOUS INDICATORS DETECTED';
        vDesc.textContent = 'Severe security red flags flagged in this link structure.';
    } else if (heuristics.riskScore >= 15) {
        banner.classList.add('state-warn');
        vIcon.textContent = '⚠️';
        vTitle.textContent = 'SUSPICIOUS / USE CAUTION';
        vDesc.textContent = 'Anomalies detected in URL parameters or domain construction.';
    } else {
        banner.classList.add('state-safe');
        vIcon.textContent = '🛡️';
        vTitle.textContent = 'LOW RISK / NO SEVERE ANOMALIES';
        vDesc.textContent = 'Standard URL construction. No obvious homograph or typosquatting spoofing detected.';
    }

    const hList = document.getElementById('heuristicsList');
    hList.innerHTML = '';
    heuristics.audit.forEach(item => {
        const div = document.createElement('div');
        div.className = 'heuristic-item';
        div.innerHTML = `
            <div class="heuristic-icon">${item.icon}</div>
            <div class="heuristic-content">
                <div class="heuristic-title">${item.title}</div>
                <div class="heuristic-desc">${item.desc}</div>
            </div>
        `;
        hList.appendChild(div);
    });

    const charSeq = document.getElementById('charSequence');
    charSeq.innerHTML = '';
    homograph.charAnalysis.forEach(item => {
        const block = document.createElement('div');
        block.className = `char-block ${item.isSuspicious ? 'suspicious' : ''}`;
        block.innerHTML = `
            <span class="char-glyph">${escapeHTML(item.glyph)}</span>
            <span class="char-code">${item.hex}</span>
            <span class="char-script">${item.script}</span>
        `;
        charSeq.appendChild(block);
    });

    document.getElementById('rawUrlDisplay').textContent = rawInput;
    document.getElementById('decodedUrlDisplay').textContent = decodedUrl;

    document.getElementById('compProtocol').textContent = comp.protocol;
    document.getElementById('compHost').textContent = comp.hostname;
    document.getElementById('compPort').textContent = comp.port;
    document.getElementById('compPath').textContent = comp.pathname;
    document.getElementById('compHash').textContent = comp.hash;

    const paramsCell = document.getElementById('compParams');
    if (comp.params.length === 0) {
        paramsCell.textContent = 'None';
    } else {
        paramsCell.innerHTML = comp.params.map(p => 
            `<div><span class="param-badge">${escapeHTML(p.key)}</span> ${escapeHTML(p.value)}</div>`
        ).join('');
    }
}

function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
}
