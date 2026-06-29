/**
 * =============================================================================
 * UNFURL REAL-TIME SNIFFER TELEMETRY CONTROLLER
 * =============================================================================
 * Handles WebSocket connection to sniffer.py, updates the live packet stream UI,
 * calculates traffic volume and threat heuristics counters, and manages Chart.js.
 */

(function () {
    // Real-time counters
    let totalPackets = 0;
    let threatAlerts = 0;
    let totalBytes = 0;
    let protoCounts = { TCP: 0, UDP: 0, OTHER: 0 };
    let protocolChart = null;

    // DOM Elements
    let wsBadge, wsStatusText, statTotalPackets, statThreatAlerts, statTotalBytes, logTableBody;

    // Initialize sniffer client on DOM load
    document.addEventListener('DOMContentLoaded', () => {
        initDOMElements();
        initChart();
        connectTelemetryStream();
    });

    function initDOMElements() {
        wsBadge = document.getElementById('wsBadge');
        wsStatusText = document.getElementById('wsStatusText');
        statTotalPackets = document.getElementById('statTotalPackets');
        statThreatAlerts = document.getElementById('statThreatAlerts');
        statTotalBytes = document.getElementById('statTotalBytes');
        logTableBody = document.getElementById('logTableBody');
    }

    function initChart() {
        const canvas = document.getElementById('protocolChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        protocolChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'Others'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#00bfff', '#9d4edd', '#f59e0b'],
                    borderColor: '#0c1222',
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', font: { family: 'Fira Code, monospace' } }
                    }
                }
            }
        });
    }

    // Setup Telemetry Stream Connection (HTTP SSE with WebSocket Fallback)
    function connectTelemetryStream() {
        if (!wsBadge || !wsStatusText) return;

        const streamUrl = (window.location.origin && window.location.origin !== 'null' && window.location.protocol.startsWith('http'))
            ? `${window.location.origin}/api/sniffer/stream`
            : 'http://localhost:8000/api/sniffer/stream';

        try {
            const eventSource = new EventSource(streamUrl);

            eventSource.onopen = () => {
                wsBadge.className = 'ws-badge online';
                wsStatusText.textContent = 'LIVE TELEMETRY STREAMING';
            };

            eventSource.onmessage = (event) => {
                try {
                    const packet = JSON.parse(event.data);
                    processIncomingPacket(packet);
                } catch (err) {
                    console.error("Error processing packet data:", err);
                }
            };

            eventSource.onerror = () => {
                wsBadge.className = 'ws-badge';
                wsStatusText.textContent = 'DISCONNECTED - RETRYING...';
            };
        } catch (e) {
            connectWebSocketFallback();
        }
    }

    function connectWebSocketFallback() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsHost = (window.location.hostname && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1')
            ? window.location.host
            : 'localhost:8765';
        const socket = new WebSocket(`${wsProtocol}//${wsHost}`);

        socket.onopen = () => {
            wsBadge.className = 'ws-badge online';
            wsStatusText.textContent = 'WEBSOCKET CONNECTED (LIVE)';
        };

        socket.onmessage = (event) => {
            try {
                const packet = JSON.parse(event.data);
                processIncomingPacket(packet);
            } catch (err) {
                console.error("Error processing packet data:", err);
            }
        };

        socket.onclose = () => {
            wsBadge.className = 'ws-badge';
            wsStatusText.textContent = 'DISCONNECTED - RETRYING...';
            setTimeout(connectTelemetryStream, 3000);
        };

        socket.onerror = () => {
            socket.close();
        };
    }

    function processIncomingPacket(packet) {
        // Update Metrics
        totalPackets++;
        totalBytes += packet.size;
        if (packet.is_suspicious) threatAlerts++;

        if (statTotalPackets) statTotalPackets.textContent = totalPackets.toLocaleString();
        if (statThreatAlerts) statThreatAlerts.textContent = threatAlerts.toLocaleString();
        if (statTotalBytes) {
            statTotalBytes.textContent = (totalBytes / 1024).toFixed(1) + ' KB';
        }

        // Update Chart protocol breakdown
        if (packet.protocol === 'TCP') protoCounts.TCP++;
        else if (packet.protocol === 'UDP') protoCounts.UDP++;
        else protoCounts.OTHER++;

        if (protocolChart) {
            protocolChart.data.datasets[0].data = [protoCounts.TCP, protoCounts.UDP, protoCounts.OTHER];
            protocolChart.update('none'); // Silent fast update without animation loop lag
        }

        // Render Table Row
        if (!logTableBody) return;
        const tr = document.createElement('tr');
        if (packet.is_suspicious) {
            tr.className = 'alert-row';
        }

        const protoClass = packet.protocol === 'TCP' ? 'proto-tcp' : packet.protocol === 'UDP' ? 'proto-udp' : 'proto-other';

        tr.innerHTML = `
            <td>${escapeHTML(packet.timestamp)}</td>
            <td><span class="proto-badge ${protoClass}">${escapeHTML(packet.protocol)}</span></td>
            <td>${escapeHTML(packet.src)}</td>
            <td>${escapeHTML(packet.dst)}</td>
            <td>${packet.size} B</td>
            <td>${packet.is_suspicious ? '🚨 ' + escapeHTML(packet.alert) : '✓ Normal'}</td>
        `;

        // Prepend to top of table
        logTableBody.insertBefore(tr, logTableBody.firstChild);

        // Strict 30 row cap
        if (logTableBody.children.length > 30) {
            logTableBody.removeChild(logTableBody.lastChild);
        }
    }

    function escapeHTML(str) {
        return String(str).replace(/[&<>'"]/g, 
            tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
        );
    }
})();
