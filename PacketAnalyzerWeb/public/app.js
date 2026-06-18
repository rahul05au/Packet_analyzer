document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const uploadSection = document.getElementById('uploadSection');
    const loadingState = document.getElementById('loading');
    const resultsSection = document.getElementById('resultsSection');
    const btnNewScan = document.getElementById('btnNewScan');
    const livePacketCount = document.getElementById('livePacketCount');
    const liveLog = document.getElementById('liveLog');
    const loadingStatus = document.getElementById('loadingStatus');

    // ── Navigation ──────────────────────────────────────────────────
    const btnNavUpload = document.getElementById('btnNavUpload');
    const btnNavRules = document.getElementById('btnNavRules');
    const rulesSection = document.getElementById('rulesSection');
    const rulesEditor = document.getElementById('rulesEditor');
    const btnSaveRules = document.getElementById('btnSaveRules');
    const rulesSaveSuccess = document.getElementById('rulesSaveSuccess');

    btnNavUpload.addEventListener('click', () => {
        btnNavUpload.classList.add('active');
        btnNavRules.classList.remove('active');
        rulesSection.classList.add('hidden');
        uploadSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        dropZone.style.display = 'block';
    });

    btnNavRules.addEventListener('click', () => {
        btnNavRules.classList.add('active');
        btnNavUpload.classList.remove('active');
        uploadSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
        rulesSection.classList.remove('hidden');
        rulesSaveSuccess.classList.add('hidden');
        fetch('/api/rules')
            .then(r => r.json())
            .then(d => { if (d.success) rulesEditor.value = d.content; })
            .catch(e => console.error(e));
    });

    btnSaveRules.addEventListener('click', () => {
        btnSaveRules.textContent = 'Saving...';
        btnSaveRules.disabled = true;
        fetch('/api/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: rulesEditor.value })
        })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    rulesSaveSuccess.classList.remove('hidden');
                    setTimeout(() => rulesSaveSuccess.classList.add('hidden'), 3000);
                } else showErrorToast('Failed to save rules.');
            })
            .catch(() => showErrorToast('Error saving rules.'))
            .finally(() => { btnSaveRules.textContent = 'Save Rules'; btnSaveRules.disabled = false; });
    });

    // ── Drag & Drop ──────────────────────────────────────────────────
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault(); dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
    });
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => { if (fileInput.files.length > 0) handleFile(fileInput.files[0]); });

    btnNewScan.addEventListener('click', () => {
        resultsSection.classList.add('hidden');
        dropZone.style.display = 'block';
        uploadSection.classList.remove('hidden');
        fileInput.value = '';
        clearDashboard();
    });

    // ── File Handler ─────────────────────────────────────────────────
    function handleFile(file) {
        if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
            alert('Please upload a valid .pcap or .pcapng file');
            return;
        }
        dropZone.style.display = 'none';
        loadingState.classList.remove('hidden');
        if (liveLog) liveLog.innerHTML = '';
        if (livePacketCount) livePacketCount.textContent = '0';
        if (loadingStatus) loadingStatus.textContent = 'Starting DPI Engine...';

        const formData = new FormData();
        formData.append('pcapFile', file);

        // Use streaming SSE endpoint
        analyzeWithStream(formData);
    }

    // ── Streaming Analysis via SSE ───────────────────────────────────
    function analyzeWithStream(formData) {
        fetch('/api/analyze-stream', { method: 'POST', body: formData })
            .then(response => {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';

                const pump = () => reader.read().then(({ done, value }) => {
                    if (done) return;
                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\n');
                    buffer = lines.pop();

                    lines.forEach(line => {
                        if (line.startsWith('data: ')) {
                            try {
                                const event = JSON.parse(line.slice(6));
                                handleStreamEvent(event);
                            } catch (e) { }
                        }
                    });
                    pump();
                });
                pump();
            })
            .catch(err => {
                console.error('Stream error:', err);
                alert('Failed to connect to the analyzer engine.');
                btnNewScan.click();
            });
    }

    // ── Handle each SSE event ────────────────────────────────────────
    let pktRowCount = 0;

    function handleStreamEvent(event) {
        switch (event.type) {
            case 'status':
                if (loadingStatus) loadingStatus.textContent = event.message;
                appendLog(event.message, 'log-info');
                break;

            case 'log':
                appendLog(event.line, classifyLogLine(event.line));
                if (loadingStatus) loadingStatus.textContent = truncate(event.line, 55);
                break;

            case 'progress':
                if (livePacketCount && event.packets > 0) {
                    animateValueEl(livePacketCount, parseInt(livePacketCount.textContent) || 0, event.packets, 400);
                }
                break;

            case 'packet':
                addPacketRow(event);
                break;

            case 'done':
                loadingState.classList.add('hidden');
                uploadSection.classList.add('hidden');
                renderDashboard(event.data);
                break;

            case 'error':
                loadingState.classList.add('hidden');
                showErrorToast(event.message);
                dropZone.style.display = 'block';
                uploadSection.classList.remove('hidden');
                break;
        }
    }

    // ── Live log panel ───────────────────────────────────────────────
    function appendLog(text, cssClass = '') {
        if (!liveLog) return;
        const line = document.createElement('div');
        line.className = 'log-line ' + cssClass;
        line.textContent = text;
        liveLog.appendChild(line);
        // Keep only last 80 lines
        while (liveLog.children.length > 80) liveLog.removeChild(liveLog.firstChild);
        liveLog.scrollTop = liveLog.scrollHeight;
    }

    function classifyLogLine(line) {
        const l = line.toLowerCase();
        if (l.includes('block') || l.includes('drop')) return 'log-blocked';
        if (l.includes('error') || l.includes('fail')) return 'log-error';
        if (l.includes('forward') || l.includes('pass')) return 'log-ok';
        if (l.includes('dns') || l.includes('sni') || l.includes('http')) return 'log-dns';
        return '';
    }

    function truncate(str, n) { return str.length > n ? str.slice(0, n) + '…' : str; }

    // ── Render Dashboard ─────────────────────────────────────────────
    function renderDashboard(data) {
        resultsSection.classList.remove('hidden');

        // Stagger card animations
        document.querySelectorAll('.stat-card.pop-in').forEach((c, i) => {
            c.style.animationDelay = (0.05 * i) + 's';
            c.style.opacity = '0';
            c.style.transform = 'scale(0.92)';
            setTimeout(() => { c.style.opacity = '1'; c.style.transform = 'scale(1)'; c.style.transition = 'all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)'; }, 80 * i);
        });

        // Animate stat numbers with count-up
        animateValue('stat-total', 0, data.packets.total, 1200);
        animateValue('stat-tcp', 0, data.packets.tcp, 1200);
        animateValue('stat-udp', 0, data.packets.udp, 1200);
        animateValue('stat-blocked', 0, data.filtering.dropped, 1200);

        // Color blocked card red if any packets blocked
        const blockedCard = document.querySelector('.stat-card.shield-card');
        if (blockedCard && data.filtering.dropped > 0) {
            blockedCard.style.borderColor = 'rgba(255,51,102,0.5)';
            blockedCard.style.boxShadow = '0 0 24px rgba(255,51,102,0.2)';
        }

        // ── Apps List ────────────────────────────────────────────────
        const appsList = document.getElementById('appsList');
        appsList.innerHTML = '';

        if (data.apps && data.apps.length > 0) {
            // Sort by count desc
            data.apps.sort((a, b) => b.count - a.count);
            data.apps.forEach((app, idx) => {
                const item = document.createElement('div');
                item.className = 'app-item';
                item.style.opacity = '0';
                item.style.transform = 'translateX(-12px)';
                item.innerHTML = `
                    <div class="app-title">
                        <span>${app.name}</span>
                        <span class="app-count">${app.count} conns · ${app.percentage}%</span>
                    </div>
                    <div class="app-bar-wrap">
                        <div class="app-bar" style="width: 0%" data-target="${app.percentage}"></div>
                    </div>
                `;
                appsList.appendChild(item);
                setTimeout(() => {
                    item.style.transition = 'all 0.4s ease';
                    item.style.opacity = '1';
                    item.style.transform = 'translateX(0)';
                }, 100 * idx);
            });

            setTimeout(() => {
                document.querySelectorAll('.app-bar').forEach(bar => {
                    bar.style.width = bar.getAttribute('data-target') + '%';
                });
            }, 400);
        } else {
            appsList.innerHTML = '<p class="text-dim">No recognizable application data found. Try uploading a larger .pcap capture (10–30 seconds of browsing).</p>';
        }

        // ── Summary Panel ─────────────────────────────────────────────
        animateValue('sum-total', 0, data.classification.total, 1000);
        animateValue('sum-class', 0, data.classification.classified, 1000);
        animateValue('sum-unk', 0, data.classification.unknown, 1000);

        let bytesStr = data.packets.bytes + ' B';
        if (data.packets.bytes > 1024 * 1024) bytesStr = (data.packets.bytes / (1024 * 1024)).toFixed(2) + ' MB';
        else if (data.packets.bytes > 1024) bytesStr = (data.packets.bytes / 1024).toFixed(2) + ' KB';
        document.getElementById('sum-bytes').textContent = bytesStr;

        // Drop Rate badge
        const dropRateEl = document.getElementById('dropRate');
        if (dropRateEl) {
            animateValueEl(dropRateEl, 0, data.filtering.dropRate, 1200, 1, '%');
        }

        // ── Ring Chart ────────────────────────────────────────────────
        const ringFill = document.getElementById('classifiedRing');
        const textPct = document.getElementById('classifiedPercentage');
        const totalConns = data.classification.total;
        const classified = data.classification.classified;
        let pct = totalConns > 0 ? Math.round((classified / totalConns) * 100) : 0;

        ringFill.setAttribute('stroke-dasharray', '0, 100');
        textPct.textContent = '0%';

        setTimeout(() => {
            ringFill.setAttribute('stroke-dasharray', `${pct}, 100`);
            animateValue('classifiedPercentage', 0, pct, 1000, '%');
        }, 300);
    }

    // ── Utility: Clear dashboard for new scan ────────────────────────
    function clearDashboard() {
        pktRowCount = 0;
        ['stat-total', 'stat-tcp', 'stat-udp', 'stat-blocked',
            'sum-total', 'sum-class', 'sum-unk'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.textContent = '0';
            });
        const sb = document.getElementById('sum-bytes'); if (sb) sb.textContent = '0 B';
        const ring = document.getElementById('classifiedRing');
        if (ring) ring.setAttribute('stroke-dasharray', '0,100');
        const pctEl = document.getElementById('classifiedPercentage');
        if (pctEl) pctEl.textContent = '0%';
        const al = document.getElementById('appsList');
        if (al) al.innerHTML = '';
        if (liveLog) liveLog.innerHTML = '';
        if (livePacketCount) livePacketCount.textContent = '0';
        // Reset packet table
        const tbody = document.getElementById('packetTableBody');
        if (tbody) tbody.innerHTML = '';
        const cnt = document.getElementById('pktTableCount');
        if (cnt) cnt.textContent = '0';
    }

    // ── Live Packet Table Row ─────────────────────────────────────────
    function addPacketRow(pkt) {
        const tbody = document.getElementById('packetTableBody');
        const countEl = document.getElementById('pktTableCount');
        if (!tbody) return;

        pktRowCount++;
        if (countEl) countEl.textContent = pktRowCount;

        const isBlocked = pkt.action === 'BLOCKED';
        const tr = document.createElement('tr');
        tr.className = 'pkt-row ' + (isBlocked ? 'pkt-blocked' : 'pkt-forward');

        tr.innerHTML = `
            <td class="pkt-num">${pktRowCount}</td>
            <td class="pkt-ip">${pkt.src}</td>
            <td class="pkt-ip">${pkt.dst}</td>
            <td><span class="proto-badge proto-${pkt.proto}">${pkt.proto}</span></td>
            <td class="pkt-port">${pkt.port}</td>
            <td class="pkt-sni">${pkt.sni === '-' ? '<span class="dim">—</span>' : pkt.sni}</td>
            <td class="pkt-app">${pkt.app}</td>
            <td><span class="action-badge ${isBlocked ? 'action-blocked' : 'action-forward'}">
                ${isBlocked ? '🔴 BLOCKED' : '🟢 FORWARD'}
            </span></td>
        `;

        // Keep max 200 rows for performance
        if (tbody.children.length >= 200) tbody.removeChild(tbody.firstChild);
        tbody.appendChild(tr);

        // Smooth scroll to latest if near bottom
        const wrap = tbody.closest('.packet-table-wrap');
        if (wrap) wrap.scrollTop = wrap.scrollHeight;
    }

    // ── Error Toast ───────────────────────────────────────────────────
    function showErrorToast(msg) {
        const toast = document.createElement('div');
        toast.className = 'error-toast';
        toast.textContent = '⚠️ ' + msg;
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 10);
        setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 400); }, 5000);
    }

    // ── Count-Up Animation ────────────────────────────────────────────
    function animateValue(id, start, end, duration, suffix = '') {
        const obj = document.getElementById(id);
        if (!obj) return;
        animateValueEl(obj, start, end, duration, 0, suffix);
    }

    function animateValueEl(el, start, end, duration, decimals = 0, suffix = '') {
        if (!el) return;
        const range = end - start;
        if (range === 0) { el.textContent = end.toFixed(decimals) + suffix; return; }
        const startTime = performance.now();
        const step = (now) => {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Ease out
            const eased = 1 - Math.pow(1 - progress, 3);
            const value = start + range * eased;
            el.textContent = value.toFixed(decimals) + suffix;
            if (progress < 1) requestAnimationFrame(step);
            else el.textContent = end.toFixed(decimals) + suffix;
        };
        requestAnimationFrame(step);
    }
});
