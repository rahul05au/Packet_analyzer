const express = require('express');
const multer = require('multer');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Set up storage for uploaded pcap files
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, `upload_${Date.now()}.pcap`);
    }
});
const upload = multer({ storage });

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '100kb' }));

// Set up rules file
const RULES_FILE = path.join(__dirname, 'rules.txt');
if (!fs.existsSync(RULES_FILE)) {
    fs.writeFileSync(RULES_FILE, "[BLOCKED_IPS]\n\n[BLOCKED_APPS]\n\n[BLOCKED_DOMAINS]\n\n[BLOCKED_PORTS]\n", "utf8");
}

// Rules API endpoints
app.get('/api/rules', (req, res) => {
    try {
        const rulesText = fs.readFileSync(RULES_FILE, 'utf8');
        res.json({ success: true, content: rulesText });
    } catch (e) {
        res.status(500).json({ error: "Failed reading rules" });
    }
});

app.post('/api/rules', (req, res) => {
    try {
        fs.writeFileSync(RULES_FILE, req.body.content, 'utf8');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Failed writing rules" });
    }
});

// Parse the Java CLI output into structured JSON
function parseDpiOutput(output) {
    const data = {
        packets: { total: 0, tcp: 0, udp: 0, bytes: 0 },
        filtering: { forwarded: 0, dropped: 0, dropRate: 0 },
        classification: { total: 0, classified: 0, unknown: 0 },
        apps: []
    };

    const match = (regex) => { const m = output.match(regex); return m ? parseFloat(m[1]) : 0; };

    data.packets.total = match(/Total Packets:\s+(\d+)/);
    data.packets.bytes = match(/Total Bytes:\s+(\d+)/);
    data.packets.tcp = match(/TCP Packets:\s+(\d+)/);
    data.packets.udp = match(/UDP Packets:\s+(\d+)/);

    data.filtering.forwarded = match(/Forwarded:\s+(\d+)/);
    data.filtering.dropped = match(/Dropped\/Blocked:\s+(\d+)/);
    data.filtering.dropRate = match(/Drop Rate:\s+([\d.]+)%/);

    data.classification.total = match(/Total Connections:\s+(\d+)/);
    data.classification.classified = match(/Classified:\s+(\d+)/);
    data.classification.unknown = match(/Unidentified:\s+(\d+)/);

    // Parse application distribution list
    const appsSectionMatch = output.match(/APPLICATION DISTRIBUTION[\s\S]*?╠[═]+╣([\s\S]*?)╚[═]+╝/);
    if (appsSectionMatch) {
        const appsText = appsSectionMatch[1];
        const lines = appsText.split('\n');
        for (let line of lines) {
            line = line.replace(/║/g, '').trim();
            if (!line) continue;
            const parts = line.split(/\s{2,}/);
            if (parts.length >= 3) {
                const name = parts[0].trim();
                const count = parseInt(parts[1]);
                const pct = parseFloat(parts[2].replace('%', ''));
                if (name && !isNaN(count)) {
                    data.apps.push({ name, count, percentage: pct });
                }
            }
        }
    }

    return data;
}

// ─────────────────────────────────────────────
// STREAMING ANALYSIS ENDPOINT (SSE)
// ─────────────────────────────────────────────
app.post('/api/analyze-stream', upload.single('pcapFile'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No PCAP file uploaded' });
    }

    const inputPcap = req.file.path;
    const outputPcap = path.join(__dirname, 'uploads', `out_${Date.now()}.pcap`);
    const javaClasspath = path.join(__dirname, '..', 'PacketAnalyzerJava', 'out');
    const javaExe = 'java';

    // Set headers for Server-Sent Events
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const sendEvent = (type, payload) => {
        res.write(`data: ${JSON.stringify({ type, ...payload })}\n\n`);
    };

    sendEvent('status', { message: '🚀 Launching DPI Engine...' });

    const args = [
        '-cp', javaClasspath,
        'com.packetanalyzer.Main',
        '--dpi',
        inputPcap,
        outputPcap,
        RULES_FILE
    ];

    let fullOutput = '';
    let packetCount = 0;
    let lineBuffer = '';

    const child = spawn(javaExe, args);

    const processLine = (line) => {
        fullOutput += line + '\n';

        // ── Structured per-packet JSON emitted by FastPathProcessor ──────────
        if (line.startsWith('PKT_JSON:')) {
            try {
                const pkt = JSON.parse(line.slice(9));
                sendEvent('packet', pkt);           // sends to live table in UI
                if (pkt.action === 'BLOCKED') {
                    sendEvent('progress', { packets: ++packetCount });
                }
            } catch (e) { /* malformed line, ignore */ }
            return;  // don't also send as log
        }

        // Send raw log line to UI
        if (line.trim()) {
            sendEvent('log', { line: line.trim() });
        }

        // Try to extract running totals from output lines
        const pktMatch = line.match(/Packet\s+#?(\d+)/i);
        if (pktMatch) {
            packetCount = parseInt(pktMatch[1]);
            sendEvent('progress', { packets: packetCount });
        }

        // Detect final stats
        const totalMatch = line.match(/Total Packets:\s+(\d+)/);
        if (totalMatch) {
            sendEvent('progress', { packets: parseInt(totalMatch[1]) });
        }
    };

    const handleStream = (data) => {
        lineBuffer += data.toString();
        const lines = lineBuffer.split('\n');
        lineBuffer = lines.pop(); // keep incomplete last line
        lines.forEach(processLine);
    };

    child.stdout.on('data', handleStream);
    child.stderr.on('data', handleStream);

    req.on('close', () => {
        if (!child.killed) {
            console.log("Client disconnected early, killing Java process...");
            child.kill();
        }
    });

    child.on('close', (code) => {
        // Flush remaining buffer
        if (lineBuffer.trim()) processLine(lineBuffer);

        // Clean up temp files
        try {
            if (fs.existsSync(inputPcap)) fs.unlinkSync(inputPcap);
            if (fs.existsSync(outputPcap)) fs.unlinkSync(outputPcap);
        } catch (e) { console.error('Cleanup error', e); }

        if (fullOutput.includes('Total Packets:')) {
            const parsed = parseDpiOutput(fullOutput);
            sendEvent('done', { data: parsed });
        } else if (!child.killed) {
            sendEvent('error', { message: 'DPI engine produced no valid output. Check that the PCAP file is valid and Java is installed.' });
        }

        res.end();
    });

    child.on('error', (err) => {
        sendEvent('error', { message: 'Failed to start Java process: ' + err.message });
        res.end();
    });
});

app.listen(PORT, () => {
    console.log(`Packet Analyzer Web UI running at http://localhost:${PORT}`);
});
