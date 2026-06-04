# 🔍 Packet Analyzer — Java DPI Engine + Web UI

> A high-performance, multithreaded **Deep Packet Inspection (DPI)** engine written in Java, paired with a real-time **Node.js web interface**. Reads `.pcap` files, classifies network traffic by application, extracts TLS SNI / HTTP Host / DNS information, and enforces IP/domain/app/port blocking rules.

---

## 📸 Overview

```
┌─────────────────────────────────────────────┐
│           Browser  (Web UI)                 │
│  Upload PCAP ──► Live Table + Stats Cards   │
└────────────────┬────────────────────────────┘
                 │ HTTP / SSE
┌────────────────▼────────────────────────────┐
│         Node.js Express Server              │
│      PacketAnalyzerWeb / server.js          │
└────────────────┬────────────────────────────┘
                 │ spawns
┌────────────────▼────────────────────────────┐
│         Java DPI Engine                     │
│                                             │
│  PcapReader ──► LoadBalancers (×2)          │
│                     └──► FastPathProcessors │
│                              ├── SNI/TLS    │
│                              ├── HTTP/DNS   │
│                              ├── Rule Match │
│                              └──► Output    │
└─────────────────────────────────────────────┘
```

---

## 🏗️ Project Structure

```
Packet_analyzer/
├── PacketAnalyzerJava/          # Java DPI engine (CLI)
│   └── src/main/java/com/packetanalyzer/
│       ├── Main.java            # Entry point (display + DPI modes)
│       ├── DpiEngine.java       # Main orchestrator
│       ├── PcapReader.java      # Binary .pcap file parser
│       ├── PacketParser.java    # Ethernet / IP / TCP / UDP parser
│       ├── SniExtractor.java    # TLS SNI, HTTP Host, DNS, QUIC extraction
│       ├── ConnectionTracker.java  # Per-flow connection state table
│       ├── FastPathProcessor.java  # Worker: DPI + rule matching
│       ├── LoadBalancer.java    # Consistent-hash packet router
│       ├── RuleManager.java     # Thread-safe blocking rules
│       ├── AppType.java         # Application classification enum
│       ├── FiveTuple.java       # Flow key: src/dst IP+port+protocol
│       ├── Connection.java      # Per-flow state object
│       ├── PacketJob.java       # Packet container for thread handoff
│       └── ParsedPacket.java    # Human-readable parsed fields
│
├── PacketAnalyzerWeb/           # Node.js web interface
│   ├── server.js                # Express server + SSE streaming
│   ├── rules.txt                # Active blocking rules (editable via UI)
│   ├── start_web.bat            # Windows one-click launcher
│   └── public/
│       ├── index.html           # Frontend SPA
│       └── style.css            # Styling
│
├── generate_test_pcaps.py       # Python script to generate test PCAP files
└── .gitignore
```

---

## ⚙️ Architecture Deep-Dive

### Multithreaded Pipeline

```
PcapReader (1 reader thread)
    │
    │  consistent-hash on FiveTuple
    ▼
LoadBalancers × 2  (LB threads)
    │
    │  consistent-hash on FiveTuple
    ▼
FastPathProcessors × 4  (FP threads)
    │
    │  Per-packet:
    │   • TLS ClientHello → SNI extraction
    │   • HTTP GET/POST  → Host header
    │   • DNS queries    → domain lookup
    │   • QUIC           → SNI extraction
    │   • IP/App/Domain/Port rule matching
    ▼
Output Queue → Output Writer thread → Forwarded PCAP
```

- **Consistent hashing** on the 5-tuple ensures all packets belonging to the same flow are always processed by the same `FastPathProcessor` thread — no locking needed for per-flow state.
- `LinkedBlockingQueue` (Java built-in) replaces the C++ custom `ThreadSafeQueue<T>`.
- `ReentrantReadWriteLock` replaces `std::shared_mutex` for `RuleManager`.

### Application Detection

The engine detects **23 applications** via TLS SNI, HTTP Host headers, and DNS queries:

| Protocol Apps | Streaming | Social | Productivity | Messaging |
|---|---|---|---|---|
| HTTP, HTTPS, DNS, TLS, QUIC | YouTube, Netflix, Spotify | Facebook, Instagram, Twitter/X, TikTok | Google, Microsoft, Amazon, Apple, GitHub, Cloudflare | WhatsApp, Telegram, Discord, Zoom |

---

## 🛠️ Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **Java JDK** | 11 or higher | Compile & run the DPI engine |
| **Node.js** | 16 or higher | Run the web server |
| **npm** | bundled with Node.js | Install web dependencies |

---

## 🚀 Quick Start

### 1. Compile the Java Engine

```cmd
cd PacketAnalyzerJava\src\main\java
javac com\packetanalyzer\*.java -d ..\..\..\..\out
```

> Output `.class` files will be placed in `PacketAnalyzerJava/out/`

### 2. Install Web Dependencies

```cmd
cd PacketAnalyzerWeb
npm install
```

### 3. Launch the Web UI

```cmd
cd PacketAnalyzerWeb
node server.js
```

Or use the one-click launcher on Windows:
```cmd
PacketAnalyzerWeb\start_web.bat
```

Then open your browser at: **http://localhost:3000**

---

## 💻 CLI Usage (Java Engine Only)

### Mode 1 — Simple Packet Display

Print human-readable packet info from a `.pcap` file:

```cmd
java -cp PacketAnalyzerJava\out com.packetanalyzer.Main path\to\capture.pcap
java -cp PacketAnalyzerJava\out com.packetanalyzer.Main path\to\capture.pcap 50
```

The optional second argument limits the number of packets displayed.

**Sample Output:**
```
Packet #1: TCP 192.168.1.5:54321 -> 142.250.80.46:443 (46 bytes)
  App: Google  SNI: www.googleapis.com
Packet #2: UDP 192.168.1.5:53231 -> 8.8.8.8:53  (73 bytes)
  App: DNS     Query: www.youtube.com
```

### Mode 2 — Full DPI Engine Pipeline

Process a `.pcap` through the full DPI pipeline with optional blocking rules:

```cmd
java -cp PacketAnalyzerJava\out com.packetanalyzer.Main --dpi input.pcap output.pcap
java -cp PacketAnalyzerJava\out com.packetanalyzer.Main --dpi input.pcap output.pcap rules.txt
```

**Sample Output:**
```
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE STATISTICS                      ║
╠══════════════════════════════════════════════════════════════╣
║ PACKET STATISTICS                                             ║
║   Total Packets:             1842                             ║
║   Total Bytes:             987432                             ║
║   TCP Packets:               1203                             ║
║   UDP Packets:                639                             ║
╠══════════════════════════════════════════════════════════════╣
║ FILTERING STATISTICS                                          ║
║   Forwarded:                 1612                             ║
║   Dropped/Blocked:            230                             ║
║   Drop Rate:                12.49%                            ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 📋 Blocking Rules Format

Create a `rules.txt` file with the following sections (all sections are optional):

```ini
[BLOCKED_IPS]
1.2.3.4
10.0.0.100

[BLOCKED_APPS]
YouTube
Netflix
TikTok
Facebook

[BLOCKED_DOMAINS]
*.facebook.com
badsite.com
*.tiktok.com

[BLOCKED_PORTS]
8080
4444
```

**Supported App Names:** `YouTube`, `Netflix`, `Facebook`, `Instagram`, `Twitter`, `TikTok`, `Spotify`, `Google`, `Microsoft`, `Amazon`, `Apple`, `WhatsApp`, `Telegram`, `Discord`, `Zoom`, `GitHub`, `Cloudflare`

---

## 🌐 Web Interface Features

| Feature | Description |
|---------|-------------|
| 📁 **PCAP Upload** | Drag-and-drop or browse to upload any `.pcap` file |
| 📡 **Live Packet Table** | Real-time packet stream via Server-Sent Events (SSE) |
| 📊 **Stats Dashboard** | Total packets, TCP/UDP split, forwarded/dropped counts, drop rate |
| 🔵 **App Distribution** | Visual breakdown of classified applications |
| 🚫 **Rules Editor** | Edit and save `rules.txt` blocking rules directly from the browser |
| 🖥️ **DPI Log Console** | Raw engine output streamed live to the UI |

### How It Works (Web)

1. User uploads a `.pcap` file via the browser
2. Server saves the file temporarily and spawns the Java DPI engine
3. Engine output is streamed line-by-line over SSE to the browser
4. `PKT_JSON:` prefixed lines are parsed and rendered in the live table
5. Final statistics are parsed and shown in the dashboard cards
6. Temp files are cleaned up automatically after analysis

---

## 🗺️ C++ → Java Mapping

This project is a complete Java port of a C++ DPI engine:

| C++ File / Class | Java File |
|---|---|
| `types.h` / `types.cpp` | `AppType.java`, `FiveTuple.java`, `Connection.java`, `PacketJob.java` |
| `pcap_reader.h/.cpp` | `PcapReader.java` |
| `packet_parser.h/.cpp` | `PacketParser.java`, `ParsedPacket.java` |
| `sni_extractor.h/.cpp` | `SniExtractor.java` |
| `connection_tracker.h/.cpp` | `ConnectionTracker.java` |
| `rule_manager.h/.cpp` | `RuleManager.java` |
| `fast_path.h/.cpp` | `FastPathProcessor.java` |
| `load_balancer.h/.cpp` | `LoadBalancer.java` |
| `dpi_engine.h/.cpp` | `DpiEngine.java` |
| `thread_safe_queue.h` | `java.util.concurrent.LinkedBlockingQueue` |
| `main.cpp` | `Main.java` |

### Key Language Differences

| Feature | C++ | Java |
|---|---|---|
| Thread-safe queue | `ThreadSafeQueue<T>` (custom) | `LinkedBlockingQueue<PacketJob>` |
| Shared mutex | `std::shared_mutex` | `ReentrantReadWriteLock` |
| Optional return | `std::optional<T>` | Return `null` |
| Atomic counters | `std::atomic<uint64_t>` | `AtomicLong` |
| Raw byte access | `uint8_t*` pointer arithmetic | `byte[]` with index arithmetic |
| Unsigned integers | `uint8_t`, `uint16_t`, … | `int`/`long` with `& 0xFF` masking |
| Memory management | Stack/RAII, no GC overhead | JVM managed heap |

---

## 🧪 Generating Test PCAP Files

A Python script is included to generate synthetic test captures:

```cmd
python generate_test_pcaps.py
```

This creates several `.pcap` files simulating YouTube, ChatGPT, and other traffic patterns, useful for testing blocking rules.

---

## 📁 Web API Reference

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/analyze-stream` | `multipart/form-data` | Upload PCAP, stream results via SSE |
| `POST /api/analyze` | `multipart/form-data` | Upload PCAP, get JSON response (legacy) |
| `GET /api/rules` | — | Fetch current `rules.txt` content |
| `POST /api/rules` | `application/json` | Save updated rules content |

---

## 📌 Notes

- The Java engine reads **standard libpcap format** (`.pcap`) files — not `.pcapng`
- Only **IPv4 TCP and UDP** packets are processed; others are skipped
- The output PCAP contains only **forwarded (non-blocked)** packets
- For large captures (>100MB), use the CLI mode directly for better performance

---

## 👤 Author

**Rahul Kumar** — [github.com/rahul05au](https://github.com/rahul05au)

See the full list of contributors in [CONTRIBUTORS.md](CONTRIBUTORS.md).

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

Please make sure your code follows the existing style and includes appropriate documentation.

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
