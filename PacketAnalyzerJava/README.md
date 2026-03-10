# Packet Analyzer — Java Port

A complete Java conversion of the C++ Deep Packet Inspection (DPI) packet analyzer.

## Project Structure

```
PacketAnalyzerJava/
└── src/main/java/com/packetanalyzer/
    ├── Main.java               # Entry point (display + DPI modes)
    ├── AppType.java            # Application classification enum (C++ AppType)
    ├── FiveTuple.java          # Flow identifier: src/dst IP+port+protocol
    ├── Connection.java         # Per-flow connection state
    ├── PacketJob.java          # Packet container passed between threads
    ├── PcapReader.java         # .pcap file reader (C++ PcapReader)
    ├── ParsedPacket.java       # Human-readable parsed fields
    ├── PacketParser.java       # Ethernet / IP / TCP / UDP parser
    ├── SniExtractor.java       # TLS SNI, HTTP Host, DNS, QUIC extraction
    ├── ConnectionTracker.java  # Per-FP flow table (C++ ConnectionTracker)
    ├── RuleManager.java        # Thread-safe blocking rules (C++ RuleManager)
    ├── FastPathProcessor.java  # Worker thread: DPI + rule matching (C++ FastPathProcessor)
    ├── LoadBalancer.java       # Consistent-hash router → FP threads (C++ LoadBalancer)
    └── DpiEngine.java          # Main orchestrator (C++ DPIEngine)
```

## Architecture

```
PcapReader (reader thread)
    │
    ▼ hash → select LB
LoadBalancers × 2  (LB threads)
    │
    ▼ hash → select FP within LB
FastPathProcessors × 4  (FP threads)
    │  • Connection tracking
    │  • TLS SNI / HTTP Host / DNS extraction
    │  • IP / App / Domain / Port rule matching
    ▼
Output Queue → Output Writer thread → Forwarded PCAP
```

## Build & Run

### Compile
```cmd
cd PacketAnalyzerJava\src\main\java
javac com\packetanalyzer\*.java
```

### Mode 1 — Simple Packet Display (like original main.cpp)
```cmd
java -cp . com.packetanalyzer.Main path\to\capture.pcap
java -cp . com.packetanalyzer.Main path\to\capture.pcap 10
```

### Mode 2 — Full DPI Engine Pipeline
```cmd
java -cp . com.packetanalyzer.Main --dpi input.pcap output.pcap
java -cp . com.packetanalyzer.Main --dpi input.pcap output.pcap rules.txt
```

## Rules File Format

```
[BLOCKED_IPS]
1.2.3.4

[BLOCKED_APPS]
YouTube
Facebook

[BLOCKED_DOMAINS]
*.facebook.com
badsite.com

[BLOCKED_PORTS]
8080
```

## C++ → Java Mapping

| C++ File / Class              | Java File                       |
|-------------------------------|---------------------------------|
| `types.h` / `types.cpp`       | `AppType.java`, `FiveTuple.java`, `Connection.java`, `PacketJob.java` |
| `pcap_reader.h/.cpp`          | `PcapReader.java`               |
| `packet_parser.h/.cpp`        | `PacketParser.java`, `ParsedPacket.java` |
| `sni_extractor.h/.cpp`        | `SniExtractor.java`             |
| `connection_tracker.h/.cpp`   | `ConnectionTracker.java`        |
| `rule_manager.h/.cpp`         | `RuleManager.java`              |
| `fast_path.h/.cpp`            | `FastPathProcessor.java`        |
| `load_balancer.h/.cpp`        | `LoadBalancer.java`             |
| `dpi_engine.h/.cpp`           | `DpiEngine.java`                |
| `thread_safe_queue.h`         | `java.util.concurrent.LinkedBlockingQueue` |
| `main.cpp`                    | `Main.java`                     |

## Key Differences from C++

| Feature                  | C++                            | Java                                       |
|--------------------------|--------------------------------|--------------------------------------------|
| Thread-safe queue        | Custom `ThreadSafeQueue<T>`    | `LinkedBlockingQueue<PacketJob>`           |
| Shared mutex             | `std::shared_mutex`            | `ReentrantReadWriteLock`                   |
| Optional return values   | `std::optional<T>`             | Return `null`                              |
| Atomic integers          | `std::atomic<uint64_t>`        | `AtomicLong`                               |
| Raw byte access          | `uint8_t*` pointer arithmetic  | `byte[]` with index arithmetic             |
| Unsigned integers        | `uint8_t`, `uint16_t`, …       | `int`/`long` with `& 0xFF` masking         |
| No GC / no heap overhead | Stack/RAII allocation          | JVM managed heap                           |
