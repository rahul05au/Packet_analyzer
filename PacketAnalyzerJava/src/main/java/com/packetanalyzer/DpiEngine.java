package com.packetanalyzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.io.*;

/**
 * DPI Engine — the main orchestrator.
 *
 * Architecture (mirrors C++ DPIEngine):
 *
 *   PcapReader (reader thread)
 *       |
 *       ↓  hash to LB
 *   LoadBalancers (LB threads) ×2
 *       |
 *       ↓  hash to FP within LB
 *   FastPathProcessors (FP threads) ×4
 *       |
 *       ↓
 *   Output queue → output thread → forwarded PCAP
 *
 * Corresponds to C++ class DPIEngine in dpi_engine.h / dpi_engine.cpp
 */
public class DpiEngine {

    // ── Configuration ─────────────────────────────────────────────────────
    public static class Config {
        public int    numLoadBalancers = 2;
        public int    fpsPerLb        = 2;
        public int    queueSize       = 10_000;
        public String rulesFile       = "";
        public boolean verbose        = false;
    }

    // ── Statistics ────────────────────────────────────────────────────────
    public static class DpiStats {
        public final AtomicLong totalPackets     = new AtomicLong();
        public final AtomicLong totalBytes       = new AtomicLong();
        public final AtomicLong forwardedPackets = new AtomicLong();
        public final AtomicLong droppedPackets   = new AtomicLong();
        public final AtomicLong tcpPackets       = new AtomicLong();
        public final AtomicLong udpPackets       = new AtomicLong();
    }

    private final Config config;
    private final DpiStats stats = new DpiStats();

    // Shared components
    private RuleManager ruleManager;

    // Thread pools
    private final List<FastPathProcessor> fps  = new ArrayList<>();
    private final List<LoadBalancer>      lbs  = new ArrayList<>();

    // Output handling
    private final BlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(10_000);
    private Thread                         outputThread;
    private volatile RandomAccessFile      outputFile;
    private final Object                   outputLock = new Object();

    // Control
    private volatile boolean running           = false;
    private volatile boolean processingComplete = false;

    // Reader thread
    private Thread readerThread;

    public DpiEngine(Config config) {
        this.config = config;

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║ Configuration:                                                ║%n");
        System.out.printf( "║   Load Balancers:   %3d                                       ║%n", config.numLoadBalancers);
        System.out.printf( "║   FPs per LB:       %3d                                       ║%n", config.fpsPerLb);
        System.out.printf( "║   Total FP threads: %3d                                       ║%n", config.numLoadBalancers * config.fpsPerLb);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    public boolean initialize() {
        ruleManager = new RuleManager();

        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        // Output callback: called by each FP thread
        java.util.function.BiConsumer<PacketJob, FastPathProcessor.PacketAction> outputCb =
                (job, action) -> handleOutput(job, action);

        // Create FP threads
        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        for (int i = 0; i < totalFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCb));
        }

        // Create LB threads, each owning a slice of the FP queues
        for (int lb = 0; lb < config.numLoadBalancers; lb++) {
            List<BlockingQueue<PacketJob>> fpQueueSlice = new ArrayList<>();
            int fpStart = lb * config.fpsPerLb;
            for (int i = 0; i < config.fpsPerLb; i++) {
                fpQueueSlice.add(fps.get(fpStart + i).getInputQueue());
            }
            lbs.add(new LoadBalancer(lb, fpQueueSlice, fpStart));
        }

        System.out.println("[DpiEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running) return;
        running             = true;
        processingComplete  = false;

        // Start output thread
        outputThread = new Thread(this::outputThreadFunc, "Output-Writer");
        outputThread.setDaemon(true);
        outputThread.start();

        // Start FP threads
        fps.forEach(FastPathProcessor::start);

        // Start LB threads
        lbs.forEach(LoadBalancer::start);

        System.out.println("[DpiEngine] All threads started");
    }

    public void stop() {
        if (!running) return;
        running = false;

        lbs.forEach(LoadBalancer::stop);
        fps.forEach(FastPathProcessor::stop);

        if (outputThread != null) {
            outputThread.interrupt();
            try { outputThread.join(3000); } catch (InterruptedException ignored) {}
        }

        System.out.println("[DpiEngine] All threads stopped");
    }

    public void waitForCompletion() {
        if (readerThread != null) {
            try { readerThread.join(); } catch (InterruptedException ignored) {}
        }
        // Give queues time to drain
        try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        processingComplete = true;
    }

    // ── Process a PCAP file ───────────────────────────────────────────────

    /**
     * Main entry point: read input PCAP, inspect/filter, write output PCAP.
     * Corresponds to C++ DPIEngine::processFile()
     */
    public boolean processFile(String inputFile, String outputFilePath) {
        System.out.println("\n[DpiEngine] Processing: " + inputFile);
        System.out.println("[DpiEngine] Output to:  " + outputFilePath + "\n");

        if (ruleManager == null) {
            if (!initialize()) return false;
        }

        // Open output file
        try {
            outputFile = new RandomAccessFile(outputFilePath, "rw");
            outputFile.setLength(0); // truncate
        } catch (IOException e) {
            System.err.println("[DpiEngine] Error: Cannot open output file: " + e.getMessage());
            return false;
        }

        start();

        // Start reader thread
        readerThread = new Thread(() -> readerThreadFunc(inputFile), "PCAP-Reader");
        readerThread.start();

        waitForCompletion();

        // Extra drain time
        try { Thread.sleep(200); } catch (InterruptedException ignored) {}

        stop();

        if (outputFile != null) {
            try { outputFile.close(); } catch (IOException ignored) {}
        }

        // Print final reports
        System.out.println(generateReport());
        System.out.println(generateClassificationReport());

        return true;
    }

    // ── Reader thread ─────────────────────────────────────────────────────

    private void readerThreadFunc(String inputFilePath) {
        PcapReader reader = new PcapReader();
        try {
            reader.open(inputFilePath);
        } catch (IOException e) {
            System.err.println("[Reader] Error: " + e.getMessage());
            return;
        }

        // Write PCAP global header to output
        writeOutputHeader(reader);

        int packetId = 0;
        System.out.println("[Reader] Starting packet processing...");

        try {
            PcapReader.RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) continue;

                // Only process IP + TCP/UDP
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

                PacketJob job = createPacketJob(raw, parsed, packetId++);

                // Global stats
                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
                else               stats.udpPackets.incrementAndGet();

                // Route to the appropriate LB
                LoadBalancer lb = getLbForPacket(job.tuple);
                lb.getInputQueue().put(job);
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("[Reader] Error: " + e.getMessage());
        } finally {
            reader.close();
        }

        System.out.println("[Reader] Finished reading " + packetId + " packets");
    }

    /**
     * Build a PacketJob from raw + parsed data.
     * Corresponds to C++ DPIEngine::createPacketJob()
     */
    private PacketJob createPacketJob(PcapReader.RawPacket raw,
                                      ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec    = raw.header.tsSec;
        job.tsUsec   = raw.header.tsUsec;

        job.tuple = new FiveTuple(
                FiveTuple.parseIp(parsed.srcIp),
                FiveTuple.parseIp(parsed.destIp),
                parsed.srcPort,
                parsed.destPort,
                parsed.protocol);

        job.tcpFlags = parsed.tcpFlags;
        job.data     = raw.data;

        // Calculate offsets
        job.ethOffset = 0;
        job.ipOffset  = 14; // Ethernet header

        if (job.data.length > 14) {
            int ipIhl       = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;

            if (parsed.hasTcp && job.data.length > job.transportOffset) {
                int tcpDataOffset = (job.data[job.transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen  = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8; // UDP header = 8 bytes
            }

            if (job.payloadOffset < job.data.length) {
                job.payloadLength = job.data.length - job.payloadOffset;
            }
        }

        return job;
    }

    // ── Output thread ─────────────────────────────────────────────────────

    private void outputThreadFunc() {
        while (running || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) writeOutputPacket(job);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void handleOutput(PacketJob job, FastPathProcessor.PacketAction action) {
        if (action == FastPathProcessor.PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        try { outputQueue.put(job); } catch (InterruptedException ignored) {}
    }

    private void writeOutputHeader(PcapReader reader) {
        synchronized (outputLock) {
            if (outputFile == null) return;
            try {
                // Re-create the 24-byte global header
                byte[] hdr = new byte[24];
                writeUint32LE(hdr, 0,  0xa1b2c3d4L); // magic (native)
                writeUint16LE(hdr, 4,  reader.versionMajor);
                writeUint16LE(hdr, 6,  reader.versionMinor);
                writeUint32LE(hdr, 8,  0);   // thiszone
                writeUint32LE(hdr, 12, 0);   // sigfigs
                writeUint32LE(hdr, 16, reader.snaplen);
                writeUint32LE(hdr, 20, reader.network);
                outputFile.write(hdr);
            } catch (IOException e) {
                System.err.println("[DpiEngine] Error writing PCAP header: " + e.getMessage());
            }
        }
    }

    private void writeOutputPacket(PacketJob job) {
        synchronized (outputLock) {
            if (outputFile == null) return;
            try {
                byte[] hdr = new byte[16];
                writeUint32LE(hdr, 0, job.tsSec);
                writeUint32LE(hdr, 4, job.tsUsec);
                writeUint32LE(hdr, 8, job.data.length);
                writeUint32LE(hdr, 12, job.data.length);
                outputFile.write(hdr);
                outputFile.write(job.data);
            } catch (IOException e) {
                System.err.println("[DpiEngine] Error writing packet: " + e.getMessage());
            }
        }
    }

    // ── Load balancer routing ─────────────────────────────────────────────

    private LoadBalancer getLbForPacket(FiveTuple tuple) {
        int idx = Math.abs(tuple.hashCode()) % lbs.size();
        return lbs.get(idx);
    }

    // ── Rule management API ───────────────────────────────────────────────

    public void blockIp(String ip)              { if (ruleManager != null) ruleManager.blockIp(ip); }
    public void unblockIp(String ip)            { if (ruleManager != null) ruleManager.unblockIp(ip); }
    public void blockApp(AppType app)           { if (ruleManager != null) ruleManager.blockApp(app); }
    public void unblockApp(AppType app)         { if (ruleManager != null) ruleManager.unblockApp(app); }
    public void blockDomain(String domain)      { if (ruleManager != null) ruleManager.blockDomain(domain); }
    public void unblockDomain(String domain)    { if (ruleManager != null) ruleManager.unblockDomain(domain); }
    public boolean loadRules(String filename)   { return ruleManager != null && ruleManager.loadRules(filename); }
    public boolean saveRules(String filename)   { return ruleManager != null && ruleManager.saveRules(filename); }
    public RuleManager getRuleManager()         { return ruleManager; }
    public DpiStats getStats()                  { return stats; }

    // ── Reporting ─────────────────────────────────────────────────────────

    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append(  "║                    DPI ENGINE STATISTICS                      ║\n");
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(  "║ PACKET STATISTICS                                             ║\n");
        sb.append(String.format("║   Total Packets:      %12d                        ║%n", stats.totalPackets.get()));
        sb.append(String.format("║   Total Bytes:        %12d                        ║%n", stats.totalBytes.get()));
        sb.append(String.format("║   TCP Packets:        %12d                        ║%n", stats.tcpPackets.get()));
        sb.append(String.format("║   UDP Packets:        %12d                        ║%n", stats.udpPackets.get()));
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(  "║ FILTERING STATISTICS                                          ║\n");
        sb.append(String.format("║   Forwarded:          %12d                        ║%n", stats.forwardedPackets.get()));
        sb.append(String.format("║   Dropped/Blocked:    %12d                        ║%n", stats.droppedPackets.get()));

        if (stats.totalPackets.get() > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / stats.totalPackets.get();
            sb.append(String.format("║   Drop Rate:          %11.2f%%                        ║%n", dropRate));
        }

        // LB stats
        if (!lbs.isEmpty()) {
            long totalRcv = 0, totalDisp = 0;
            for (LoadBalancer lb : lbs) {
                LoadBalancer.LBStats s = lb.getStats();
                totalRcv  += s.packetsReceived;
                totalDisp += s.packetsDispatched;
            }
            sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
            sb.append(  "║ LOAD BALANCER STATISTICS                                      ║\n");
            sb.append(String.format("║   LB Received:        %12d                        ║%n", totalRcv));
            sb.append(String.format("║   LB Dispatched:      %12d                        ║%n", totalDisp));
        }

        // FP stats
        if (!fps.isEmpty()) {
            long proc = 0, fwd = 0, drop = 0, conns = 0;
            for (FastPathProcessor fp : fps) {
                FastPathProcessor.FPStats s = fp.getStats();
                proc  += s.packetsProcessed;
                fwd   += s.packetsForwarded;
                drop  += s.packetsDropped;
                conns += s.connectionsTracked;
            }
            sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
            sb.append(  "║ FAST PATH STATISTICS                                          ║\n");
            sb.append(String.format("║   FP Processed:       %12d                        ║%n", proc));
            sb.append(String.format("║   FP Forwarded:       %12d                        ║%n", fwd));
            sb.append(String.format("║   FP Dropped:         %12d                        ║%n", drop));
            sb.append(String.format("║   Active Connections: %12d                        ║%n", conns));
        }

        // Rule stats
        if (ruleManager != null) {
            RuleManager.RuleStats rs = ruleManager.getStats();
            sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
            sb.append(  "║ BLOCKING RULES                                                ║\n");
            sb.append(String.format("║   Blocked IPs:        %12d                        ║%n", rs.blockedIps));
            sb.append(String.format("║   Blocked Apps:       %12d                        ║%n", rs.blockedApps));
            sb.append(String.format("║   Blocked Domains:    %12d                        ║%n", rs.blockedDomains));
            sb.append(String.format("║   Blocked Ports:      %12d                        ║%n", rs.blockedPorts));
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    public String generateClassificationReport() {
        // Aggregate across all FP connection trackers
        Map<AppType, Long>  appCounts    = new HashMap<>();
        Map<String, Long>   domainCounts = new HashMap<>();
        long totalClassified = 0, totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(conn -> {
                appCounts.merge(conn.appType, 1L, Long::sum);
                if (conn.appType == AppType.UNKNOWN) ; // counted below via totalUnknown
                if (!conn.sni.isEmpty()) domainCounts.merge(conn.sni, 1L, Long::sum);
            });
        }

        for (Map.Entry<AppType, Long> e : appCounts.entrySet()) {
            if (e.getKey() == AppType.UNKNOWN) totalUnknown  += e.getValue();
            else                               totalClassified += e.getValue();
        }

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? 100.0 * totalClassified / total : 0;
        double unknownPct    = total > 0 ? 100.0 * totalUnknown    / total : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append(  "║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Total Connections:    %10d                             ║%n", total));
        sb.append(String.format("║ Classified:           %10d (%.1f%%)                  ║%n", totalClassified, classifiedPct));
        sb.append(String.format("║ Unidentified:         %10d (%.1f%%)                  ║%n", totalUnknown, unknownPct));
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(  "║                    APPLICATION DISTRIBUTION                   ║\n");
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");

        // Sort by count descending
        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appCounts.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> e : sorted) {
            double pct    = total > 0 ? 100.0 * e.getValue() / total : 0;
            int    barLen = (int)(pct / 5); // max 20 chars
            String bar    = "#".repeat(Math.max(0, barLen));
            sb.append(String.format("║ %-15s %8d %5.1f%% %-20s   ║%n",
                    e.getKey().toDisplayString(), e.getValue(), pct, bar));
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    // ── Byte helpers for writing PCAP (little-endian) ─────────────────────

    private static void writeUint32LE(byte[] buf, int off, long v) {
        buf[off]   = (byte)( v        & 0xFF);
        buf[off+1] = (byte)((v >>  8) & 0xFF);
        buf[off+2] = (byte)((v >> 16) & 0xFF);
        buf[off+3] = (byte)((v >> 24) & 0xFF);
    }

    private static void writeUint16LE(byte[] buf, int off, long v) {
        buf[off]   = (byte)( v       & 0xFF);
        buf[off+1] = (byte)((v >> 8) & 0xFF);
    }
}
