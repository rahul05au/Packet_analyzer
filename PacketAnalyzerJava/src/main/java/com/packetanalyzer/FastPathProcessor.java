package com.packetanalyzer;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Fast Path Processor — a single worker thread that performs
 * connection tracking, DPI (SNI extraction), rule checking, and forwarding.
 *
 * Corresponds to C++ class FastPathProcessor in fast_path.h / fast_path.cpp
 */
public class FastPathProcessor {

    /** Action to take for a packet. */
    public enum PacketAction {
        FORWARD, DROP, INSPECT, LOG_ONLY
    }

    /** Statistics for this FP. */
    public static class FPStats {
        public long packetsProcessed;
        public long packetsForwarded;
        public long packetsDropped;
        public long connectionsTracked;
        public long sniExtractions;
        public long classificationHits;
    }

    private final int fpId;
    private final BlockingQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    private volatile boolean running = false;
    private Thread thread;

    // ── Statistics ────────────────────────────────────────────────────────
    private final AtomicLong packetsProcessed = new AtomicLong();
    private final AtomicLong packetsForwarded = new AtomicLong();
    private final AtomicLong packetsDropped = new AtomicLong();
    private final AtomicLong sniExtractions = new AtomicLong();
    private final AtomicLong classificationHits = new AtomicLong();

    public FastPathProcessor(int fpId, RuleManager ruleManager,
            BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId = fpId;
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
        this.connTracker = new ConnectionTracker(fpId);
        this.inputQueue = new LinkedBlockingQueue<>(10_000);
    }

    public void start() {
        if (running)
            return;
        running = true;
        thread = new Thread(this::run, "FP-" + fpId);
        thread.setDaemon(true);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running)
            return;
        running = false;
        if (thread != null)
            thread.interrupt();
        if (thread != null) {
            try {
                thread.join(2000);
            } catch (InterruptedException ignored) {
            }
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    /** Returns the input queue so LBs can push packets. */
    public BlockingQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    /** Returns the connection tracker (for reporting). */
    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public FPStats getStats() {
        FPStats s = new FPStats();
        s.packetsProcessed = packetsProcessed.get();
        s.packetsForwarded = packetsForwarded.get();
        s.packetsDropped = packetsDropped.get();
        s.connectionsTracked = connTracker.getActiveCount();
        s.sniExtractions = sniExtractions.get();
        s.classificationHits = classificationHits.get();
        return s;
    }

    public int getId() {
        return fpId;
    }

    // ── Main loop ─────────────────────────────────────────────────────────

    private void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) {
                    // Periodic stale connection cleanup (every 300 s)
                    connTracker.cleanupStale(300);
                    continue;
                }

                packetsProcessed.incrementAndGet();
                PacketAction action = processPacket(job);

                if (outputCallback != null)
                    outputCallback.accept(job, action);

                if (action == PacketAction.DROP)
                    packetsDropped.incrementAndGet();
                else
                    packetsForwarded.incrementAndGet();

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    // ── Packet processing ─────────────────────────────────────────────────

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);

        // Update stats
        connTracker.updateConnection(conn, job.data.length, true);

        // TCP state machine
        if (job.tuple.protocol == 6) {
            updateTcpState(conn, job.tcpFlags);
        }

        // Already blocked → drop immediately
        if (conn.state == Connection.State.BLOCKED)
            return PacketAction.DROP;

        // Deep inspection (classify if not yet classified)
        if (conn.state != Connection.State.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    /**
     * Inspect packet payload for SNI/HTTP/DNS classification.
     * Corresponds to C++ inspectPayload()
     */
    private void inspectPayload(PacketJob job, Connection conn) {
        byte[] payload = job.getPayload();
        if (payload.length == 0)
            return;

        // 1. TLS SNI
        if (tryExtractSni(job, conn, payload))
            return;

        // 2. HTTP Host header
        if (tryExtractHttpHost(job, conn, payload))
            return;

        // 3. DNS (port 53)
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            String domain = SniExtractor.extractDnsQuery(payload, payload.length);
            if (domain != null) {
                connTracker.classifyConnection(conn, AppType.DNS, domain);
                return;
            }
        }

        // 4. Port-based fallback
        if (job.tuple.dstPort == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.dstPort == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSni(PacketJob job, Connection conn, byte[] payload) {
        if (job.tuple.dstPort != 443 && payload.length < 50)
            return false;

        String sni = SniExtractor.extractTlsSni(payload, payload.length);
        if (sni == null)
            return false;

        sniExtractions.incrementAndGet();
        AppType app = AppType.fromSni(sni);
        connTracker.classifyConnection(conn, app, sni);

        if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
            classificationHits.incrementAndGet();
        }
        return true;
    }

    private boolean tryExtractHttpHost(PacketJob job, Connection conn, byte[] payload) {
        if (job.tuple.dstPort != 80)
            return false;

        String host = SniExtractor.extractHttpHost(payload, payload.length);
        if (host == null)
            return false;

        AppType app = AppType.fromSni(host);
        connTracker.classifyConnection(conn, app, host);

        if (app != AppType.UNKNOWN && app != AppType.HTTP) {
            classificationHits.incrementAndGet();
        }
        return true;
    }

    /**
     * Check blocking rules for a packet/connection.
     * Corresponds to C++ checkRules()
     */
    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) {
            emitPacketJson(job, conn, "FORWARD", "");
            return PacketAction.FORWARD;
        }

        RuleManager.BlockReason reason = ruleManager.shouldBlock(
                job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni);

        if (reason != null) {
            String detail;
            switch (reason.type) {
                case IP:
                    detail = "IP " + reason.detail;
                    break;
                case APP:
                    detail = "App " + reason.detail;
                    break;
                case DOMAIN:
                    detail = "Domain " + reason.detail;
                    break;
                case PORT:
                    detail = "Port " + reason.detail;
                    break;
                default:
                    detail = reason.detail;
            }
            System.out.println("[FP" + fpId + "] BLOCKED packet: " + detail);
            emitPacketJson(job, conn, "BLOCKED", detail);
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        emitPacketJson(job, conn, "FORWARD", "");
        return PacketAction.FORWARD;
    }

    /**
     * Emit a single-line JSON record for this packet — parsed by the Web UI live
     * table.
     */
    private static void emitPacketJson(PacketJob job, Connection conn, String action, String reason) {
        String proto = job.tuple.protocol == 6 ? "TCP" : "UDP";
        // Use FiveTuple.ipToString() — IPs are stored in little-endian network byte
        // order
        String srcIp = FiveTuple.ipToString(job.tuple.srcIp);
        String dstIp = FiveTuple.ipToString(job.tuple.dstIp);
        String sni = conn.sni.isEmpty() ? "-" : conn.sni.replace("\"", "'");
        String app = conn.appType != null ? conn.appType.toDisplayString().replace("\"", "'") : "Unknown";
        String rsn = reason.replace("\"", "'");
        int dstPort = job.tuple.dstPort;
        System.out.println("PKT_JSON:{\"src\":\"" + srcIp + "\",\"dst\":\"" + dstIp +
                "\",\"proto\":\"" + proto + "\",\"port\":" + dstPort +
                ",\"sni\":\"" + sni + "\",\"app\":\"" + app +
                "\",\"action\":\"" + action + "\",\"reason\":\"" + rsn + "\"}");
    }

    /**
     * Update TCP connection state machine.
     * Corresponds to C++ updateTCPState()
     */
    private void updateTcpState(Connection conn, int flags) {
        final int SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04;

        if ((flags & SYN) != 0) {
            if ((flags & ACK) != 0)
                conn.synAckSeen = true;
            else
                conn.synSeen = true;
        }

        if (conn.synSeen && conn.synAckSeen && (flags & ACK) != 0) {
            if (conn.state == Connection.State.NEW) {
                conn.state = Connection.State.ESTABLISHED;
            }
        }

        if ((flags & FIN) != 0)
            conn.finSeen = true;
        if ((flags & RST) != 0)
            conn.state = Connection.State.CLOSED;
        if (conn.finSeen && (flags & ACK) != 0)
            conn.state = Connection.State.CLOSED;
    }
}
