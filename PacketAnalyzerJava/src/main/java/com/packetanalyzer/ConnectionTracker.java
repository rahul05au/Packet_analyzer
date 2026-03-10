package com.packetanalyzer;

import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * Tracks all active connections for a single Fast Path thread.
 * Corresponds to C++ class ConnectionTracker in connection_tracker.h / .cpp
 *
 * Each FP thread owns its own ConnectionTracker — no shared state,
 * no synchronisation needed within the tracker itself.
 */
public class ConnectionTracker {

    /** Aggregated tracker statistics */
    public static class TrackerStats {
        public int activeConnections;
        public int totalConnectionsSeen;
        public int classifiedConnections;
        public int blockedConnections;
    }

    private final int    fpId;
    private final int    maxConnections;
    private final Map<FiveTuple, Connection> connections = new LinkedHashMap<>();

    private int totalSeen       = 0;
    private int classifiedCount = 0;
    private int blockedCount    = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId           = fpId;
        this.maxConnections = maxConnections;
    }

    /**
     * Get an existing connection or create a new one.
     * Corresponds to C++ getOrCreateConnection()
     */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection(tuple);
        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    /**
     * Get an existing connection (checks forward + reverse direction).
     * Returns null if not found.
     * Corresponds to C++ getConnection()
     */
    public Connection getConnection(FiveTuple tuple) {
        Connection c = connections.get(tuple);
        if (c != null) return c;
        return connections.get(tuple.reverse());
    }

    /**
     * Update connection statistics with a new packet.
     * Corresponds to C++ updateConnection()
     */
    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeen = Instant.now();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    /**
     * Mark a connection as classified (app type + SNI known).
     * Corresponds to C++ classifyConnection()
     */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.state != Connection.State.CLASSIFIED) {
            conn.appType = app;
            conn.sni     = sni != null ? sni : "";
            conn.state   = Connection.State.CLASSIFIED;
            classifiedCount++;
        }
    }

    /**
     * Mark a connection as blocked.
     * Corresponds to C++ blockConnection()
     */
    public void blockConnection(Connection conn) {
        if (conn == null) return;
        conn.state  = Connection.State.BLOCKED;
        conn.action = Connection.Action.DROP;
        blockedCount++;
    }

    /**
     * Mark a connection as closed.
     * Corresponds to C++ closeConnection()
     */
    public void closeConnection(FiveTuple tuple) {
        Connection c = connections.get(tuple);
        if (c != null) c.state = Connection.State.CLOSED;
    }

    /**
     * Remove connections that have been idle longer than timeoutSeconds,
     * or that are in CLOSED state.
     * Corresponds to C++ cleanupStale()
     */
    public int cleanupStale(long timeoutSeconds) {
        Instant cutoff = Instant.now().minusSeconds(timeoutSeconds);
        int removed = 0;

        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection c = it.next().getValue();
            if (c.state == Connection.State.CLOSED || c.lastSeen.isBefore(cutoff)) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        TrackerStats s = new TrackerStats();
        s.activeConnections     = connections.size();
        s.totalConnectionsSeen  = totalSeen;
        s.classifiedConnections = classifiedCount;
        s.blockedConnections    = blockedCount;
        return s;
    }

    public void clear() {
        connections.clear();
    }

    /**
     * Iterate over all connections.
     * Corresponds to C++ forEach()
     */
    public void forEach(Consumer<Connection> action) {
        connections.values().forEach(action);
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private void evictOldest() {
        if (connections.isEmpty()) return;
        FiveTuple oldest = null;
        Instant   oldestTime = Instant.MAX;

        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().lastSeen.isBefore(oldestTime)) {
                oldestTime = entry.getValue().lastSeen;
                oldest     = entry.getKey();
            }
        }

        if (oldest != null) connections.remove(oldest);
    }
}
