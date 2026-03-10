package com.packetanalyzer;

import java.util.Objects;

/**
 * Five-Tuple: uniquely identifies a network connection/flow.
 * Corresponds to C++ struct FiveTuple in types.h
 */
public class FiveTuple {
    public final long srcIp;   // 32-bit IP stored as long (unsigned)
    public final long dstIp;
    public final int  srcPort; // 16-bit port stored as int
    public final int  dstPort;
    public final int  protocol; // TCP=6, UDP=17

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /**
     * Create reverse tuple (for bidirectional flow matching).
     */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
               srcPort == t.srcPort && dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        // Mirrors the C++ FiveTupleHash logic
        long h = 0;
        h ^= Long.hashCode(srcIp)  + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Long.hashCode(dstIp)  + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(srcPort) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(dstPort) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(protocol) + 0x9e3779b9L + (h << 6) + (h >> 2);
        return (int)(h ^ (h >>> 32));
    }

    @Override
    public String toString() {
        String proto = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "?";
        return ipToString(srcIp) + ":" + srcPort +
               " -> " +
               ipToString(dstIp) + ":" + dstPort +
               " (" + proto + ")";
    }

    /** Convert a 32-bit IP (stored as long, network byte order) to dotted string. */
    public static String ipToString(long ip) {
        return ((ip) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    /** Parse "a.b.c.d" string to 32-bit IP stored in network byte order (as long). */
    public static long parseIp(String ip) {
        long result = 0;
        int octet = 0;
        int shift = 0;
        for (char c : ip.toCharArray()) {
            if (c == '.') {
                result |= ((long) octet & 0xFF) << shift;
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= ((long) octet & 0xFF) << shift;
        return result;
    }
}
