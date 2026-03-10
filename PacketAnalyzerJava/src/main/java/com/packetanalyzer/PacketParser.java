package com.packetanalyzer;

/**
 * Parses raw packet bytes into human-readable fields.
 * Corresponds to C++ class PacketParser in packet_parser.h / packet_parser.cpp
 */
public class PacketParser {

    private static final int ETH_HEADER_LEN     = 14;
    private static final int MIN_IP_HEADER_LEN  = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN     = 8;

    /**
     * Parse a raw packet into a ParsedPacket.
     * Returns null if parsing fails.
     * Corresponds to C++ PacketParser::parse()
     */
    public static ParsedPacket parse(PcapReader.RawPacket raw) {
        ParsedPacket parsed = new ParsedPacket();
        parsed.timestampSec  = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        int len = data.length;
        int[] offset = {0};   // mutable offset passed by reference via int[]

        if (!parseEthernet(data, len, parsed, offset)) return null;

        if (parsed.etherType == ParsedPacket.ETHER_TYPE_IPV4) {
            if (!parseIPv4(data, len, parsed, offset)) return null;

            if (parsed.protocol == ParsedPacket.PROTO_TCP) {
                if (!parseTCP(data, len, parsed, offset)) return null;
            } else if (parsed.protocol == ParsedPacket.PROTO_UDP) {
                if (!parseUDP(data, len, parsed, offset)) return null;
            }
        }

        // Set payload
        if (offset[0] < len) {
            parsed.payloadLength = len - offset[0];
            parsed.payloadData   = new byte[parsed.payloadLength];
            System.arraycopy(data, offset[0], parsed.payloadData, 0, parsed.payloadLength);
        } else {
            parsed.payloadLength = 0;
            parsed.payloadData   = new byte[0];
        }

        return parsed;
    }

    // ── Private parsers ───────────────────────────────────────────────────

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket p, int[] offset) {
        if (len < ETH_HEADER_LEN) return false;

        p.destMac   = macToString(data, 0);
        p.srcMac    = macToString(data, 6);
        p.etherType = readUint16BE(data, 12);

        offset[0] = ETH_HEADER_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket p, int[] offset) {
        int start = offset[0];
        if (len < start + MIN_IP_HEADER_LEN) return false;

        int versionIhl = data[start] & 0xFF;
        p.ipVersion    = (versionIhl >> 4) & 0x0F;
        int ihl        = versionIhl & 0x0F;

        if (p.ipVersion != 4) return false;

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < start + ipHeaderLen) return false;

        p.ttl      = data[start + 8] & 0xFF;
        p.protocol = data[start + 9] & 0xFF;
        p.srcIp    = ipToString(data, start + 12);
        p.destIp   = ipToString(data, start + 16);
        p.hasIp    = true;

        offset[0] = start + ipHeaderLen;
        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket p, int[] offset) {
        int start = offset[0];
        if (len < start + MIN_TCP_HEADER_LEN) return false;

        p.srcPort   = readUint16BE(data, start);
        p.destPort  = readUint16BE(data, start + 2);
        p.seqNumber = readUint32BE(data, start + 4);
        p.ackNumber = readUint32BE(data, start + 8);

        int dataOffset = (data[start + 12] >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;
        p.tcpFlags = data[start + 13] & 0xFF;

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < start + tcpHeaderLen) return false;

        p.hasTcp   = true;
        offset[0]  = start + tcpHeaderLen;
        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket p, int[] offset) {
        int start = offset[0];
        if (len < start + UDP_HEADER_LEN) return false;

        p.srcPort  = readUint16BE(data, start);
        p.destPort = readUint16BE(data, start + 2);
        p.hasUdp   = true;

        offset[0] = start + UDP_HEADER_LEN;
        return true;
    }

    // ── String helper methods (static, public - used by Main) ─────────────

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int offset) {
        return (data[offset]   & 0xFF) + "." +
               (data[offset+1] & 0xFF) + "." +
               (data[offset+2] & 0xFF) + "." +
               (data[offset+3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case ParsedPacket.PROTO_ICMP: return "ICMP";
            case ParsedPacket.PROTO_TCP:  return "TCP";
            case ParsedPacket.PROTO_UDP:  return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & ParsedPacket.TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & ParsedPacket.TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & ParsedPacket.TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & ParsedPacket.TCP_RST) != 0) sb.append("RST ");
        if ((flags & ParsedPacket.TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & ParsedPacket.TCP_URG) != 0) sb.append("URG ");
        String result = sb.toString().trim();
        return result.isEmpty() ? "none" : result;
    }

    // ── Byte-reading utilities ────────────────────────────────────────────

    static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    static long readUint32BE(byte[] data, int offset) {
        return ((long)(data[offset]   & 0xFF) << 24) |
               ((long)(data[offset+1] & 0xFF) << 16) |
               ((long)(data[offset+2] & 0xFF) << 8)  |
               ((long)(data[offset+3] & 0xFF));
    }

    static int readUint24BE(byte[] data, int offset) {
        return ((data[offset]   & 0xFF) << 16) |
               ((data[offset+1] & 0xFF) << 8)  |
               ((data[offset+2] & 0xFF));
    }
}
