package com.packetanalyzer;

/**
 * Parsed packet — human-readable fields extracted from raw bytes.
 * Corresponds to C++ struct ParsedPacket in packet_parser.h
 */
public class ParsedPacket {

    // Timestamps
    public long timestampSec;
    public long timestampUsec;

    // Ethernet layer
    public String srcMac  = "";
    public String destMac = "";
    public int etherType  = 0;

    // IP layer
    public boolean hasIp    = false;
    public int     ipVersion;
    public String  srcIp    = "";
    public String  destIp   = "";
    public int     protocol;   // 6=TCP, 17=UDP, 1=ICMP
    public int     ttl;

    // Transport layer
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int     srcPort;
    public int     destPort;

    // TCP-specific
    public int  tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload
    public int    payloadLength;
    public byte[] payloadData;   // reference slice into packet data

    // ── EtherType constants ───────────────────────────────────────────────
    public static final int ETHER_TYPE_IPV4 = 0x0800;
    public static final int ETHER_TYPE_IPV6 = 0x86DD;
    public static final int ETHER_TYPE_ARP  = 0x0806;

    // ── Protocol constants ────────────────────────────────────────────────
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // ── TCP flag constants ────────────────────────────────────────────────
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;
}
