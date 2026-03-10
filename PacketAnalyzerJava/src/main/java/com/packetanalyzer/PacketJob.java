package com.packetanalyzer;

/**
 * Packet job — wrapper passed between threads (Reader → LB → FP).
 * Corresponds to C++ struct PacketJob in types.h
 */
public class PacketJob {
    public int    packetId;
    public FiveTuple tuple;
    public byte[] data;

    public int  ethOffset       = 0;
    public int  ipOffset        = 0;
    public int  transportOffset = 0;
    public int  payloadOffset   = 0;
    public int  payloadLength   = 0;
    public int  tcpFlags        = 0;

    public long tsSec;
    public long tsUsec;

    public PacketJob() {}

    /** Get payload bytes as a sub-array view. Returns empty array if none. */
    public byte[] getPayload() {
        if (data == null || payloadOffset >= data.length || payloadLength == 0)
            return new byte[0];
        int len = Math.min(payloadLength, data.length - payloadOffset);
        byte[] payload = new byte[len];
        System.arraycopy(data, payloadOffset, payload, 0, len);
        return payload;
    }
}
