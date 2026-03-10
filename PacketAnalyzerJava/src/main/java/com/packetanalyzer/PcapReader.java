package com.packetanalyzer;

import java.io.*;

/**
 * Reads packets from a PCAP file.
 * Corresponds to C++ class PcapReader in pcap_reader.h / pcap_reader.cpp
 *
 * PCAP file format:
 *   Global header (24 bytes) followed by records:
 *     Per-packet header (16 bytes) + raw bytes
 */
public class PcapReader implements Closeable {

    // PCAP magic numbers
    private static final long PCAP_MAGIC_NATIVE  = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    /** Global header fields (read at open) */
    public int  versionMajor;
    public int  versionMinor;
    public long snaplen;
    public long network;    // 1 = Ethernet
    public long magicNumber;

    private DataInputStream in;
    private boolean needsByteSwap = false;

    /**
     * Parsed per-packet header.
     */
    public static class PcapPacketHeader {
        public long tsSec;
        public long tsUsec;
        public long inclLen;   // bytes saved in file
        public long origLen;   // original length
    }

    /**
     * A single captured packet.
     */
    public static class RawPacket {
        public PcapPacketHeader header = new PcapPacketHeader();
        public byte[] data;
    }

    /**
     * Open a .pcap file for reading.
     * @throws IOException if the file cannot be opened or has an invalid header
     */
    public void open(String filename) throws IOException {
        close(); // close any previously opened file

        InputStream fis = new FileInputStream(filename);
        in = new DataInputStream(new BufferedInputStream(fis));

        // Read global header (24 bytes)
        byte[] hdr = new byte[24];
        readFully(hdr);

        // Magic number (first 4 bytes, little-endian as written by most tools)
        long magic = readUint32LE(hdr, 0);
        this.magicNumber = magic;

        if (magic == PCAP_MAGIC_NATIVE) {
            needsByteSwap = false;
        } else if (magic == PCAP_MAGIC_SWAPPED) {
            needsByteSwap = true;
        } else {
            throw new IOException("Invalid PCAP magic number: 0x" + Long.toHexString(magic));
        }

        versionMajor = (int) maybeSwap16(readUint16LE(hdr, 4));
        versionMinor = (int) maybeSwap16(readUint16LE(hdr, 6));
        // thiszone, sigfigs skipped (indices 8–15)
        snaplen = maybeSwap32(readUint32LE(hdr, 16));
        network = maybeSwap32(readUint32LE(hdr, 20));

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + versionMajor + "." + versionMinor);
        System.out.println("  Snaplen: " + snaplen + " bytes");
        System.out.println("  Link type: " + network + (network == 1 ? " (Ethernet)" : ""));
    }

    /**
     * Read the next packet. Returns null at EOF.
     */
    public RawPacket readNextPacket() throws IOException {
        if (in == null) return null;

        // Read per-packet header (16 bytes)
        byte[] hdr = new byte[16];
        int r = readFullyOrEOF(hdr);
        if (r < 16) return null;  // EOF

        RawPacket pkt = new RawPacket();
        pkt.header.tsSec  = maybeSwap32(readUint32LE(hdr, 0));
        pkt.header.tsUsec = maybeSwap32(readUint32LE(hdr, 4));
        pkt.header.inclLen = maybeSwap32(readUint32LE(hdr, 8));
        pkt.header.origLen = maybeSwap32(readUint32LE(hdr, 12));

        // Sanity check
        if (pkt.header.inclLen > 65535) {
            throw new IOException("Invalid packet length: " + pkt.header.inclLen);
        }

        pkt.data = new byte[(int) pkt.header.inclLen];
        readFully(pkt.data);

        return pkt;
    }

    @Override
    public void close() {
        if (in != null) {
            try { in.close(); } catch (IOException ignored) {}
            in = null;
        }
    }

    public boolean isOpen() { return in != null; }
    public boolean needsByteSwap() { return needsByteSwap; }

    // ── Byte-order helpers ────────────────────────────────────────────────

    private long readUint32LE(byte[] buf, int offset) {
        return ((long)(buf[offset]   & 0xFF))       |
               ((long)(buf[offset+1] & 0xFF) << 8)  |
               ((long)(buf[offset+2] & 0xFF) << 16) |
               ((long)(buf[offset+3] & 0xFF) << 24);
    }

    private int readUint16LE(byte[] buf, int offset) {
        return ((buf[offset]   & 0xFF)) |
               ((buf[offset+1] & 0xFF) << 8);
    }

    private long maybeSwap32(long v) {
        if (!needsByteSwap) return v;
        return ((v & 0xFF000000L) >> 24) |
               ((v & 0x00FF0000L) >> 8)  |
               ((v & 0x0000FF00L) << 8)  |
               ((v & 0x000000FFL) << 24);
    }

    private int maybeSwap16(int v) {
        if (!needsByteSwap) return v;
        return ((v & 0xFF00) >> 8) | ((v & 0x00FF) << 8);
    }

    private void readFully(byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int r = in.read(buf, total, buf.length - total);
            if (r < 0) throw new EOFException("Unexpected EOF in PCAP");
            total += r;
        }
    }

    /** Like readFully but returns number of bytes actually read (may be < len at EOF). */
    private int readFullyOrEOF(byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int r = in.read(buf, total, buf.length - total);
            if (r < 0) break;
            total += r;
        }
        return total;
    }
}
