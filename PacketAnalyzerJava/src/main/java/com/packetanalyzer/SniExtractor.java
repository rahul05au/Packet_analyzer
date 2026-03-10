package com.packetanalyzer;

/**
 * Extracts the Server Name Indication (SNI) from TLS Client Hello messages,
 * HTTP Host headers, DNS queries, and QUIC Initial packets.
 *
 * Corresponds to C++ classes in sni_extractor.h / sni_extractor.cpp
 */
public class SniExtractor {

    // TLS constants
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI          = 0x0000;
    private static final int SNI_TYPE_HOSTNAME      = 0x00;

    // ── TLS SNI ───────────────────────────────────────────────────────────

    /**
     * Check if the payload looks like a TLS Client Hello.
     * Corresponds to C++ SNIExtractor::isTLSClientHello()
     */
    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (length < 9) return false;
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        int version = PacketParser.readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;

        int recordLen = PacketParser.readUint16BE(payload, 3);
        if (recordLen > length - 5) return false;

        return (payload[5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    /**
     * Extract SNI string from a TLS Client Hello payload.
     * Returns null if not found.
     * Corresponds to C++ SNIExtractor::extract()
     */
    public static String extractTlsSni(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) return null;

        int offset = 5; // skip TLS record header

        // Handshake header: type(1) + length(3)
        // readUint24BE(payload, offset+1) is the handshake body length — we skip it
        offset += 4;  // past handshake type + 3-byte length

        // Client version (2 bytes)
        offset += 2;

        // Random (32 bytes)
        offset += 32;

        // Session ID
        if (offset >= length) return null;
        int sessionIdLen = payload[offset] & 0xFF;
        offset += 1 + sessionIdLen;

        // Cipher suites
        if (offset + 2 > length) return null;
        int cipherSuitesLen = PacketParser.readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLen;

        // Compression methods
        if (offset >= length) return null;
        int compressionLen = payload[offset] & 0xFF;
        offset += 1 + compressionLen;

        // Extensions
        if (offset + 2 > length) return null;
        int extensionsLen  = PacketParser.readUint16BE(payload, offset);
        offset += 2;

        int extensionsEnd = Math.min(offset + extensionsLen, length);

        while (offset + 4 <= extensionsEnd) {
            int extType   = PacketParser.readUint16BE(payload, offset);
            int extLen    = PacketParser.readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extLen > extensionsEnd) break;

            if (extType == EXTENSION_SNI) {
                if (extLen < 5) break;
                // SNI list length (2) + type (1) + SNI length (2)
                int sniType   = payload[offset + 2] & 0xFF;
                int sniLen    = PacketParser.readUint16BE(payload, offset + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLen > extLen - 5) break;

                return new String(payload, offset + 5, sniLen);
            }

            offset += extLen;
        }

        return null;
    }

    // ── HTTP Host header ──────────────────────────────────────────────────

    /**
     * Check if the payload looks like an HTTP request.
     * Corresponds to C++ HTTPHostExtractor::isHTTPRequest()
     */
    public static boolean isHttpRequest(byte[] payload, int length) {
        if (length < 4) return false;
        String start = new String(payload, 0, 4);
        return start.equals("GET ") || start.equals("POST") ||
               start.equals("PUT ") || start.equals("HEAD") ||
               start.equals("DELE") || start.equals("PATC") ||
               start.equals("OPTI");
    }

    /**
     * Extract the HTTP Host header value.
     * Returns null if not found.
     * Corresponds to C++ HTTPHostExtractor::extract()
     */
    public static String extractHttpHost(byte[] payload, int length) {
        if (!isHttpRequest(payload, length)) return null;

        String text = new String(payload, 0, length);
        int idx = text.toLowerCase().indexOf("\nhost:");
        if (idx < 0) {
            idx = text.toLowerCase().indexOf("\r\nhost:");
        }
        if (idx < 0) {
            // Check line 0
            idx = text.toLowerCase().indexOf("host:");
            if (idx > 0) idx = -1; // only match from start of a line
        }
        if (idx < 0) return null;

        int colonAt = text.indexOf(':', idx) + 1;
        int end = text.indexOf('\n', colonAt);
        if (end < 0) end = length;

        String host = text.substring(colonAt, end).trim();
        // Remove any \r
        host = host.replace("\r", "").trim();

        // Strip port if present
        int port = host.indexOf(':');
        if (port >= 0) host = host.substring(0, port);

        return host.isEmpty() ? null : host;
    }

    // ── DNS query ─────────────────────────────────────────────────────────

    /**
     * Check if the payload is a DNS query.
     * Corresponds to C++ DNSExtractor::isDNSQuery()
     */
    public static boolean isDnsQuery(byte[] payload, int length) {
        if (length < 12) return false;
        // QR bit = 0 means query
        if ((payload[2] & 0x80) != 0) return false;
        int qdcount = PacketParser.readUint16BE(payload, 4);
        return qdcount > 0;
    }

    /**
     * Extract the queried domain from a DNS request.
     * Returns null if not parseable.
     * Corresponds to C++ DNSExtractor::extractQuery()
     */
    public static String extractDnsQuery(byte[] payload, int length) {
        if (!isDnsQuery(payload, length)) return null;

        int offset = 12;
        StringBuilder domain = new StringBuilder();

        while (offset < length) {
            int labelLen = payload[offset] & 0xFF;
            if (labelLen == 0) break;
            if (labelLen > 63) break;

            offset++;
            if (offset + labelLen > length) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, offset, labelLen));
            offset += labelLen;
        }

        return domain.length() == 0 ? null : domain.toString();
    }

    // ── QUIC (simplified) ─────────────────────────────────────────────────

    /**
     * Check if the payload looks like a QUIC Initial packet.
     * Corresponds to C++ QUICSNIExtractor::isQUICInitial()
     */
    public static boolean isQuicInitial(byte[] payload, int length) {
        if (length < 5) return false;
        return (payload[0] & 0x80) != 0; // long header form
    }

    /**
     * Attempt to extract SNI from a QUIC Initial packet by searching for
     * a TLS Client Hello buried inside CRYPTO frames.
     * Corresponds to C++ QUICSNIExtractor::extract()
     */
    public static String extractQuicSni(byte[] payload, int length) {
        if (!isQuicInitial(payload, length)) return null;

        for (int i = 0; i + 50 < length; i++) {
            if ((payload[i] & 0xFF) == HANDSHAKE_CLIENT_HELLO) {
                int start = Math.max(0, i - 5);
                byte[] sub = new byte[length - start];
                System.arraycopy(payload, start, sub, 0, sub.length);
                String sni = extractTlsSni(sub, sub.length);
                if (sni != null) return sni;
            }
        }
        return null;
    }
}
