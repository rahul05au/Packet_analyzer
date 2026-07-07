package com.packetanalyzer;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Main entry point — reads a PCAP file and prints all packet details.
 *
 * Corresponds to C++ main.cpp (simple packet display mode)
 *
 * Usage:
 *   java -cp . com.packetanalyzer.Main <pcap_file> [max_packets]
 *
 * For DPI engine mode (full pipeline with LB + FP threads): 
 *   java -cp . com.packetanalyzer.Main --dpi <input.pcap> <output.pcap> [rules_file]
 */
public class Main {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0 (Java)");
        System.out.println("====================================\n");

        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        // ── DPI Engine mode ───────────────────────────────────────────────
        if ("--dpi".equals(args[0])) {
            if (args.length < 3) {
                System.err.println("Usage: Main --dpi <input.pcap> <output.pcap> [rules_file]");
                System.exit(1);
            }
            runDpiMode(args);
            return;
        }

        // ── Simple display mode ───────────────────────────────────────────
        String filename   = args[0];
        int    maxPackets = (args.length >= 2) ? Integer.parseInt(args[1]) : -1;

        PcapReader reader = new PcapReader();
        try {
            reader.open(filename);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }

        System.out.println("\n--- Reading packets ---");

        int packetCount = 0;
        int parseErrors = 0;

        try {
            PcapReader.RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                packetCount++;
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed != null) {
                    printPacketSummary(parsed, packetCount);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                }

                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }
        } catch (Exception e) {
            System.err.println("Error reading packets: " + e.getMessage());
        } finally {
            reader.close();
        }

        System.out.println("\n====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets read:  " + packetCount);
        System.out.println("  Parse errors:        " + parseErrors);
        System.out.println("====================================");
    }

    // ── DPI Engine runner ─────────────────────────────────────────────────

    private static void runDpiMode(String[] args) {
        String inputFile  = args[1];
        String outputFile = args[2];
        String rulesFile  = (args.length >= 4) ? args[3] : "";

        DpiEngine.Config config = new DpiEngine.Config();
        config.numLoadBalancers = 2;
        config.fpsPerLb         = 2;
        config.rulesFile        = rulesFile;

        DpiEngine engine = new DpiEngine(config);
        engine.initialize();

        // Example rules — uncomment to test blocking:
        // engine.blockApp(AppType.YOUTUBE);
        // engine.blockDomain("*.facebook.com");
        // engine.blockIp("1.2.3.4");

        boolean ok = engine.processFile(inputFile, outputFile);
        System.exit(ok ? 0 : 1);
    }

    // ── Packet display ────────────────────────────────────────────────────

    private static void printPacketSummary(ParsedPacket pkt, int num) {
        Instant ts = Instant.ofEpochSecond(pkt.timestampSec,
                                           (int)(pkt.timestampUsec * 1000));
        System.out.println("\n========== Packet #" + num + " ==========");
        System.out.printf("Time: %s.%06d%n", TS_FMT.format(ts), pkt.timestampUsec);

        // ── Ethernet ──────────────────────────────────────────────────────
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        String etherLabel = "";
        if      (pkt.etherType == ParsedPacket.ETHER_TYPE_IPV4) etherLabel = " (IPv4)";
        else if (pkt.etherType == ParsedPacket.ETHER_TYPE_IPV6) etherLabel = " (IPv6)";
        else if (pkt.etherType == ParsedPacket.ETHER_TYPE_ARP)  etherLabel = " (ARP)";
        System.out.printf("  EtherType:       0x%04X%s%n", pkt.etherType, etherLabel);

        // ── IP ────────────────────────────────────────────────────────────
        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        // ── TCP ───────────────────────────────────────────────────────────
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        // ── UDP ───────────────────────────────────────────────────────────
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }

        // ── Payload ───────────────────────────────────────────────────────
        if (pkt.payloadLength > 0 && pkt.payloadData != null) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");

            int previewLen = Math.min(pkt.payloadLength, 32);
            StringBuilder hex = new StringBuilder("  Preview: ");
            for (int i = 0; i < previewLen; i++) {
                hex.append(String.format("%02x ", pkt.payloadData[i] & 0xFF));
            }
            if (pkt.payloadLength > 32) hex.append("...");
            System.out.println(hex);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  java Main <pcap_file> [max_packets]");
        System.out.println("  java Main --dpi <input.pcap> <output.pcap> [rules_file]");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  pcap_file   - Path to a .pcap file");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java Main capture.pcap");
        System.out.println("  java Main capture.pcap 10");
        System.out.println("  java Main --dpi capture.pcap output.pcap");
        System.out.println("  java Main --dpi capture.pcap output.pcap rules.txt");
    }
}
