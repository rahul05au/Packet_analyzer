package com.packetanalyzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load Balancer — receives packets and distributes them to Fast Path threads
 * using consistent hashing (same flow → same FP).
 *
 * Corresponds to C++ class LoadBalancer in load_balancer.h / load_balancer.cpp
 */
public class LoadBalancer {

    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
        public long[] perFpPackets;
    }

    private final int     lbId;
    private final int     fpStartId;
    private final List<BlockingQueue<PacketJob>> fpQueues;

    private final BlockingQueue<PacketJob>   inputQueue = new LinkedBlockingQueue<>(10_000);
    private volatile boolean                 running    = false;
    private Thread                           thread;

    private final AtomicLong packetsReceived   = new AtomicLong();
    private final AtomicLong packetsDispatched = new AtomicLong();
    private final long[]     perFpCounts;

    public LoadBalancer(int lbId, List<BlockingQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId      = lbId;
        this.fpStartId = fpStartId;
        this.fpQueues  = fpQueues;
        this.perFpCounts = new long[fpQueues.size()];
    }

    public void start() {
        if (running) return;
        running = true;
        thread  = new Thread(this::run, "LB-" + lbId);
        thread.setDaemon(true);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId +
                           "-FP" + (fpStartId + fpQueues.size() - 1) + ")");
    }

    public void stop() {
        if (!running) return;
        running = false;
        if (thread != null) thread.interrupt();
        if (thread != null) {
            try { thread.join(2000); } catch (InterruptedException ignored) {}
        }
        System.out.println("[LB" + lbId + "] Stopped");
    }

    public BlockingQueue<PacketJob> getInputQueue() { return inputQueue; }

    public LBStats getStats() {
        LBStats s = new LBStats();
        s.packetsReceived   = packetsReceived.get();
        s.packetsDispatched = packetsDispatched.get();
        s.perFpPackets      = Arrays.copyOf(perFpCounts, perFpCounts.length);
        return s;
    }

    // ── Main loop ─────────────────────────────────────────────────────────

    private void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) continue;

                packetsReceived.incrementAndGet();

                int fpIndex = selectFp(job.tuple);
                fpQueues.get(fpIndex).put(job);

                packetsDispatched.incrementAndGet();
                perFpCounts[fpIndex]++;

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * Select a Fast Path thread for a packet using five-tuple hash.
     * Mirrors C++ LoadBalancer::selectFP()
     */
    private int selectFp(FiveTuple tuple) {
        int hash = tuple.hashCode();
        return Math.abs(hash) % fpQueues.size();
    }
}
