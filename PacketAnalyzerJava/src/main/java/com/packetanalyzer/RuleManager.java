package com.packetanalyzer;

import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Manages IP, application, domain, and port blocking rules.
 * Thread-safe — multiple FP threads read concurrently; the engine writes.
 *
 * Corresponds to C++ class RuleManager in rule_manager.h / rule_manager.cpp
 */
public class RuleManager {

    /** Reason a packet/connection was blocked. */
    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        public final Type   type;
        public final String detail;

        public BlockReason(Type type, String detail) {
            this.type   = type;
            this.detail = detail;
        }
    }

    public static class RuleStats {
        public int blockedIps;
        public int blockedApps;
        public int blockedDomains;
        public int blockedPorts;
    }

    // ── Storage (protected by separate read-write locks) ──────────────────

    private final ReadWriteLock ipLock     = new ReentrantReadWriteLock();
    private final Set<Long>     blockedIps = new HashSet<>();

    private final ReadWriteLock  appLock     = new ReentrantReadWriteLock();
    private final Set<AppType>   blockedApps = new HashSet<>();

    private final ReadWriteLock  domainLock     = new ReentrantReadWriteLock();
    private final Set<String>    blockedDomains = new HashSet<>();
    private final List<String>   domainPatterns = new ArrayList<>(); // wildcard patterns

    private final ReadWriteLock  portLock     = new ReentrantReadWriteLock();
    private final Set<Integer>   blockedPorts = new HashSet<>(); // 0–65535

    // ── IP Blocking ───────────────────────────────────────────────────────

    public void blockIp(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.add(ip);
            System.out.println("[RuleManager] Blocked IP: " + FiveTuple.ipToString(ip));
        } finally { ipLock.writeLock().unlock(); }
    }

    public void blockIp(String ip) { blockIp(FiveTuple.parseIp(ip)); }

    public void unblockIp(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.remove(ip);
            System.out.println("[RuleManager] Unblocked IP: " + FiveTuple.ipToString(ip));
        } finally { ipLock.writeLock().unlock(); }
    }

    public void unblockIp(String ip) { unblockIp(FiveTuple.parseIp(ip)); }

    public boolean isIpBlocked(long ip) {
        ipLock.readLock().lock();
        try { return blockedIps.contains(ip); }
        finally { ipLock.readLock().unlock(); }
    }

    public List<String> getBlockedIps() {
        ipLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (long ip : blockedIps) result.add(FiveTuple.ipToString(ip));
            return result;
        } finally { ipLock.readLock().unlock(); }
    }

    // ── Application Blocking ──────────────────────────────────────────────

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
            System.out.println("[RuleManager] Blocked app: " + app.toDisplayString());
        } finally { appLock.writeLock().unlock(); }
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
            System.out.println("[RuleManager] Unblocked app: " + app.toDisplayString());
        } finally { appLock.writeLock().unlock(); }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try { return blockedApps.contains(app); }
        finally { appLock.readLock().unlock(); }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try { return new ArrayList<>(blockedApps); }
        finally { appLock.readLock().unlock(); }
    }

    // ── Domain Blocking ───────────────────────────────────────────────────

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
            System.out.println("[RuleManager] Blocked domain: " + domain);
        } finally { domainLock.writeLock().unlock(); }
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain);
            }
            System.out.println("[RuleManager] Unblocked domain: " + domain);
        } finally { domainLock.writeLock().unlock(); }
    }

    public boolean isDomainBlocked(String domain) {
        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(domain)) return true;
            String lower = domain.toLowerCase();
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lower, pattern.toLowerCase())) return true;
            }
            return false;
        } finally { domainLock.readLock().unlock(); }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally { domainLock.readLock().unlock(); }
    }

    // ── Port Blocking ─────────────────────────────────────────────────────

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port);
            System.out.println("[RuleManager] Blocked port: " + port);
        } finally { portLock.writeLock().unlock(); }
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try { blockedPorts.remove(port); }
        finally { portLock.writeLock().unlock(); }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try { return blockedPorts.contains(port); }
        finally { portLock.readLock().unlock(); }
    }

    // ── Combined check ────────────────────────────────────────────────────

    /**
     * Decide if a packet should be blocked.
     * Returns a BlockReason if blocked, null if allowed.
     * Corresponds to C++ RuleManager::shouldBlock()
     */
    public BlockReason shouldBlock(long srcIp, int dstPort, AppType app, String domain) {
        if (isIpBlocked(srcIp))
            return new BlockReason(BlockReason.Type.IP, FiveTuple.ipToString(srcIp));
        if (isPortBlocked(dstPort))
            return new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort));
        if (isAppBlocked(app))
            return new BlockReason(BlockReason.Type.APP, app.toDisplayString());
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain))
            return new BlockReason(BlockReason.Type.DOMAIN, domain);
        return null;
    }

    // ── Persistence ───────────────────────────────────────────────────────

    /** Save rules to a plain-text file. */
    public boolean saveRules(String filename) {
        try (java.io.PrintWriter pw = new java.io.PrintWriter(filename)) {
            pw.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIps()) pw.println(ip);
            pw.println();

            pw.println("[BLOCKED_APPS]");
            for (AppType app : getBlockedApps()) pw.println(app.toDisplayString());
            pw.println();

            pw.println("[BLOCKED_DOMAINS]");
            for (String d : getBlockedDomains()) pw.println(d);
            pw.println();

            pw.println("[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try {
                for (int port : blockedPorts) pw.println(port);
            } finally { portLock.readLock().unlock(); }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (Exception e) {
            System.err.println("[RuleManager] Failed to save rules: " + e.getMessage());
            return false;
        }
    }

    /** Load rules from a plain-text file. */
    public boolean loadRules(String filename) {
        try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(filename))) {
            String line;
            String section = "";
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) {
                    section = line;
                    continue;
                }
                switch (section) {
                    case "[BLOCKED_IPS]":    blockIp(line); break;
                    case "[BLOCKED_APPS]":
                        for (AppType app : AppType.values()) {
                            if (app.toDisplayString().equals(line)) { blockApp(app); break; }
                        }
                        break;
                    case "[BLOCKED_DOMAINS]": blockDomain(line); break;
                    case "[BLOCKED_PORTS]":   blockPort(Integer.parseInt(line)); break;
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (Exception e) {
            System.err.println("[RuleManager] Failed to load rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();     try { blockedIps.clear();     } finally { ipLock.writeLock().unlock();     }
        appLock.writeLock().lock();    try { blockedApps.clear();    } finally { appLock.writeLock().unlock();    }
        domainLock.writeLock().lock(); try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();   try { blockedPorts.clear();   } finally { portLock.writeLock().unlock();   }
        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        RuleStats s = new RuleStats();
        ipLock.readLock().lock();     try { s.blockedIps     = blockedIps.size();     } finally { ipLock.readLock().unlock();     }
        appLock.readLock().lock();    try { s.blockedApps    = blockedApps.size();    } finally { appLock.readLock().unlock();    }
        domainLock.readLock().lock(); try { s.blockedDomains = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }
        portLock.readLock().lock();   try { s.blockedPorts   = blockedPorts.size();   } finally { portLock.readLock().unlock();   }
        return s;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Returns true if domain matches a wildcard pattern like "*.example.com".
     * Corresponds to C++ domainMatchesPattern()
     */
    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.length() >= 2 && pattern.charAt(0) == '*' && pattern.charAt(1) == '.') {
            String suffix = pattern.substring(1); // ".example.com"
            if (domain.endsWith(suffix)) return true;
            if (domain.equals(pattern.substring(2))) return true; // bare domain
        }
        return false;
    }
}
