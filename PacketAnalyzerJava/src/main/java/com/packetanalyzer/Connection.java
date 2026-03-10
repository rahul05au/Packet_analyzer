package com.packetanalyzer;

import java.time.Instant;

/**
 * Connection entry — tracks per-flow state.
 * Corresponds to C++ struct Connection in types.h
 */
public class Connection {

    public enum State {
        NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED
    }

    public enum Action {
        FORWARD, DROP, INSPECT, LOG_ONLY
    }

    public FiveTuple tuple;
    public State     state   = State.NEW;
    public AppType   appType = AppType.UNKNOWN;
    public String    sni     = "";

    public long packetsIn  = 0;
    public long packetsOut = 0;
    public long bytesIn    = 0;
    public long bytesOut   = 0;

    public Instant firstSeen = Instant.now();
    public Instant lastSeen  = Instant.now();

    public Action action = Action.FORWARD;

    // TCP state tracking
    public boolean synSeen    = false;
    public boolean synAckSeen = false;
    public boolean finSeen    = false;

    public Connection(FiveTuple tuple) {
        this.tuple     = tuple;
        this.firstSeen = Instant.now();
        this.lastSeen  = this.firstSeen;
    }
}
