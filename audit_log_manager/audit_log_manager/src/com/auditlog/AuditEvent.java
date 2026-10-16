package com.auditlog;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;

/**
 * A single immutable audit record.
 *
 * Each event stores the hash of the previous event, forming a hash chain.
 * If any past record is modified, its hash (and every link after it) stops matching.
 */
public final class AuditEvent {

    public static final String GENESIS_HASH = "0".repeat(64);
    private static final String SEPARATOR = "|";

    private final long id;
    private final Instant timestamp;
    private final String user;
    private final String action;
    private final String resource;
    private final Outcome outcome;
    private final String details;
    private final String previousHash;
    private final String hash;

    private AuditEvent(long id, Instant timestamp, String user, String action, String resource,
                       Outcome outcome, String details, String previousHash, String hash) {
        this.id = id;
        this.timestamp = timestamp;
        this.user = user;
        this.action = action;
        this.resource = resource;
        this.outcome = outcome;
        this.details = details;
        this.previousHash = previousHash;
        this.hash = hash;
    }

    /** Creates a new event and computes its hash. */
    public static AuditEvent create(long id, Instant timestamp, String user, String action,
                                    String resource, Outcome outcome, String details,
                                    String previousHash) {
        String hash = computeHash(id, timestamp, user, action, resource, outcome, details, previousHash);
        return new AuditEvent(id, timestamp, user, action, resource, outcome, details, previousHash, hash);
    }

    /** Rebuilds an event from a stored line WITHOUT recomputing the hash, so tampering stays detectable. */
    public static AuditEvent deserialize(String line) {
        String[] p = line.split("\\|", -1);
        if (p.length != 9) {
            throw new IllegalArgumentException("Corrupt audit record: " + line);
        }
        return new AuditEvent(
                Long.parseLong(p[0]),
                Instant.parse(p[1]),
                decode(p[2]), decode(p[3]), decode(p[4]),
                Outcome.valueOf(p[5]),
                decode(p[6]),
                p[7], p[8]);
    }

    /** One-line, pipe-separated storage format (free-text fields are URL-encoded). */
    public String serialize() {
        return String.join(SEPARATOR,
                Long.toString(id), timestamp.toString(),
                encode(user), encode(action), encode(resource),
                outcome.name(), encode(details), previousHash, hash);
    }

    /** True if the stored hash matches the event's current contents. */
    public boolean isHashValid() {
        return hash.equals(computeHash(id, timestamp, user, action, resource, outcome, details, previousHash));
    }

    private static String computeHash(long id, Instant timestamp, String user, String action,
                                      String resource, Outcome outcome, String details,
                                      String previousHash) {
        String payload = String.join(SEPARATOR,
                Long.toString(id), timestamp.toString(), user, action, resource,
                outcome.name(), details, previousHash);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    public long getId() { return id; }
    public Instant getTimestamp() { return timestamp; }
    public String getUser() { return user; }
    public String getAction() { return action; }
    public String getResource() { return resource; }
    public Outcome getOutcome() { return outcome; }
    public String getDetails() { return details; }
    public String getPreviousHash() { return previousHash; }
    public String getHash() { return hash; }

    @Override
    public String toString() {
        return String.format("#%d %s %-6s %-14s %-16s [%s] %s",
                id, timestamp, user, action, resource, outcome, details);
    }
}
