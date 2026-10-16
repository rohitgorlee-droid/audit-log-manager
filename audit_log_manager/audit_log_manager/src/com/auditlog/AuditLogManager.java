package com.auditlog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Append-only audit log manager.
 *
 * Features:
 *  - log events to a file (one line per event) and keep them in memory
 *  - tamper-evident hash chain, verified with {@link #verifyIntegrity()}
 *  - search by user / action / outcome / time range
 *  - summary statistics and CSV export
 */
public class AuditLogManager {

    /** Result of an integrity check. */
    public record VerificationResult(boolean valid, long firstInvalidId, String reason) {
        public static VerificationResult ok() {
            return new VerificationResult(true, -1, "All records verified");
        }

        public static VerificationResult broken(long id, String reason) {
            return new VerificationResult(false, id, reason);
        }
    }

    private final Path logFile;
    private final List<AuditEvent> events = new ArrayList<>();

    /** Opens the log, loading existing records if the file already exists. */
    public AuditLogManager(Path logFile) throws IOException {
        this.logFile = Objects.requireNonNull(logFile, "logFile");
        if (Files.exists(logFile)) {
            for (String line : Files.readAllLines(logFile, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    events.add(AuditEvent.deserialize(line));
                }
            }
        }
    }

    /** Records a new event, chained to the previous one, and appends it to the log file. */
    public synchronized AuditEvent log(String user, String action, String resource,
                                       Outcome outcome, String details) throws IOException {
        requireText(user, "user");
        requireText(action, "action");
        requireText(resource, "resource");
        Objects.requireNonNull(outcome, "outcome");

        String previousHash = events.isEmpty()
                ? AuditEvent.GENESIS_HASH
                : events.get(events.size() - 1).getHash();

        AuditEvent event = AuditEvent.create(
                events.size() + 1L, Instant.now(), user, action, resource,
                outcome, details == null ? "" : details, previousHash);

        Files.writeString(logFile, event.serialize() + System.lineSeparator(),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        events.add(event);
        return event;
    }

    public synchronized List<AuditEvent> getAll() {
        return Collections.unmodifiableList(new ArrayList<>(events));
    }

    /** Filters events. Any argument may be null to skip that filter. */
    public synchronized List<AuditEvent> search(String user, String action, Outcome outcome,
                                                Instant from, Instant to) {
        return events.stream()
                .filter(e -> user == null || e.getUser().equalsIgnoreCase(user))
                .filter(e -> action == null || e.getAction().equalsIgnoreCase(action))
                .filter(e -> outcome == null || e.getOutcome() == outcome)
                .filter(e -> from == null || !e.getTimestamp().isBefore(from))
                .filter(e -> to == null || !e.getTimestamp().isAfter(to))
                .toList();
    }

    /** Checks every record's hash and its link to the previous record. */
    public synchronized VerificationResult verifyIntegrity() {
        String expectedPrevious = AuditEvent.GENESIS_HASH;
        long expectedId = 1;

        for (AuditEvent e : events) {
            if (e.getId() != expectedId) {
                return VerificationResult.broken(e.getId(), "Unexpected record id (missing or reordered record)");
            }
            if (!e.getPreviousHash().equals(expectedPrevious)) {
                return VerificationResult.broken(e.getId(), "Chain link does not match previous record");
            }
            if (!e.isHashValid()) {
                return VerificationResult.broken(e.getId(), "Record contents do not match stored hash");
            }
            expectedPrevious = e.getHash();
            expectedId++;
        }
        return VerificationResult.ok();
    }

    /** Number of events per outcome. */
    public synchronized Map<Outcome, Long> countByOutcome() {
        Map<Outcome, Long> counts = new EnumMap<>(Outcome.class);
        for (Outcome o : Outcome.values()) {
            counts.put(o, 0L);
        }
        events.forEach(e -> counts.merge(e.getOutcome(), 1L, Long::sum));
        return counts;
    }

    /** Number of events per user, sorted by user name. */
    public synchronized Map<String, Long> countByUser() {
        Map<String, Long> counts = new TreeMap<>();
        events.forEach(e -> counts.merge(e.getUser(), 1L, Long::sum));
        return counts;
    }

    /** Exports all events to a CSV file. */
    public synchronized void exportCsv(Path target) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("id,timestamp,user,action,resource,outcome,details,hash");
        for (AuditEvent e : events) {
            lines.add(String.join(",",
                    Long.toString(e.getId()), e.getTimestamp().toString(),
                    csv(e.getUser()), csv(e.getAction()), csv(e.getResource()),
                    e.getOutcome().name(), csv(e.getDetails()), e.getHash()));
        }
        Files.write(target, lines, StandardCharsets.UTF_8);
    }

    private static String csv(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
