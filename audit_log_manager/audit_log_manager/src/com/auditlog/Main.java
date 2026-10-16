package com.auditlog;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Demo: log events, query them, verify integrity, then simulate tampering. */
public class Main {

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("audit-demo");
        Path logFile = dir.resolve("audit.log");
        System.out.println("Log file: " + logFile);

        AuditLogManager manager = new AuditLogManager(logFile);

        // 1. Log some events
        manager.log("alice", "LOGIN", "auth-service", Outcome.SUCCESS, "Login from 10.0.0.5");
        manager.log("bob", "DELETE_USER", "user-db", Outcome.DENIED, "Insufficient privileges");
        manager.log("alice", "UPDATE_CONFIG", "billing-service", Outcome.SUCCESS, "Changed retry limit to 5");
        manager.log("carol", "LOGIN", "auth-service", Outcome.FAILURE, "Invalid password");
        manager.log("bob", "EXPORT_REPORT", "reports", Outcome.SUCCESS, "Quarterly audit report");

        printSection("All events");
        manager.getAll().forEach(System.out::println);

        // 2. Search
        printSection("Search: user = bob");
        manager.search("bob", null, null, null, null).forEach(System.out::println);

        printSection("Search: outcome = DENIED or FAILURE");
        manager.search(null, null, Outcome.DENIED, null, null).forEach(System.out::println);
        manager.search(null, null, Outcome.FAILURE, null, null).forEach(System.out::println);

        // 3. Summary
        printSection("Summary");
        System.out.println("By outcome: " + manager.countByOutcome());
        System.out.println("By user:    " + manager.countByUser());

        // 4. Verify integrity
        printSection("Integrity check (untouched log)");
        System.out.println(manager.verifyIntegrity());

        // 5. Export
        Path csv = dir.resolve("audit_export.csv");
        manager.exportCsv(csv);
        System.out.println("\nCSV exported to: " + csv);

        // 6. Simulate tampering: change bob's DENIED event to SUCCESS directly in the file
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        lines.set(1, lines.get(1).replace("|DENIED|", "|SUCCESS|"));
        Files.write(logFile, lines, StandardCharsets.UTF_8);

        printSection("Integrity check (after tampering with record #2)");
        AuditLogManager reloaded = new AuditLogManager(logFile);
        System.out.println(reloaded.verifyIntegrity());
    }

    private static void printSection(String title) {
        System.out.println("\n=== " + title + " ===");
    }
}
