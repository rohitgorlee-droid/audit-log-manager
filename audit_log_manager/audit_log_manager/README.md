# Audit Log Manager (Java)

A simple, dependency-free audit log with a tamper-evident hash chain.

## Features
- Append-only log file, one record per line
- SHA-256 hash chain: editing any past record breaks verification
- Search by user, action, outcome and time range
- Summary counts and CSV export

## Build and run (Java 17+)
```
mkdir out
javac -d out $(find src -name "*.java")
java -cp out com.auditlog.Main
```

## Structure
- `Outcome` - SUCCESS / FAILURE / DENIED
- `AuditEvent` - immutable record with hash chaining and (de)serialization
- `AuditLogManager` - log, search, verify, summarize, export
- `Main` - demo including a tampering simulation
