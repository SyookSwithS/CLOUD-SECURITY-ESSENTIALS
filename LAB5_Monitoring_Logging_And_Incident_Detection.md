# Lab 5: Monitoring, Logging & Incident Detection

**Course:** IKB42603 Cloud Computing Security Essentials
**Lab:** Lab 5
**Topic:** Centralised logging, tamper-proof logs, threat detection and incident response using Docker and LocalStack
**Environment:** Docker container `localstack` (LocalStack, CloudWatch Logs emulation), AWS CLI v2
**Name:** Muhamad Syukri Bin Hasbullah

## Lab Summary

This lab demonstrates the "visibility to response" half of cloud security. Session A (Week 9) covers generating application logs, shipping them to a centralised log store (CloudWatch Logs via LocalStack), and querying them for security-relevant activity. Session B (Week 10) covers making logs tamper-evident with a SHA-256 hash chain, detecting an incident by correlating multiple log types, and executing the incident-response lifecycle (contain, collect, document).

Two real-world issues surfaced during the lab and are documented below as troubleshooting notes: LocalStack's `:latest` image now requires a paid auth token as of March 2026, and the field-extraction command in Task 3 had an off-by-one `awk` field index. Both were resolved and re-verified before proceeding.

## Evidence Folder

All screenshots used for this report are stored in the `Evidence` folder.

| Evidence File | Purpose |
|---|---|
| `0.1-LocalStack-AuthToken-Error.png` | LocalStack `:latest` failing with license activation error |
| `0.2-LocalStack-Started.png` | LocalStack `4.4.0` started and log group/stream created |
| `1.1-Auth-Log-Created.png` | `auth.log` created with simulated attack pattern |
| `2.1-CloudWatch-Readback.png` | Centralised log read-back via `get-log-events` |
| `3.1-Query-Bug-Fix.png` | Troubleshooting: `awk` field index fix and corrected query result |
| `4.1-Hash-Chain.png` | Hash-chained log (`auth.chain`) generated |
| `4.2-Tampered-Log.png` | Tampered copy (`auth.tampered`) with EXPORT size changed |
| `4.3-Tamper-Detected.png` | Recomputed chain and final-hash comparison showing mismatch |
| `5.1-Correlation-Alert.png` | Correlation detection: `ALERT: probable brute-force -> compromise -> data exfiltration` |
| `6.1-Containment.png` | iptables rule blocking attacker IP |
| `6.2-Evidence-Collected.png` | Evidence copy and SHA-256 hash generated |
| `7.1-Verify-LogGroups.png` | `describe-log-groups` verification output |
| `7.2-Verify-Evidence-Hash.png` | `sha256sum -c evidence.sha256` → OK |

---

## Setup — Start LocalStack

```bash
EP='--endpoint-url=http://localhost:4566'
docker run -d --name localstack -p 4566:4566 localstack/localstack
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

#### Troubleshooting Note

The `localstack/localstack:latest` container exited immediately with code 55: `License activation failed! No credentials were found in the environment.` As of **23 March 2026**, LocalStack merged its Community and Pro images into a single `latest` tag that requires a `LOCALSTACK_AUTH_TOKEN`, even for previously-free Community features — a change made after this lab guide was written.

**Fix applied:** pinned the image to the last free Community release before the merge:

```bash
docker rm -f localstack
docker run -d --name localstack -p 4566:4566 localstack/localstack:4.4.0
sleep 15
docker ps | grep localstack
curl -s http://localhost:4566/_localstack/health
```

Once the container reported `healthy`, the log group and stream were created successfully.

Result:

LocalStack (pinned to `4.4.0`) started successfully, and the `/ccse/app` log group with an `auth` log stream was created, ready to receive log events.

Evidence:

<img width="809" height="100" alt="Image" src="https://github.com/user-attachments/assets/29f8ec23-f4fa-45b7-a95b-23c2bf02dd14" />


---

## Session A (Week 9) — Logging & Centralisation

### Task 1: Generate Application Logs

```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF
cat auth.log
```

Result:

A simulated authentication log was created containing one legitimate login (`ahmad`) and an attack pattern from IP `203.0.113.9`: four consecutive failed logins for `admin`, followed by one successful login, followed by a 500MB data export. This is the raw evidence that Task 5 later correlates into an incident.

Evidence:

<img width="801" height="398" alt="Image" src="https://github.com/user-attachments/assets/10de4001-46eb-4fc4-a5a7-c453633dfa0c" />

---

### Task 2: Centralise Logs (Ship to CloudWatch)

```bash
TS=$(date +%s000)
while IFS= read -r line; do
 aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
 --log-events timestamp=$TS,message="$line" >/dev/null; TS=$((TS+1000));
done < auth.log

aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
 --query 'events[].message' --output text
```

Result:

All 7 lines of `auth.log` were shipped to the centralised CloudWatch Logs store (via LocalStack) and successfully read back with `get-log-events`, confirming the log-shipping pipeline works end-to-end. Centralising logs matters because an attacker who compromises a single host cannot erase evidence that has already left that host.

Evidence:

<img width="798" height="145" alt="Image" src="https://github.com/user-attachments/assets/6059b307-3e5e-4d97-9bc1-8493beb90199" />

<img width="809" height="210" alt="Image" src="https://github.com/user-attachments/assets/f46ce11b-fb09-4296-8619-73a7331eb4d6" />

---

### Task 3: Query for Security-Relevant Activity

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

#### Troubleshooting Note

The lab guide's `awk '{print $4, $5}'` produced an incomplete result (`4 ip=203.0.113.9`, missing the `user=admin` field), because each log line only has 4 space-separated fields (`timestamp EVENT user=X ip=Y`), not 5. Field `$4` is `ip=...`; there is no `$5`.

**Fix applied:**

```bash
grep LOGIN_FAIL auth.log | awk '{print $3, $4}' | sort | uniq -c
```

Observed result after the fix:

```text
      4 user=admin ip=203.0.113.9
```

Result:

Four failed logins were identified, all for user `admin` from the same IP address (`203.0.113.9`) — a clear brute-force pattern. This distinguishes a **log** (the durable record in `auth.log`, queried after the fact) from an **event** (a real-time trigger, such as an alert fired the instant the 3rd or 4th failure occurs).

Evidence:

<img width="803" height="66" alt="Image" src="https://github.com/user-attachments/assets/648233ec-4b5f-4da7-b613-d2263db1ece8" />

<img width="803" height="79" alt="Image" src="https://github.com/user-attachments/assets/f3b220a7-4c24-4434-b7a5-0ab8bb0e3f7d" />

**End of Session A.** `auth.log` and the centralised read-back were retained for Session B.

---

## Session B (Week 10) — Tamper-Proofing, Detection & Response

### Task 4: Tamper-Proof (Hash-Chained) Logs

```bash
PREV=0
while IFS= read -r line; do
 PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
 printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain
cat auth.chain
```

Each log line's hash incorporates the previous line's hash, so altering any earlier line changes every hash that follows it.

Then a tampered copy was created, changing the export size from `500MB` to `5MB`:

```bash
sed 's/500MB/5MB/' auth.log > auth.tampered
```

The chain was recomputed from the tampered file and the final hashes compared:

```bash
PREV=0
while IFS= read -r line; do
 PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
 printf '%s | %s\n' "$line" "$PREV"
done < auth.tampered > auth.tampered.chain

echo "=== Original final hash ==="
tail -1 auth.chain

echo "=== Tampered final hash ==="
tail -1 auth.tampered.chain
```

Observed result:

```text
=== Original final hash ===
... size=500MB | ababa787b4bf524d9addca8c48e4909fc105769a6f17574f42cefe8f81233cf

=== Tampered final hash ===
... size=5MB | 72f1d53774a3a938fa7bd3a88f67894e5a64055a41ee7511eac53d7bd89d859b
```

Result:

Changing a single value in the last log line produced a completely different final hash, while every preceding line's hash (unaffected by the edit) stayed identical between the two chains. This proves the hash chain detects tampering anywhere in the log, and pinpoints that only the last entry was altered since earlier hashes still matched.

Evidence:

<img width="813" height="465" alt="Image" src="https://github.com/user-attachments/assets/ce1d0c80-ccdf-471f-ad9c-bee5bc73f4d3" />

<img width="808" height="121" alt="Image" src="https://github.com/user-attachments/assets/e4e2cd88-5a9d-44f7-b7d2-d307d20cbe1e" />

<img width="815" height="114" alt="Image" src="https://github.com/user-attachments/assets/9393e1d9-0372-4b57-8307-9db78f84e4ca" />

---

### Task 5: Detect the Incident (Correlation)

```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
 echo 'ALERT: probable brute-force -> compromise -> data exfiltration';
fi
```

Observed result:

```text
IP=203.0.113.9 fails=4 success=1 export=1
ALERT: probable brute-force -> compromise -> data exfiltration
```

Result:

No single log line in `auth.log` is inherently malicious — failed logins, a successful login, and a data export can each occur legitimately. Correlating all three event types from the same IP within the log revealed the full attack narrative and triggered an alert. This is the core function of a SIEM: turning multiple individually-benign-looking events into one actionable detection.

Evidence:

<img width="784" height="253" alt="Image" src="https://github.com/user-attachments/assets/9a91ee8c-6c08-4951-9f2d-18be6eb18e56" />

---

### Task 6: Incident Response

**CONTAIN** — block the attacker IP:

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
 'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'
```

Observed result:

```text
target     prot opt source               destination
DROP       all  --  203.0.113.9          0.0.0.0/0
```

**COLLECT** — make an immutable, hashed evidence copy:

```bash
cp auth.log evidence_$(date +%Y%m%d).log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

Observed result:

```text
0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99227731696a203b  evidence_20260902.log
```

Result:

Traffic from the attacker IP (`203.0.113.9`) was blocked at the firewall, containing the immediate threat. A timestamped copy of the original log was taken and hashed with SHA-256, so any future modification to the evidence copy can be detected by re-hashing and comparing against `evidence.sha256`.

Evidence:

<img width="815" height="121" alt="Image" src="https://github.com/user-attachments/assets/f52407b6-c08c-4720-9fa2-99a7c717079a" />

<img width="808" height="115" alt="Image" src="https://github.com/user-attachments/assets/48a55540-2c9b-4063-80f3-9eaace20a625" />

---

## Incident Report

**Detection:** The incident was detected in Task 5 by correlating three event types from `auth.log` for IP `203.0.113.9`: 4 failed logins, 1 successful login, and 1 large data export, all in quick succession. Individually none of these events would trigger suspicion; correlated together they matched a known attack signature (brute-force → compromise → exfiltration) and raised an alert.

**Analysis:** The timeline shows a brute-force attempt against the `admin` account beginning at `09:01:10`, four rapid failures 2–3 seconds apart, then a successful login at `09:01:22` — consistent with a scripted credential-guessing attack that eventually succeeded. Eighteen seconds later, at `09:01:40`, the same IP exported 500MB of data, consistent with exfiltration immediately following account compromise.

**Containment:** An iptables `DROP` rule was applied against source IP `203.0.113.9` on the `INPUT` chain, blocking any further traffic from the attacker to the affected host.

**Evidence & integrity:** The original `auth.log` was hash-chained (Task 4) before containment, and a hash mismatch on the tampered copy proved the chain detects unauthorised edits. A separate timestamped evidence copy (`evidence_20260902.log`) was taken and hashed (`sha256sum -c evidence.sha256` → `OK`), providing a verifiable, tamper-evident record for follow-up investigation.

**Lesson learned:** A single failed login or a single large export is not inherently alarming, but the *combination and sequence* of events from one source is. This lab reinforced that meaningful detection requires correlating logs across time and event type — not just storing them — and that evidence integrity (hash chaining, separate storage of the evidence hash) must be established *before* an incident occurs, since an attacker who can also edit the primary log could otherwise erase their own tracks.

---

## Verification Commands

```bash
aws --endpoint-url=http://localhost:4566 logs describe-log-groups
sha256sum -c evidence.sha256
```

Observed result:

```json
{
    "logGroups": [
        {
            "logGroupName": "/ccse/app",
            "creationTime": 1788332330989,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:us-east-1:000000000000:log-group:/ccse/app:*",
            "storedBytes": 397
        }
    ]
}
```

```text
evidence_20260902.log: OK
```

Evidence:

<img width="809" height="323" alt="Image" src="https://github.com/user-attachments/assets/3b76a1b2-1a20-48ae-bd61-87eacb05116f" />

---

## Short-Answer Questions

### Q1. What is the difference between a log and an event? Give an example of each from this lab.

A **log** is a durable, passive record of something that happened, stored for later query — for example, the line `2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9` sitting in `auth.log`, which only gets examined when someone runs a query against it (Task 3). An **event** is an active, real-time trigger fired the moment a condition is met — for example, the `ALERT: probable brute-force -> compromise -> data exfiltration` message produced in Task 5, which is generated instantly when the correlation conditions (≥3 fails, ≥1 success, ≥1 export from the same IP) are satisfied, rather than being discovered later by manual review.

### Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?

Audit logs must be tamper-proof because they are often the only record of what an attacker did, and an attacker with sufficient access frequently tries to edit or delete logs to cover their tracks. If logs can be silently altered, they cannot be trusted as evidence for detection, forensics, or compliance.

A hash chain achieves this by making each log entry's hash a function of both its own content and the previous entry's hash. Task 4 showed that changing a single value (`500MB` → `5MB`) in one line produced a different hash for that line, while every prior line's hash stayed identical — proving both that the log was altered and roughly where. Recomputing the chain and comparing the final hash against a previously-stored value makes any tampering, anywhere in the log, immediately detectable.

### Q3. How did correlation detect an incident that no single log line revealed?

No individual line in `auth.log` is conclusively malicious on its own: failed logins happen from typos, a successful login is normal, and a large data export can be legitimate business activity. Task 5's correlation logic combined three separate counts — `LOGIN_FAIL` ≥ 3, `LOGIN_OK` ≥ 1, and `EXPORT_DATA` ≥ 1 — all filtered to the *same* IP address. Only when all three conditions were true together did the script raise `ALERT: probable brute-force -> compromise -> data exfiltration`. This is exactly how a SIEM works: it looks for patterns across multiple events rather than judging any single event in isolation.

### Q4. List the incident-response steps you performed and the goal of each.

| Step | Goal |
|---|---|
| **Detect** (Task 5) | Identify that an incident occurred at all, by correlating failed logins, a successful login, and a data export from the same IP. |
| **Analyse** (Incident Report) | Reconstruct the timeline and understand what happened — a brute-force attack that succeeded, followed by exfiltration. |
| **Contain** (Task 6) | Stop the attack from continuing, by blocking the attacker's IP with an iptables `DROP` rule. |
| **Collect evidence** (Task 6) | Preserve a hashed, timestamped copy of the log for forensic and legal integrity, so it can later be proven unaltered. |
| **Document** (Incident Report) | Record detection, analysis, containment, evidence, and lessons learned for future reference and compliance. |

### Q5. How do the same logs serve both security monitoring and compliance evidence (Weeks 6, 11)?

The same `auth.log` entries serve two purposes simultaneously. For **security monitoring**, they feed queries and correlation rules (Tasks 3 and 5) that detect brute-force attempts and data exfiltration in near real time, enabling a timely response. For **compliance evidence**, the same log — once hash-chained (Task 4) and collected with a verifiable SHA-256 hash (Task 6) — becomes a tamper-evident record that can be presented to auditors or regulators to prove what happened, when, and that the record has not been altered since collection. The dual value depends on the same underlying practices: centralising logs so they cannot be quietly edited at the source, and preserving their integrity so they remain trustworthy for both operational and audit purposes.

---

## Security Best-Practices Checklist

- [x] Logs are centralised, not left scattered on each host.
- [x] Security-relevant activity (failed logins) can be queried.
- [x] Logs are tamper-evident (hash chain) and forwarded to a separate store.
- [x] An incident is detected by correlating multiple events.
- [x] Incident response performed: contain, collect evidence, document.

---

## Cleanup

After completing the lab and saving all evidence, the environment was removed:

```bash
rm -f auth.log auth.chain auth.tampered auth.tampered.chain evidence_*.log evidence.sha256
docker stop localstack && docker rm localstack
```

---

## Conclusion

This lab demonstrated that security is not just about prevention.Visibility and response matter just as much, since "prevention eventually fails." Session A showed that logs are only useful if they are centralised and queryable; a log sitting only on a compromised host is easy for an attacker to destroy. Session B showed that integrity (hash chaining) protects logs from silent tampering, correlation turns individually harmless-looking events into an actionable detection, and a disciplined incident-response process (contain, collect, document) preserves both the ability to stop an ongoing attack and the evidence needed afterward. The troubleshooting encountered, LocalStack's licensing change and an incorrect `awk` field index also reinforced the same lesson from Lab 4: security tooling and commands must be verified against real output, not assumed correct from documentation alone.
