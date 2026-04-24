# Project Koala — Test Execution Report
Date: 2026-04-23

## Executive Summary
The security harness for Milestones 1–5 was executed. Most core security controls (Rate Limiting, Step-up Auth, HMAC Signing, Fail-closed Core) are functioning correctly. However, a **critical bug** was identified in the **Milestone 5 Audit Chain** verification logic.

## Detailed Results

| Section | Test Case | Status | Notes |
| :--- | :--- | :--- | :--- |
| 1 | Health Checks | **PASS** | PEP, PDP, and MCP Core are all healthy. |
| 2 | Happy Path | **PASS** | End-to-end flow with step-up verification works. |
| 3 | PDP Stress Test | **PASS** | Decision bands (PERMIT/CHALLENGE/DENY) verified. |
| 4 | Step-up Probe | **PASS** | Audit logs correctly capture 401/404 rejections. |
| 5 | Fail-closed (PEP) | **PASS** | Core rejects tampered/stale/bare requests. |
| 6 | Step-up Timeout | **PASS** | PEP holds requests for 30s before 408 timeout. |
| 7 | Audit Chain | **FAIL** | **Integrity Mismatch** (see findings below). |
| 8 | Memory Hygiene | **PASS** | PDP trust scorer evicts idle subjects correctly. |

## Key Findings & Issues

### [BUG] Audit Chain Timestamp Normalization
The `verify_chain.py` script reports intermittent `record_hash MISMATCH` failures.
- **Symptom:** ~10% of rows fail verification without manual tampering.
- **Root Cause:** Discrepancy between Python's `datetime.isoformat()` (used for hashing) and Postgres's `to_jsonb()` (used for fetching). Postgres truncates trailing zeros in fractional seconds (e.g., `.490610` becomes `.49061`), causing a hash mismatch.
- **Impact:** False positives during integrity audits.
- **Recommendation:** Implement a custom canonicalization function that forces a fixed number of decimal places for timestamps before hashing.

### [VERIFIED] Tamper Detection
Despite the bug above, the chain correctly identifies manual tampering. Mutating a `decision` column in the database immediately causes the `verify_chain.py` script to flag the specific row and subsequent rows as broken.

## Cleanup
The environment was left running. To clean up:
```bash
docker-compose down -v
```
