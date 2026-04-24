# Project Koala — Test & Stress Plan

This folder contains the harness for verifying that every security control
added across Milestones 1–5 actually works end-to-end. Each section lists
what is being tested, the command to run, and what "passing" looks like.

All commands assume you are at the repo root (the `Koala/` directory).

## 0. Prerequisites

- Docker + Docker Compose up and running.
- Python 3.10+ on the host with `httpx` installed:
  ```bash
  pip install httpx
  ```

Bring the stack up (clean, so rate-limiter state and audit log start empty):

```bash
docker-compose down -v
docker-compose up --build -d
```

Wait ~10 s for Postgres to go healthy, then verify containers:

```bash
docker-compose ps
```

All of `zta-postgres`, `zta-pdp`, `zta-mcp-core`, `zta-pep` should be `running`
and `healthy` (or `started`). Tail logs in a second terminal while testing:

```bash
docker-compose logs -f pep pdp mcp_core
```

---

## 1. Health checks

```bash
curl -s http://localhost:8000/health
```
Expect: `{"status":"ok","service":"pep"}`

PDP and MCP Core are **not** reachable from the host by design (ZTA). The
only way to health-check them is through their internal network:

```bash
docker exec zta-pep curl -s http://pdp:8181/health
docker exec zta-pep curl -s http://mcp_core:8080/health
```
Expect: `{"status":"ok","service":"pdp"}` and `{"status":"ok","service":"mcp_core"}`.

---

## 2. Happy path (Milestones 1–2)

**A. Mock Agent:**
```bash
python agents/mock_agent.py
```

**B. LLM Agent:**
```bash
python agents/llm_agent.py --prompt "What is the weather in Bengaluru?"
```

Expect a clean run ending with a `get_weather` result. Both agents exercise:

- JSON-RPC through the PEP → PDP → Core
- HMAC signing of the `SecurityContext` at the PEP
- Signature + timestamp + payload-hash verification at the Core
- CHALLENGE parking and step-up release (Milestone 4)

---

## 3. Stress test the PDP trust scorer (Milestone 3)

Spams the PEP as a single subject and classifies responses into the three
decision bands.

```bash
python test/stress_rate_limit.py 12 stress-test
```

Default scorer: `threshold=5 req/60s`, `penalty=0.2`. Expected breakdown for
12 back-to-back calls (plus `initialize` + `initialized` already counted):

| Request # | Scorer count | Trust score | Expected band       |
| --------- | ------------ | ----------- | ------------------- |
|   1 – 4   |   3 – 6      |  1.0 – 0.8  | PERMIT              |
|   5 – 6   |   7 – 8      |  0.6 – 0.4  | CHALLENGE (parks)   |
|   7 –     |   ≥ 9        |  ≤ 0.2      | DENY (`-32001`)     |

> CHALLENGE requests park at the PEP for up to 30 s. The stress script uses
> a short client timeout so they surface as `CHALLENGE (client timeout,
> still parked)` and the loop moves on. Those parked coroutines will log
> `STEPUP/DENY` events at the PEP once they time out, which is expected and
> will show up in §7.

---

## 4. Step-up authentication probe (Milestone 5 patch)

Fires a series of bad `/stepup/verify` requests. Every rejection **must**
appear on the audit chain.

```bash
python test/stepup_probe.py probe-test
```

Expect `401` for each invalid token and `404` for the non-existent
challenge. The script prints where to look next — the audit chain inspection
in §7 should show `action=STEPUP decision=DENY` rows for every probe.

---

## 5. Fail-closed at the MCP Core (Milestones 2–3)

The Core is on the internal network only; you cannot reach it from the host:

```bash
curl -s --max-time 2 http://localhost:8080/mcp || echo "blocked (expected)"
```

To prove the signature/replay/payload-binding controls work, run the forge
harness **inside the PEP container** (it has the signing secret and the
internal DNS for `mcp_core`):

```bash
docker cp test/forge_attack.py zta-pep:/tmp/forge_attack.py
docker exec zta-pep python /tmp/forge_attack.py
```

Expected output (four checks):

1. `missing X-Koala-Context` → 401  (`missing X-Koala-Context header`)
2. `valid signed context (sanity)` → 200  (weather payload returned)
3. `payload tamper` → 401  (`payload hash mismatch`)
4. `replay (stale timestamp >60s old)` → 401  (`context timestamp too old`)

`Result: 4/4 checks passed.`

---

## 6. Step-up timeout behaviour (Milestone 4)

Triggers a CHALLENGE but does **not** send the step-up token. The PEP should
hold the request for ~30 s and then return a JSON-RPC `-32000` with a
`Step-up authentication timed out` message, and the PEP must append a
`STEPUP/DENY` event.

```bash
# First, push a subject into the CHALLENGE band:
python test/stress_rate_limit.py 8 timeout-subject

# The stress script already drove 'timeout-subject' past the threshold.
# Now fire one more tool-call and wait it out (no stepup/verify):
python - <<'PY'
import httpx, json
r = httpx.post(
    "http://localhost:8000/mcp",
    headers={
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "X-Koala-Subject": "timeout-subject",
    },
    json={
        "jsonrpc": "2.0", "id": 9999,
        "method": "tools/call",
        "params": {"name": "get_weather", "arguments": {"location": "Void"}}
    },
    timeout=60,
)
print("status", r.status_code)
print(json.dumps(r.json(), indent=2))
PY
```

Expect HTTP 408 and body:
```json
{"jsonrpc":"2.0","id":9999,"error":{"code":-32000,"message":"Step-up authentication timed out"}}
```

---

## 7. Tamper-evident audit chain (Milestone 5)

Pulls every row from `audit_logs` and recomputes the chain:

```bash
python test/verify_chain.py
```

Expect a row-by-row listing tagged `[OK    ]` and a final
`CHAIN INTACT — N rows verified.` line.

You should see a mix of actions (the exact counts depend on how many of the
previous sections you ran):

| `action`    | Produced by                                  |
| ----------- | -------------------------------------------- |
| `AUTHORIZE` | PDP — one per `/authorize` call              |
| `TOOL_CALL` | PEP — one per successful core execution     |
| `STEPUP`    | PEP — one per `/stepup/verify` outcome       |
| `DENY`      | PEP — one per PDP `DENY` reaching the router |

Raw peek (useful for screenshots / demo):

```bash
docker exec zta-postgres psql -U koala -d koala_audit -c \
  "SELECT seq, action, decision, subject_id, left(record_hash, 12) AS hash FROM audit_logs ORDER BY seq;"
```

### Prove the chain catches tampering

Mutate one row and re-verify — the chain must break from that point forward:

```bash
docker exec zta-postgres psql -U koala -d koala_audit -c \
  "UPDATE audit_logs SET decision='PERMIT' WHERE action='DENY' AND seq = (SELECT MIN(seq) FROM audit_logs WHERE action='DENY');"

python test/verify_chain.py
```

Expect: one `[BROKEN]` row (the one you mutated) plus every row after it
(because their `prev_hash` no longer matches the recomputed `record_hash`
of the mutated ancestor). Final line:
`CHAIN BROKEN — N integrity failure(s) across M rows.`

Restore with a fresh run:

```bash
docker-compose down -v
docker-compose up --build -d
```

---

## 8. Memory hygiene of the trust scorer (Milestone 3 post-audit)

The scorer evicts idle subject keys. Drive ~20 one-shot subjects, wait for
the 60 s GC sweep, and confirm the subjects are gone. Because the in-memory
dict is process-local, the inspection runs in the PDP container:

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -H "Content-Type: application/json" \
       -H "Accept: application/json, text/event-stream" \
       -H "X-Koala-Subject: throwaway-$i" \
       -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"gc","version":"0.0"}}}' \
       http://localhost:8000/mcp
done

# Wait out the 60s window + one GC sweep, then look at PDP logs:
sleep 75
docker-compose logs --tail=50 pdp | grep "gc: evicted"
```

Expect at least one log line like `trust-scorer gc: evicted N idle subjects`
where `N ≥ 20`.

---

## Cleanup

```bash
docker-compose down -v   # -v wipes the audit volume; omit to keep it
```

---

## File map

| File                          | Runs on            | Purpose                                   |
| ----------------------------- | ------------------ | ----------------------------------------- |
| `TEST.md`                     | —                  | This document.                            |
| `stress_rate_limit.py`        | host               | Rate-limit band stress test.              |
| `stepup_probe.py`             | host               | Audited stepup rejection probe.           |
| `forge_attack.py`             | PEP container      | Direct-to-Core replay/tamper/bypass.      |
| `verify_chain.py`             | host (shells `docker exec`) | Full hash-chain integrity check. |
