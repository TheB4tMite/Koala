# Koala Healthcare ZTA Agent (IEEE Demo)

This agent is a ReAct-style LLM assistant ported to the `feature/ieee-healthcare-demo` branch. It demonstrates Zero Trust Architecture (ZTA) principles applied to the Model Context Protocol (MCP) in a healthcare setting.

## Key Branch Features

- **Request-ID Keyed Step-Up**: On this branch, challenges are suspended by `request_id` (UUID4) rather than `subject_id`. The agent must supply this ID in the `X-Koala-Request-Id` header and use it during `/stepup/verify`.
- **Restricted Tiers**: Certain tools (like `prescribe_medication`) always trigger a `CHALLENGE` decision at the PDP.
- **Egress DLP**: The PEP automatically scrubs SSNs from patient records. The agent is instructed to handle `[REDACTED_SSN]` gracefully.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `ollama` | `ollama` or `openai` |
| `LLM_MODEL` | `gemma3:4b` | Model name |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |
| `PEP_BASE` | `http://localhost:8000` | PEP proxy endpoint |
| `KOALA_SUBJECT` | `llm-agent` | Default subject ID |
| `KOALA_STEPUP_TOKEN` | `koala_admin_token` | Token for /stepup/verify |

## Usage

```bash
# Basic usage (REPL)
python agents/llm_agent.py

# Single prompt
python agents/llm_agent.py --prompt "Is there an interaction between aspirin and warfarin?"

# Canned Demo Scenarios
python agents/llm_agent.py --scenario a|b|c|d|all
```

## Demo Scenarios

### a. Public: Drug Interactions
**Prompt**: "What's the interaction between ibuprofen and warfarin?"
**Behavior**: Calls `get_drug_interactions`. Usually a one-shot `PERMIT`.

### b. Internal: Patient Records + DLP
**Prompt**: "Pull the record for patient P001."
**Behavior**: Calls `get_patient_record`. PEP scrubs the SSN. Agent logs `[!] PEP DLP scrubbed SSN`.

### c. Restricted: Prescribing + Step-Up
**Prompt**: "Prescribe amoxicillin 500mg for patient P001."
**Behavior**: Calls `prescribe_medication`. PDP returns `CHALLENGE`. Agent races a back-channel `/stepup/verify` and retries.

### d. Stress: Rogue Agent
**Behavior**: Rapidly fires `get_drug_interactions` until the trust score collapses and the PDP returns `DENY`.

---

## Contrast with Main Branch

On the `main` branch, the step-up verification was keyed by `subject_id`. This healthcare branch improves security by using a unique `request_id` for every transaction, preventing session-level bypass and providing more granular audit logs.
