# ZTA-MCP: Zero Trust Architecture for Model Context Protocol Servers

A security sidecar that places a Zero Trust boundary between AI agents and
[Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers. Instead of
letting an agent talk directly to an MCP server, every JSON-RPC call is intercepted,
authenticated, evaluated against policy, and sanitized before it reaches the tools.

## Motivation

MCP is rapidly becoming the standard interface for agent-to-tool communication, but
the base protocol has no native notion of identity, dynamic trust, data loss
prevention, or fine-grained authorization. This project wraps an MCP server in a
Zero Trust architecture so that:

- No request is trusted by default — every call is re-evaluated.
- Access is granted based on a *dynamic* trust score, not just a static role.
- Egress data is scrubbed for sensitive material before it leaves the trust
  boundary.

## Architecture

```
+-----------+       +-------+       +-------+       +----------+
| MockAgent | --->  |  PEP  | --->  |  PDP  |       | MCP Core |
| (client)  |       | :8000 | <---  | :8181 |       |  :8080   |
+-----------+       +---+---+       +-------+       +----+-----+
                        |                                 ^
                        +---------------------------------+
                              forwarded JSON-RPC
```

| Component    | Role                                                                 |
| ------------ | -------------------------------------------------------------------- |
| **PEP**      | Policy Enforcement Point. FastAPI router. Intercepts JSON-RPC, applies identity + egress scrubbing, forwards to MCP Core. |
| **PDP**      | Policy Decision Point. FastAPI + OPA. Computes dynamic trust scores and evaluates access rules. |
| **MCP Core** | The actual MCP server built with the official Python `mcp` SDK (FastMCP). Hosts the tools. |

Only the **PEP** is exposed to the host. The PDP and MCP Core live on an
internal Docker network and are unreachable from outside the trust boundary.

## Repository layout

```
Koala/
├── docker-compose.yml
├── shared/            # cross-service code (schemas, utils)
│   └── schemas/
├── services/
│   ├── pep/           # Policy Enforcement Point
│   ├── pdp/           # Policy Decision Point
│   └── mcp_core/      # MCP server with tools
└── agents/
    └── mock_agent.py  # test client
```

## Running

Requires Docker + Docker Compose.

```bash
docker-compose up --build
```

This brings up all three services. The PEP listens on `http://localhost:8000`.

In a second shell, fire a request through the PEP:

```bash
python agents/mock_agent.py
```

The mock agent will call `tools/list` and then invoke `get_weather`, both routed
through the PEP.

## Milestones

- **M1 — Pass-through (current):** end-to-end wiring. PEP forwards JSON-RPC to
  MCP Core with no security checks. Two dummy tools exposed: `get_weather`,
  `read_dummy_file`.
- **M2 — Identity & AuthN:** OIDC/JWT at the PEP.
- **M3 — PDP + OPA:** dynamic trust scoring, Rego policies.
- **M4 — Egress DLP:** response scrubbing before it leaves the PEP.

## Status

Milestone 1 scaffolding. Not production-ready. Academic project.
