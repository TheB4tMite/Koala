# Koala LLM Agent

The `llm_agent.py` is a ReAct-style AI agent that communicates with MCP servers through the Koala Zero Trust PEP. It supports local LLMs via Ollama and OpenAI-compatible backends.

## Features

- **ZTA Integrated:** Automatically handles `X-Koala-Subject`, `Mcp-Session-Id`, and Step-up Authentication (CHALLENGE flow).
- **Multi-Backend:** Works with Ollama (default) or any OpenAI-compatible API (vLLM, llama.cpp, etc.).
- **Gemma Optimized:** Uses a robust prompt-based tool calling fallback for models that don't support native tool-calling reliably.
- **Interactive REPL:** Explore tools and ZTA behavior in real-time.

## Configuration

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `LLM_PROVIDER` | `ollama` | `ollama` or `openai` |
| `LLM_MODEL` | `gemma3:4b` | Model name to use |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |
| `LLM_BASE_URL` | (varies) | Base URL for OpenAI-compatible provider |
| `LLM_API_KEY` | `no-key-required` | API key for the LLM provider |
| `KOALA_SUBJECT` | `gemma-agent-1` | Value for `X-Koala-Subject` header |
| `KOALA_STEPUP_TOKEN` | `koala_admin_token` | Token used for `/stepup/verify` |
| `MAX_STEPS` | `6` | Maximum ReAct loop iterations per turn |

## Usage

### Prerequisites

1. Ensure the Koala stack is running: `docker-compose up -d`
2. Install dependencies: `pip install -r agents/requirements.txt`
3. Pull the default model: `ollama pull gemma3:4b`

### Running the Agent

**Interactive REPL:**
```bash
python agents/llm_agent.py
```

**Single Prompt:**
```bash
python agents/llm_agent.py --prompt "What is the weather in Bengaluru?"
```

## Prompt Format (Gemma Fallback)

The agent uses a ReAct pattern with structured JSON output. The system prompt instructs the model to reply with a single JSON object on one line:

- For tool calls: `{"tool": "get_weather", "arguments": {"location": "Bengaluru"}}`
- For final answers: `{"final": "The weather in Bengaluru is 25°C."}`

## Sample Transcript

```text
[*] Initializing MCP session for subject: gemma-agent-1
[*] Step 1/6...
[TOOL_CALL] get_weather({"location": "Bengaluru"})
[TOOL_RESULT] {"temperature": 25, "condition": "Sunny"}...
[*] Step 2/6...

Assistant: The weather in Bengaluru is currently 25°C and sunny.
```

### CHALLENGE & Step-up Recovery

```text
user> What is the weather in Chennai?
[*] Step 1/6...
[TOOL_CALL] get_weather({"location": "Chennai"})
[*] Received CHALLENGE for tools/call. Attempting step-up...
[+] Step-up successful.
[TOOL_RESULT] {"temperature": 30, "condition": "Humid"}...
[*] Step 2/6...

Assistant: It is 30°C and humid in Chennai.
```

## Backend Matrix

| Provider | `LLM_PROVIDER` | `LLM_BASE_URL` | `LLM_MODEL` |
| --- | --- | --- | --- |
| Ollama | `ollama` | `http://localhost:11434` | `gemma3:4b` |
| vLLM | `openai` | `http://<host>:8000/v1` | `<model_name>` |
| LM Studio | `openai` | `http://localhost:1234/v1` | `<model_name>` |
| OpenAI | `openai` | `https://api.openai.com/v1` | `gpt-4o` |
