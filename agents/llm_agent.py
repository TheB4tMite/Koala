"""LLM-driven MCP agent — Milestone 6.

Supports Gemma via Ollama (default) and OpenAI-compatible backends.
Implements the full MCP handshake and ZTA (PERMIT/CHALLENGE/DENY) logic.
"""

import asyncio
import hashlib
import json
import os
import sys
import re
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

# Constants matching mock_agent.py & ZTA contract
PEP_BASE = os.getenv("PEP_BASE", "http://localhost:8000")
PEP_MCP = f"{PEP_BASE}/mcp"
PEP_STEPUP = f"{PEP_BASE}/stepup/verify"
PROTOCOL_VERSION = "2024-11-05"
ACCEPT = "application/json, text/event-stream"
DEFAULT_SUBJECT_ID = "gemma-agent-1"
DEFAULT_STEPUP_TOKEN = "koala_admin_token"

# LLM Config
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")  # 'ollama' or 'openai'
LLM_MODEL = os.getenv("LLM_MODEL", "gemma3:4b")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", OLLAMA_HOST if LLM_PROVIDER == "ollama" else None)
LLM_API_KEY = os.getenv("LLM_API_KEY", "no-key-required")

MAX_STEPS = int(os.getenv("MAX_STEPS", "6"))

SYSTEM_PROMPT = (
    "You are a helpful assistant with access to tools via MCP. "
    "Follow this ReAct pattern:\n"
    "1. Receive user goal.\n"
    "2. If you need information from a tool, output a SINGLE LINE containing ONLY a JSON object: "
    '{"tool": "tool_name", "arguments": {"arg1": "val1"}}\n'
    "3. Wait for the tool result.\n"
    "4. When you have the final answer, output a SINGLE LINE containing ONLY a JSON object: "
    '{"final": "your final answer to the user"}\n'
    "Keep responses concise. Use ONLY available tools."
)

class ToolCall(BaseModel):
    tool: str
    arguments: Dict[str, Any]

class FinalResult(BaseModel):
    final: str

class AgentState:
    def __init__(self, subject_id: str):
        self.subject_id = subject_id
        self.session_id: Optional[str] = None
        self.tools: List[Dict[str, Any]] = []
        self.history: List[Dict[str, Any]] = []

def _extract_json(text: str) -> Dict[str, Any]:
    """Lenient JSON extractor that finds the first balanced JSON object."""
    text = text.strip()
    # Try to find something that looks like a JSON object
    match = re.search(r'(\{.*\})', text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON found in response: {text}")
    
    raw = match.group(1)
    # Basic balancing if needed (though re.DOTALL and .* usually grab everything)
    # For robust parsing of nested objects, a simple counter works
    stack = 0
    end_idx = -1
    for i, char in enumerate(raw):
        if char == '{':
            stack += 1
        elif char == '}':
            stack -= 1
            if stack == 0:
                end_idx = i + 1
                break
    
    if end_idx == -1:
         raise ValueError(f"Incomplete JSON found: {raw}")
    
    return json.loads(raw[:end_idx])

class KoalaAgent:
    def __init__(self, subject_id: str = DEFAULT_SUBJECT_ID):
        self.state = AgentState(subject_id)
        self.client = httpx.AsyncClient(timeout=120.0)

    async def close(self):
        await self.client.aclose()

    async def _check_ollama_model(self):
        if LLM_PROVIDER != "ollama":
            return
        
        try:
            resp = await self.client.get(f"{OLLAMA_HOST}/api/tags")
            resp.raise_for_status()
            tags = resp.json().get("models", [])
            names = [t["name"] for t in tags]
            if LLM_MODEL not in names and f"{LLM_MODEL}:latest" not in names:
                print(f"ERROR: Model '{LLM_MODEL}' not found in Ollama.")
                print(f"Please run: ollama pull {LLM_MODEL}")
                sys.exit(1)
        except httpx.ConnectError:
            print(f"ERROR: Could not connect to Ollama at {OLLAMA_HOST}.")
            print("Ensure Ollama is running.")
            sys.exit(1)

    async def _mcp_rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if "id" not in payload and not method.startswith("notifications/"):
            payload["id"] = int(datetime.now().timestamp() * 1000)

        headers = {
            "Content-Type": "application/json",
            "Accept": ACCEPT,
            "X-Koala-Subject": self.state.subject_id,
        }
        if self.state.session_id:
            headers["Mcp-Session-Id"] = self.state.session_id

        resp = await self.client.post(PEP_MCP, json=payload, headers=headers)
        
        # Handle CHALLENGE
        if resp.status_code == 408:
            error_data = resp.json().get("error", {})
            if error_data.get("code") == -32000:
                print(f"[*] Received CHALLENGE for {method}. Attempting step-up...")
                await self._stepup()
                # Retry once
                resp = await self.client.post(PEP_MCP, json=payload, headers=headers)

        if resp.status_code == 403:
            error_msg = resp.json().get("error", {}).get("message", "Unknown denial")
            print(f"[-] DENIED by PEP: {error_msg}")
            sys.exit(1)

        resp.raise_for_status()
        
        # Update session ID if provided
        new_sid = resp.headers.get("mcp-session-id")
        if new_sid:
            self.state.session_id = new_sid

        return self._parse_mcp_response(resp)

    def _parse_mcp_response(self, resp: httpx.Response) -> Dict[str, Any]:
        if not resp.content:
            return {}
        ctype = resp.headers.get("content-type", "")
        if ctype.startswith("application/json"):
            return resp.json()
        if ctype.startswith("text/event-stream"):
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    return json.loads(line.removeprefix("data:").strip())
        return {}

    async def _stepup(self):
        stepup_token = os.getenv("KOALA_STEPUP_TOKEN", DEFAULT_STEPUP_TOKEN)
        resp = await self.client.post(
            PEP_STEPUP,
            json={"subject_id": self.state.subject_id, "secondary_token": stepup_token}
        )
        if resp.status_code == 200:
            print("[+] Step-up successful.")
        else:
            print(f"[-] Step-up failed: {resp.text}")
            sys.exit(1)

    async def initialize(self):
        print(f"[*] Initializing MCP session for subject: {self.state.subject_id}")
        await self._check_ollama_model()
        
        init_res = await self._mcp_rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "koala-llm-agent", "version": "0.1.0"},
        })
        
        await self._mcp_rpc("notifications/initialized")
        
        tools_res = await self._mcp_rpc("tools/list")
        self.state.tools = tools_res.get("result", {}).get("tools", [])
        print(f"[+] Initialized. Found {len(self.state.tools)} tools.")

    async def _llm_chat(self, messages: List[Dict[str, str]]) -> str:
        if LLM_PROVIDER == "ollama":
            url = f"{OLLAMA_HOST}/api/chat"
            payload = {
                "model": LLM_MODEL,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9,
                }
            }
            resp = await self.client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()["message"]["content"]
        else:
            # OpenAI compatible
            url = f"{LLM_BASE_URL}/chat/completions"
            headers = {"Authorization": f"Bearer {LLM_API_KEY}"}
            payload = {
                "model": LLM_MODEL,
                "messages": messages,
                "temperature": 0.2,
            }
            resp = await self.client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    async def run_turn(self, user_prompt: str):
        self.state.history.append({"role": "user", "content": user_prompt})
        
        # Inject system prompt and tool list
        tool_desc = "\n".join([f"- {t['name']}: {t['description']} (args: {t['inputSchema']['properties']})" for t in self.state.tools])
        prompt_with_tools = f"{SYSTEM_PROMPT}\n\nAvailable tools:\n{tool_desc}"
        
        messages = [{"role": "system", "content": prompt_with_tools}] + self.state.history
        
        for step in range(MAX_STEPS):
            print(f"[*] Step {step+1}/{MAX_STEPS}...")
            response_text = await self._llm_chat(messages)
            
            try:
                parsed = _extract_json(response_text)
                if "tool" in parsed:
                    tool_name = parsed["tool"]
                    args = parsed["arguments"]
                    print(f"[TOOL_CALL] {tool_name}({json.dumps(args)})")
                    
                    tool_result = await self._mcp_rpc("tools/call", {"name": tool_name, "arguments": args})
                    
                    # Log result
                    result_str = json.dumps(tool_result.get("result", tool_result))
                    print(f"[TOOL_RESULT] {result_str[:100]}...")
                    
                    messages.append({"role": "assistant", "content": response_text})
                    messages.append({"role": "user", "content": f"Tool result: {result_str}"})
                elif "final" in parsed:
                    print(f"\nAssistant: {parsed['final']}")
                    self.state.history.append({"role": "assistant", "content": parsed["final"]})
                    return
                else:
                    print(f"[!] LLM returned unknown JSON: {response_text}")
                    messages.append({"role": "assistant", "content": response_text})
                    messages.append({"role": "user", "content": "Error: Your response must contain either 'tool' or 'final' key."})
            except Exception as e:
                print(f"[!] Failed to parse LLM response: {e}")
                print(f"Raw response: {response_text}")
                messages.append({"role": "assistant", "content": response_text})
                messages.append({"role": "user", "content": "Error: Could not parse your JSON. Please output a single line of valid JSON."})

        print("[-] Max steps reached.")

async def repl():
    subject = os.getenv("KOALA_SUBJECT", DEFAULT_SUBJECT_ID)
    agent = KoalaAgent(subject)
    try:
        await agent.initialize()
        print("\n--- Koala ZTA Agent REPL ---")
        print("Type 'exit' or 'quit' to stop.\n")
        
        while True:
            try:
                user_input = input("user> ").strip()
                if not user_input:
                    continue
                if user_input.lower() in ("exit", "quit"):
                    break
                
                await agent.run_turn(user_input)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
    finally:
        await agent.close()

async def single_prompt(prompt: str):
    subject = os.getenv("KOALA_SUBJECT", DEFAULT_SUBJECT_ID)
    agent = KoalaAgent(subject)
    try:
        await agent.initialize()
        await agent.run_turn(prompt)
    finally:
        await agent.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", help="Run a single prompt and exit")
    parser.add_argument("--subject", help="Set X-Koala-Subject")
    args = parser.parse_args()

    if args.subject:
        os.environ["KOALA_SUBJECT"] = args.subject

    if args.prompt:
        asyncio.run(single_prompt(args.prompt))
    else:
        asyncio.run(repl())
