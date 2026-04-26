"""LLM-driven MCP agent — Healthcare ZTA Demo.

Ported to feature/ieee-healthcare-demo branch.
Handles:
  - Dynamic tool discovery via tools/list.
  - Step-up authentication keyed by request_id (UUID4).
  - DLP visibility and awareness.
  - Restricted tier immediate challenges.
"""

import asyncio
import hashlib
import json
import os
import sys
import re
import uuid
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

# Constants matching ZTA contract on this branch
PEP_BASE = os.getenv("PEP_BASE", "http://localhost:8000")
PEP_MCP = f"{PEP_BASE}/mcp"
PEP_STEPUP = f"{PEP_BASE}/stepup/verify"
PROTOCOL_VERSION = "2024-11-05"
ACCEPT = "application/json, text/event-stream"
DEFAULT_SUBJECT_ID = "llm-agent"
DEFAULT_STEPUP_TOKEN = "koala_admin_token"

# LLM Config
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")  # 'ollama' or 'openai'
LLM_MODEL = os.getenv("LLM_MODEL", "gemma3:4b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", OLLAMA_HOST if LLM_PROVIDER == "ollama" else None)
LLM_API_KEY = os.getenv("LLM_API_KEY", "no-key-required")

MAX_STEPS = int(os.getenv("MAX_STEPS", "6"))

SYSTEM_PROMPT = (
    "You are a Healthcare Data Assistant with access to clinical tools via MCP. "
    "Follow this ReAct pattern:\n"
    "1. Receive user goal.\n"
    "2. If you need information from a tool, output a SINGLE LINE containing ONLY a JSON object with 'tool' and 'arguments'. "
    "   IMPORTANT: Use raw values for arguments. Do NOT include schema metadata like 'title' or 'type'.\n"
    "   Example: {\"tool\": \"get_drug_interactions\", \"arguments\": {\"drug_a\": \"aspirin\", \"drug_b\": \"warfarin\"}}\n"
    "3. Wait for the tool result.\n"
    "4. When you have the final answer, output a SINGLE LINE containing ONLY a JSON object: "
    '{"final": "your final answer to the user"}\n'
    "\n"
    "Available Healthcare Tools:\n"
    "- get_drug_interactions(drug_a, drug_b): Public interaction check.\n"
    "- get_patient_record(patient_id): Internal PHI retrieval. Valid IDs: P001, P002, P003.\n"
    "- prescribe_medication(patient_id, medication): Restricted prescribing endpoint.\n"
    "\n"
    "IMPORTANT SECURITY NOTE:\n"
    "Responses containing PHI will have SSNs automatically redacted by the PEP. "
    "You will see '[REDACTED_SSN]' in these fields. This is EXPECTED behavior. "
    "Do NOT attempt to un-redact, re-fetch, or ask the user for the raw SSN.\n"
    "Keep responses concise. Use ONLY available tools."
)

class AgentState:
    def __init__(self, subject_id: str):
        self.subject_id = subject_id
        self.session_id: Optional[str] = None
        self.tools: List[Dict[str, Any]] = []
        self.history: List[Dict[str, Any]] = []

def _extract_json(text: str) -> Dict[str, Any]:
    text = text.strip()
    match = re.search(r'(\{.*\})', text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON found in response: {text}")
    
    raw = match.group(1)
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
    def __init__(self, subject_id: str = DEFAULT_SUBJECT_ID, fake_llm: bool = False):
        self.state = AgentState(subject_id)
        self.client = httpx.AsyncClient(timeout=60.0)
        self.fake_llm = fake_llm
        self.last_request_id: Optional[str] = None

    async def close(self):
        await self.client.aclose()

    async def _check_ollama_model(self):
        if LLM_PROVIDER != "ollama" or self.fake_llm:
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

    async def _stepup(self, request_id: str, delay: float = 2.0):
        await asyncio.sleep(delay)
        stepup_token = os.getenv("KOALA_STEPUP_TOKEN", DEFAULT_STEPUP_TOKEN)
        print(f"[*] (Back-channel) Attempting step-up for request_id: {request_id}...")
        try:
            resp = await self.client.post(
                PEP_STEPUP,
                json={"request_id": request_id, "secondary_token": stepup_token}
            )
            if resp.status_code == 200:
                print("[+] (Back-channel) Step-up successful.")
                return True
            else:
                print(f"[-] (Back-channel) Step-up failed: {resp.text}")
                return False
        except Exception as e:
            print(f"[-] (Back-channel) Step-up error: {e}")
            return False

    async def _mcp_rpc(self, method: str, params: Optional[Dict[str, Any]] = None, retry_on_challenge: bool = True) -> Dict[str, Any]:
        request_id = str(uuid.uuid4())
        self.last_request_id = request_id
        
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if "id" not in payload and not method.startswith("notifications/"):
            payload["id"] = int(datetime.now().timestamp() * 1000)

        headers = {
            "Content-Type": "application/json",
            "Accept": ACCEPT,
            "X-Koala-Subject": self.state.subject_id,
            "X-Koala-Request-Id": request_id,
        }
        if self.state.session_id:
            headers["Mcp-Session-Id"] = self.state.session_id

        # Restricted tools pattern: PDP always returns CHALLENGE on first call.
        # We start a background step-up task immediately to race the parked call.
        stepup_task = None
        is_restricted = (method == "tools/call" and params and params.get("name") == "prescribe_medication")
        if is_restricted:
            print(f"[*] Restricted tool detected. Proactively starting step-up race for {request_id}")
            stepup_task = asyncio.create_task(self._stepup(request_id, delay=1.5))

        resp = None
        try:
            # Longer timeout for restricted calls that might park
            timeout = 45.0 if is_restricted or not retry_on_challenge else 30.0
            resp = await self.client.post(PEP_MCP, json=payload, headers=headers, timeout=timeout)
        except (httpx.ReadTimeout, asyncio.TimeoutError):
            print(f"[*] Request {request_id} timed out (likely parked).")
            # If we didn't proactively start a step-up, start one now.
            if not stepup_task:
                 stepup_task = asyncio.create_task(self._stepup(request_id, delay=0.1))
            
            # Wait for stepup to complete then retry with FRESH request_id
            await stepup_task
            print(f"[*] Retrying {method} with fresh request_id...")
            return await self._mcp_rpc(method, params, retry_on_challenge=False)
            
        if resp:
            # Handle CHALLENGE (408 or JSON-RPC error)
            is_challenge = (resp.status_code == 408)
            parsed = self._parse_mcp_response(resp)
            if parsed and "error" in parsed and parsed["error"].get("code") == -32000:
                is_challenge = True
            
            if is_challenge and retry_on_challenge:
                print(f"[*] Received CHALLENGE for {method}. request_id={request_id}")
                if not stepup_task:
                    stepup_task = asyncio.create_task(self._stepup(request_id, delay=0.1))
                await stepup_task
                print(f"[*] Retrying {method} with fresh request_id...")
                return await self._mcp_rpc(method, params, retry_on_challenge=False)

            if resp.status_code == 403:
                error_msg = parsed.get("error", {}).get("message", "Unknown denial") if parsed else "Unknown denial"
                print(f"[-] DENIED by PEP: {error_msg}")
                return {"error": {"code": -32001, "message": f"DENIED: {error_msg}"}}

            resp.raise_for_status()
            if stepup_task and not stepup_task.done():
                try:
                    stepup_task.cancel()
                    await stepup_task 
                except asyncio.CancelledError:
                    pass
                except:
                    pass

            # Update session ID if provided
            new_sid = resp.headers.get("mcp-session-id")
            if new_sid:
                self.state.session_id = new_sid

            # Check for DLP redaction in the result
            if method == "tools/call" and parsed and "[REDACTED_SSN]" in json.dumps(parsed):
                print("[!] PEP DLP scrubbed SSN")
                
            return parsed or {}
        
        return {"error": {"code": -32000, "message": "Request failed or timed out"}}

    def _parse_mcp_response(self, resp: httpx.Response) -> Dict[str, Any]:
        if resp.status_code == 202 or not resp.content:
            return {}
        ctype = resp.headers.get("content-type", "")
        if ctype.startswith("application/json"):
            try:
                return resp.json()
            except json.JSONDecodeError:
                return {"raw": resp.text}
        if ctype.startswith("text/event-stream"):
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    try:
                        return json.loads(line.removeprefix("data:").strip())
                    except json.JSONDecodeError:
                        continue
            return {"raw": resp.text}
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {"raw": resp.text}

    async def initialize(self):
        print(f"[*] Initializing MCP session for subject: {self.state.subject_id}")
        await self._check_ollama_model()
        
        await self._mcp_rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "koala-llm-agent", "version": "1.0.0"},
        })
        
        await self._mcp_rpc("notifications/initialized")
        
        tools_res = await self._mcp_rpc("tools/list")
        self.state.tools = tools_res.get("result", {}).get("tools", [])
        print(f"[+] Initialized. Found {len(self.state.tools)} tools.")

    async def _llm_chat(self, messages: List[Dict[str, str]]) -> str:
        if self.fake_llm:
            # Simple heuristic for scenarios
            last_user_msg = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
            if "ibuprofen" in last_user_msg.lower():
                return '{"tool": "get_drug_interactions", "arguments": {"drug_a": "ibuprofen", "drug_b": "warfarin"}}'
            if "p001" in last_user_msg.lower() and "prescribe" not in last_user_msg.lower():
                return '{"tool": "get_patient_record", "arguments": {"patient_id": "P001"}}'
            if "prescribe" in last_user_msg.lower():
                return '{"tool": "prescribe_medication", "arguments": {"patient_id": "P001", "medication": "amoxicillin 500mg"}}'
            if "Tool result" in last_user_msg:
                return '{"final": "I have processed your request. The result is: ' + last_user_msg[:50] + '..."}'
            return '{"final": "I am not sure how to help with that in fake mode."}'

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
            resp = await self.client.post(url, json=payload, timeout=120.0)
            resp.raise_for_status()
            return resp.json()["message"]["content"]
        else:
            url = f"{LLM_BASE_URL}/chat/completions"
            headers = {"Authorization": f"Bearer {LLM_API_KEY}"}
            payload = {
                "model": LLM_MODEL,
                "messages": messages,
                "temperature": 0.2,
            }
            resp = await self.client.post(url, json=payload, headers=headers, timeout=120.0)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    async def run_turn(self, user_prompt: str):
        self.state.history.append({"role": "user", "content": user_prompt})
        
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
                    
                    if "error" in tool_result and tool_result["error"].get("code") == -32001:
                         print(f"[-] ReAct loop terminated: {tool_result['error']['message']}")
                         return

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

async def run_scenario(agent: KoalaAgent, scenario: str):
    if scenario == "a":
        print("\n=== Scenario A: Public tier (get_drug_interactions) ===")
        await agent.run_turn("What's the interaction between ibuprofen and warfarin?")
    elif scenario == "b":
        print("\n=== Scenario B: Internal tier (get_patient_record + DLP) ===")
        await agent.run_turn("Pull the record for patient P001.")
    elif scenario == "c":
        print("\n=== Scenario C: Restricted tier (prescribe_medication + step-up) ===")
        await agent.run_turn("Prescribe amoxicillin 500mg for patient P001.")
    elif scenario == "d":
        print("\n=== Scenario D: Stress (rapid get_drug_interactions) ===")
        for i in range(10):
            print(f"\n--- Rapid call #{i+1} ---")
            await agent._mcp_rpc("tools/call", {"name": "get_drug_interactions", "arguments": {"drug_a": "aspirin", "drug_b": "warfarin"}})
    elif scenario == "all":
        # For 'all', we use different subject IDs per scenario to avoid rate-limit bleed-over
        base_subject = agent.state.subject_id
        for s in ["a", "b", "c", "d"]:
            agent.state.subject_id = f"{base_subject}-{s}-{uuid.uuid4().hex[:4]}"
            # Clear history and session for clean run
            agent.state.history = []
            agent.state.session_id = None
            await agent.initialize() 
            await run_scenario(agent, s)

async def repl():
    subject = os.getenv("KOALA_SUBJECT", DEFAULT_SUBJECT_ID)
    agent = KoalaAgent(subject)
    try:
        await agent.initialize()
        print("\n--- Koala Healthcare ZTA Agent REPL ---")
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

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", help="Run a single prompt and exit")
    parser.add_argument("--scenario", choices=["a", "b", "c", "d", "all"], help="Run a canned scenario")
    parser.add_argument("--subject", help="Set X-Koala-Subject")
    parser.add_argument("--fake", action="store_true", help="Use fake LLM mode for testing")
    args = parser.parse_args()

    if args.subject:
        os.environ["KOALA_SUBJECT"] = args.subject

    subject = os.getenv("KOALA_SUBJECT", DEFAULT_SUBJECT_ID)
    agent = KoalaAgent(subject, fake_llm=args.fake)

    async def run():
        try:
            if args.scenario:
                await run_scenario(agent, args.scenario)
            elif args.prompt:
                await agent.initialize()
                await agent.run_turn(args.prompt)
            else:
                # Need to manually close because repl() has its own try/finally
                await agent.close()
                await repl()
                return
        finally:
            await agent.close()

    if args.scenario or args.prompt:
        asyncio.run(run())
    else:
        asyncio.run(repl())
