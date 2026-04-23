"""Pydantic v2 models for JSON-RPC 2.0.

Spec: https://www.jsonrpc.org/specification
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

JsonRpcId = str | int | None


class JsonRpcRequest(BaseModel):
    """A JSON-RPC 2.0 request (or notification, when ``id`` is omitted)."""

    model_config = ConfigDict(extra="forbid")

    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: dict[str, Any] | list[Any] | None = None
    id: JsonRpcId = None


class JsonRpcError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: int
    message: str
    data: Any | None = None


class JsonRpcResponse(BaseModel):
    """A JSON-RPC 2.0 response. Exactly one of ``result`` / ``error`` is set."""

    model_config = ConfigDict(extra="forbid")

    jsonrpc: Literal["2.0"] = "2.0"
    id: JsonRpcId = None
    result: Any | None = None
    error: JsonRpcError | None = None

    @classmethod
    def ok(cls, id: JsonRpcId, result: Any) -> "JsonRpcResponse":
        return cls(id=id, result=result)

    @classmethod
    def fail(
        cls, id: JsonRpcId, code: int, message: str, data: Any | None = None
    ) -> "JsonRpcResponse":
        return cls(id=id, error=JsonRpcError(code=code, message=message, data=data))


class JsonRpcErrorCode:
    """Standard JSON-RPC 2.0 error codes."""

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
