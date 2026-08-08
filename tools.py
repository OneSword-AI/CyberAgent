"""Tool adapter interface — stub implementations only (MVP).

Real scanners / integrations would implement the same interface.
Every tool method must call l0_check before touching anything external.
"""
from __future__ import annotations
from typing import Any
from safety import ActionRequest, ActionType, SafetyVerdict, l0_check


class ToolResult:
    def __init__(self, success: bool, data: Any, error: str = ""):
        self.success = success
        self.data = data
        self.error = error

    def __repr__(self) -> str:
        if self.success:
            return f"ToolResult(ok, data={self.data!r})"
        return f"ToolResult(error={self.error!r})"


class ToolAdapter:
    """Stub adapter — no real I/O, all results are synthetic."""

    def __init__(self, actor_id: str):
        self.actor_id = actor_id

    def _gate(self, action_type: ActionType, target: str, params: dict) -> SafetyVerdict:
        req = ActionRequest(action_type=action_type, actor=self.actor_id,
                            target=target, params=params)
        verdict = l0_check(req)
        if not verdict.allowed:
            print(f"  [L0 BLOCK] {self.actor_id} → {action_type} on {target!r}: {verdict.reason}")
        return verdict

    def read_file(self, path: str) -> ToolResult:
        v = self._gate(ActionType.READ_FILE, path, {})
        if not v.allowed:
            return ToolResult(False, None, v.reason)
        # Stub — return synthetic content
        return ToolResult(True, f"<stub content of {path}>")

    def scan_port(self, host: str, port: int) -> ToolResult:
        v = self._gate(ActionType.SCAN_PORT, host, {"port": port})
        if not v.allowed:
            return ToolResult(False, None, v.reason)
        # Stub — would call real scanner in production
        return ToolResult(True, {"host": host, "port": port, "state": "stub/unknown"})

    def execute(self, cmd: str) -> ToolResult:
        v = self._gate(ActionType.EXECUTE_CMD, cmd, {})
        if not v.allowed:
            return ToolResult(False, None, v.reason)
        return ToolResult(True, f"<stub exec: {cmd}>")

    def network_get(self, url: str) -> ToolResult:
        v = self._gate(ActionType.NETWORK_CALL, url, {})
        if not v.allowed:
            return ToolResult(False, None, v.reason)
        try:
            import requests
            resp = requests.get(url, timeout=10, allow_redirects=True)
            return ToolResult(True, {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "content_length": len(resp.content),
                "text": resp.text[:500] if resp.text else None,
                "url": resp.url
            })
        except Exception as e:
            return ToolResult(False, None, str(e))
