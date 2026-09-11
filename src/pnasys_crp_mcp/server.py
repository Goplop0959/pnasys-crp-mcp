"""MCP server exposing the PNASystems CRP Pi remote to AI clients (OpenCode).

Transport: stdio. NEVER write to stdout (protocol channel) — logging goes
to stderr only.

Every tool takes the Pi's api_key and the shared session_key as explicit
parameters. The op is encrypted locally with pnasys-encryption-service and
sent to the Vercel API as an opaque secure job; the Pi decrypts it with the
channel key from `pnasyscrp setup`. Raw keys are never logged or echoed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

BASE = os.environ.get("PNASYS_VERCEL_BASE", "https://pnasys-crp-api.vercel.app")

try:
    from mcp.server import MCPServer  # SDK >= 2.0
    _SERVER_CLS = MCPServer
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as _SERVER_CLS  # type: ignore[no-redef]

mcp = _SERVER_CLS("pnasys-crp")


def _ident(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _http(method: str, path: str, body: dict | None = None, timeout: int = 60) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE.rstrip("/") + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return {"_http_error": e.code, **json.loads(e.read().decode()[:500])}
        except Exception:
            return {"_http_error": e.code, "error": "http error"}


def _submit_and_wait(api_key: str, session_key: str, op: dict,
                     wait_s: int = 120) -> str:
    """Encrypt op, enqueue as secure job, wait for the Pi's response."""
    from pnasys_encryption_service import DecryptString, EncryptString

    blob = EncryptString(json.dumps(op, separators=(",", ":")), session_key)
    r = _http("POST", "/api/request", {"access_key": api_key, "kind": "secure",
                                       "blob": blob, "id": op.get("id") or
                                       f"mcp{int(time.time() * 1000)}"})
    if not r.get("ok"):
        return json.dumps({"ok": False, "stage": "request", "error": r.get("error", "unknown")})
    rid = r["id"]
    ident = _ident(api_key)
    deadline = time.time() + max(5, min(wait_s, 300))
    while time.time() < deadline:
        time.sleep(5)
        res = _http("GET", f"/api/result?ident={ident}&id={rid}", timeout=60)
        if res.get("pending"):
            continue
        if res.get("_http_error") or "enc" not in res:
            return json.dumps({"ok": False, "stage": "result", "error": res})
        try:
            inner = json.loads(DecryptString(str(res["enc"]), session_key))
        except Exception:
            return json.dumps({"ok": False, "stage": "decrypt",
                               "error": "response decrypt failed (wrong session key?)"})
        inner.pop("ts", None)
        return json.dumps({"ok": True, "id": rid, "result": inner})
    return json.dumps({"ok": False, "stage": "timeout", "id": rid,
                       "hint": "Pi may be offline or idle-disabled; use pi_fetch_result to retry later"})


if mcp is not None:

    @mcp.tool()
    def pi_secure_exec(api_key: str, session_key: str, cmd: str, wait_s: int = 120) -> str:
        """Run a shell command on the Pi via the encrypted channel.

        Args:
            api_key: the Pi's access key (from setup/enable)
            session_key: session key printed by `pnasyscrp enable` (from Pi setup)
            cmd: shell command to run
            wait_s: seconds to wait for the Pi (default 120)
        """
        return _submit_and_wait(api_key, session_key, {"kind": "exec", "cmd": cmd[:4000]}, wait_s)

    @mcp.tool()
    def pi_secure_read(api_key: str, session_key: str, path: str, wait_s: int = 120) -> str:
        """Read a file from the Pi via the encrypted channel.

        Args:
            api_key: the Pi's access key
            session_key: session key printed by `pnasyscrp enable`
            path: absolute path on the Pi
            wait_s: seconds to wait (default 120)
        """
        return _submit_and_wait(api_key, session_key, {"kind": "read", "path": path[:1024]}, wait_s)

    @mcp.tool()
    def pi_secure_write(api_key: str, session_key: str, path: str, data_b64: str,
                        wait_s: int = 120) -> str:
        """Write a file on the Pi via the encrypted channel.

        Args:
            api_key: the Pi's access key
            session_key: session key printed by `pnasyscrp enable`
            path: absolute destination path on the Pi
            data_b64: base64-encoded file bytes
            wait_s: seconds to wait (default 120)
        """
        return _submit_and_wait(api_key, session_key,
                                {"kind": "write", "path": path[:1024], "data_b64": data_b64}, wait_s)

    @mcp.tool()
    def pi_secure_install(api_key: str, session_key: str, pkg: str, wait_s: int = 300) -> str:
        """Install an apt package on the Pi via the encrypted channel.

        Args:
            api_key: the Pi's access key
            session_key: session key printed by `pnasyscrp enable`
            pkg: apt package name
            wait_s: seconds to wait (default 300)
        """
        return _submit_and_wait(api_key, session_key, {"kind": "install", "pkg": pkg[:256]}, wait_s)

    @mcp.tool()
    def pi_fetch_result(api_key: str, session_key: str, request_id: str) -> str:
        """Fetch (and collect) a pending Pi response by request id.

        Args:
            api_key: the Pi's access key
            session_key: session key printed by `pnasyscrp enable`
            request_id: id returned by an earlier call
        """
        from pnasys_encryption_service import DecryptString

        res = _http("GET", f"/api/result?ident={_ident(api_key)}&id={request_id}")
        if res.get("pending") or res.get("_http_error") or "enc" not in res:
            return json.dumps(res)
        try:
            inner = json.loads(DecryptString(str(res["enc"]), session_key))
        except Exception:
            return json.dumps({"ok": False, "error": "response decrypt failed"})
        inner.pop("ts", None)
        return json.dumps(inner)

    @mcp.tool()
    def pi_health() -> str:
        """Check the Vercel API is reachable."""
        return json.dumps(_http("GET", "/api/health", timeout=20))


def main() -> None:
    if mcp is None:
        print("missing dependency: pip install mcp pnasys-encryption-service", file=sys.stderr)
        raise SystemExit(2)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
