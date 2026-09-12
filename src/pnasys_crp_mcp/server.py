"""MCP server exposing the PNASystems CRP Pi remote to AI clients (OpenCode).

Transport: hand-rolled MCP stdio (newline-delimited JSON-RPC) with ZERO
protocol dependencies — only stdlib + pnasys-encryption-service. This is
deliberate: the `mcp` package hard-imports pywin32 on Windows, whose DLLs
don't load inside uvx/pipx isolated envs (ImportError:
_win32sysloader), which is exactly what made clients report the server as
failed. stdlib-only transport cannot break that way.

NEVER write to stdout except protocol replies — logging goes to stderr.

Every tool takes the per-enable session_key (you paste it to the AI) and
the Pi's api_key (printed once by `pnasyscrp setup`, bakable via
--AccessKey). Ops are encrypted locally with pnasys-encryption-service;
the Pi decrypts, encrypts its response the same way, and we decrypt it.
Vercel only stores blobs. Raw keys are never logged or echoed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request

from pnasys_crp_mcp import __version__

logger = logging.getLogger(__name__)

BASE = os.environ.get("PNASYS_VERCEL_BASE", "https://pnasys-crp-api.vercel.app")
DEFAULT_API_KEY = ""


def _ident(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _key(api_key: str) -> str:
    """Tool-call key, falling back to the --AccessKey launch default."""
    return api_key or DEFAULT_API_KEY


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

    api_key = _key(api_key)

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


def _fetch(api_key: str, session_key: str, request_id: str) -> str:
    from pnasys_encryption_service import DecryptString

    api_key = _key(api_key)
    res = _http("GET", f"/api/result?ident={_ident(api_key)}&id={request_id}")
    if res.get("pending") or res.get("_http_error") or "enc" not in res:
        return json.dumps(res)
    try:
        inner = json.loads(DecryptString(str(res["enc"]), session_key))
    except Exception:
        return json.dumps({"ok": False, "error": "response decrypt failed"})
    inner.pop("ts", None)
    return json.dumps(inner)


def _tool_pi_secure_exec(a: dict) -> str:
    return _submit_and_wait(str(a.get("api_key", "")), str(a.get("session_key", "")),
                            {"kind": "exec", "cmd": str(a.get("cmd", ""))[:4000]},
                            int(a.get("wait_s", 120) or 120))


def _tool_pi_secure_read(a: dict) -> str:
    return _submit_and_wait(str(a.get("api_key", "")), str(a.get("session_key", "")),
                            {"kind": "read", "path": str(a.get("path", ""))[:1024]},
                            int(a.get("wait_s", 120) or 120))


def _tool_pi_secure_write(a: dict) -> str:
    return _submit_and_wait(str(a.get("api_key", "")), str(a.get("session_key", "")),
                            {"kind": "write", "path": str(a.get("path", ""))[:1024],
                             "data_b64": str(a.get("data_b64", ""))},
                            int(a.get("wait_s", 120) or 120))


def _tool_pi_secure_install(a: dict) -> str:
    return _submit_and_wait(str(a.get("api_key", "")), str(a.get("session_key", "")),
                            {"kind": "install", "pkg": str(a.get("pkg", ""))[:256]},
                            int(a.get("wait_s", 300) or 300))


def _tool_pi_fetch_result(a: dict) -> str:
    return _fetch(str(a.get("api_key", "")), str(a.get("session_key", "")),
                  str(a.get("request_id", "")))


def _tool_pi_health(a: dict) -> str:
    return json.dumps(_http("GET", "/api/health", timeout=20))


_HANDLERS = {
    "pi_secure_exec": _tool_pi_secure_exec,
    "pi_secure_read": _tool_pi_secure_read,
    "pi_secure_write": _tool_pi_secure_write,
    "pi_secure_install": _tool_pi_secure_install,
    "pi_fetch_result": _tool_pi_fetch_result,
    "pi_health": _tool_pi_health,
}

_API_KEY_PROP = {"type": "string",
                 "description": "Pi access key (empty = use --AccessKey default)"}
_SESSION_PROP = {"type": "string",
                 "description": "Session key printed by `pnasyscrp enable`"}
_WAIT_PROP = {"type": "integer", "description": "Seconds to wait for the Pi",
              "default": 120}

TOOLS = [
    {"name": "pi_secure_exec",
     "description": "Run a shell command on the Pi via the encrypted channel.",
     "inputSchema": {"type": "object",
                     "properties": {"api_key": _API_KEY_PROP, "session_key": _SESSION_PROP,
                                    "cmd": {"type": "string", "description": "Shell command"},
                                    "wait_s": _WAIT_PROP},
                     "required": ["session_key", "cmd"]}},
    {"name": "pi_secure_read",
     "description": "Read a file from the Pi via the encrypted channel.",
     "inputSchema": {"type": "object",
                     "properties": {"api_key": _API_KEY_PROP, "session_key": _SESSION_PROP,
                                    "path": {"type": "string", "description": "Absolute Pi path"},
                                    "wait_s": _WAIT_PROP},
                     "required": ["session_key", "path"]}},
    {"name": "pi_secure_write",
     "description": "Write a file on the Pi via the encrypted channel.",
     "inputSchema": {"type": "object",
                     "properties": {"api_key": _API_KEY_PROP, "session_key": _SESSION_PROP,
                                    "path": {"type": "string", "description": "Destination path"},
                                    "data_b64": {"type": "string", "description": "Base64 file bytes"},
                                    "wait_s": _WAIT_PROP},
                     "required": ["session_key", "path", "data_b64"]}},
    {"name": "pi_secure_install",
     "description": "Install an apt package on the Pi via the encrypted channel.",
     "inputSchema": {"type": "object",
                     "properties": {"api_key": _API_KEY_PROP, "session_key": _SESSION_PROP,
                                    "pkg": {"type": "string", "description": "apt package name"},
                                    "wait_s": {"type": "integer", "default": 300}},
                     "required": ["session_key", "pkg"]}},
    {"name": "pi_fetch_result",
     "description": "Fetch (and collect) a pending Pi response by request id.",
     "inputSchema": {"type": "object",
                     "properties": {"api_key": _API_KEY_PROP, "session_key": _SESSION_PROP,
                                    "request_id": {"type": "string"}},
                     "required": ["session_key", "request_id"]}},
    {"name": "pi_health",
     "description": "Check the Vercel API is reachable.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _reply(mid, result=None, error=None) -> None:
    msg: dict = {"jsonrpc": "2.0", "id": mid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result if result is not None else {}
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _serve() -> None:
    inp = sys.stdin.buffer
    out_closed = False
    while True:
        try:
            line = inp.readline()
        except Exception:
            return
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line.decode("utf-8"))
        except Exception:
            continue
        method = msg.get("method", "")
        mid = msg.get("id")
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                _reply(mid, {"protocolVersion": "2024-11-05",
                             "capabilities": {"tools": {}},
                             "serverInfo": {"name": "pnasys-crp", "version": __version__}})
            elif method in ("notifications/initialized", "notifications/cancelled"):
                pass  # no reply for notifications
            elif method == "ping":
                _reply(mid, {})
            elif method == "tools/list":
                _reply(mid, {"tools": TOOLS})
            elif method == "tools/call":
                name = (params.get("name") or "")
                handler = _HANDLERS.get(name)
                if handler is None:
                    _reply(mid, error={"code": -32602, "message": f"unknown tool: {name}"})
                    continue
                try:
                    text = handler(params.get("arguments") or {})
                except Exception as e:
                    logger.exception("tool failed")
                    text = json.dumps({"ok": False, "error": "tool failed"})
                _reply(mid, {"content": [{"type": "text", "text": text}]})
            elif mid is None:
                pass
            else:
                _reply(mid, error={"code": -32601, "message": f"unknown method: {method}"})
        except (BrokenPipeError, ValueError):
            out_closed = True
            return
        except Exception:
            logger.exception("dispatch failed")
            if mid is not None and not out_closed:
                try:
                    _reply(mid, error={"code": -32603, "message": "internal error"})
                except Exception:
                    return


def main(argv: list[str] | None = None) -> None:
    global BASE, DEFAULT_API_KEY
    ap = argparse.ArgumentParser(description="pnasys-crp MCP server (stdio).")
    ap.add_argument("--AccessKey", default="", help="default Pi access key (printed by pnasyscrp setup)")
    ap.add_argument("--VercelBase", default="", help="override API base (default production)")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    args = ap.parse_args(argv)
    if args.version:
        print(__version__)
        return
    if args.AccessKey:
        DEFAULT_API_KEY = args.AccessKey
    if args.VercelBase:
        BASE = args.VercelBase
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    _serve()


if __name__ == "__main__":
    main()
