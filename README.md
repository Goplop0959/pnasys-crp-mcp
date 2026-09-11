# pnasys-crp-mcp — MCP server for PNASystems CRP (OpenCode)

Lets an AI client drive a Raspberry Pi through the PNA Vercel API over an
end-to-end encrypted channel: the AI supplies the Pi's `api_key` and the
shared `encryption_key`, the op is encrypted locally with
`pnasys-encryption-service`, and the Pi decrypts it with the channel key
from `pnasyscrp setup`.

## Install

```bash
pip install pnasys-crp-mcp
# then run from PATH:
pnasys-crp-mcp
```

Or without installing, via uvx:

```bash
uvx pnasys-crp-mcp
```

## OpenCode config (`opencode.json`)

```json
{
  "mcp": {
    "pnasys-crp": {
      "type": "local",
      "command": ["uvx", "pnasys-crp-mcp"],
      "enabled": true
    }
  }
}
```

With a PATH install instead: `"command": ["pnasys-crp-mcp"]`.
Override the API base with `PNASYS_VERCEL_BASE` env (default production).

## Tools

- `pi_secure_exec(api_key, encryption_key, cmd, wait_s)` — run shell
- `pi_secure_read(api_key, encryption_key, path, wait_s)` — read file
- `pi_secure_write(api_key, encryption_key, path, data_b64, wait_s)` — write file
- `pi_secure_install(api_key, encryption_key, pkg, wait_s)` — apt install
- `pi_fetch_result(api_key, request_id)` — collect a pending response
- `pi_health()` — API reachability

Each call encrypts, enqueues a `secure` job, waits for the Pi (long-poll),
and returns the result. Nothing secret is logged; keys stay parameters.
