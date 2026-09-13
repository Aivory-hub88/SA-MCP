# SA-MCP — SAP MCP Server (Rust)

Rust MCP server untuk SAP S/4HANA via **OData V2/V4**, kompatibel **Python MCP clients**.
Format sama dengan Od-MCP (transport, tenant isolation, gated-write, field-ACL, rate limit);
referensi SAP: `lemaiwo/btp-sap-odata-to-mcp-server` (132★, pola hierarkis) +
`fr0ster/mcp-abap-adt` (89★, auth-broker + gated exposition) +
`Jack-Liang/sap-for-agents` (Rust NWRFC, untuk fase RFC nanti).

## Transports

| Transport | Cara jalan | Endpoint |
|---|---|---|
| `stdio` | `sa-mcp --transport stdio` | stdin/stdout |
| `streamable-HTTP` | `sa-mcp --transport http --listen 127.0.0.1:8788` | `POST/GET/DELETE /mcp` |
| `SSE (legacy)` | sama | `GET /sse` + `POST /messages?sessionId=` |
| `WebSocket` | `sa-mcp --transport ws` | WS text frames JSON-RPC |
| util | — | `GET /health`, `GET /openapi.json` |

## Pola tools (hierarkis, hemat token)

1. `sap_discover` (L1) — entity sets dari `$metadata` (cached)
2. `sap_entity_metadata` (L2) — properties/keys/capabilities satu entity
3. `sap_read` / `sap_read_one` (L3) — query (`$filter/$select/$expand/$orderby/$top/$skip/$count`)

## Gated-write (kombinasi env-flag + token + audit)

`sap_preview_write → sap_validate_write (live $metadata: unknown_property, keys_required, creatable/updatable/deletable) → sap_execute_approved_write {approval, confirm:true}`, hanya jika `SAP_MCP_ENABLE_WRITES=1`. Token `sap-write:…` single-use TTL 600s, instance-bound. Update kirim `If-Match: *` kecuali ETag diberikan. V2 otomatis fetch `X-CSRF-Token`.

## Kontrol akses & safety (dari 3 referensi)

- **Exposition** (`SAP_EXPOSITION=readonly|high`, ala fr0ster): `readonly` sembunyikan semua write tools. Prod: `readonly`.
- **Entity allow/deny** (`SAP_ENTITY_ALLOW/DENY`, glob `*`, deny menang — ala lemaiwo patterns). Dicek sebelum fetch metadata.
- **Query caps**: `$filter` ≤ 2000 char, `$select` ≤ 50 field, `$expand` ≤ 5 item, `$top` ≤ 200.
- **Edm-aware keys**: key segment diformat dari tipe live `$metadata` (String/Guid/Date quoted, Int/Bool raw, Decimal `M`, Double `d`).
- **Auth override per-request** (`auth_username/auth_password/auth_token`): hanya tenant Full + `SAP_MCP_ALLOW_AUTH_OVERRIDE=1`; tidak pernah di-log.
- **Tenant isolation, rate limit, field-ACL, audit**: sama dengan Od-MCP. `GET /metrics` (Prometheus: calls per op + sessions).

## Auth SAP

`basic` (user/pass + `sap-client`), `bearer` (JWT), `oauth2` (client-credentials).
Multi-system via `SAP_INSTANCES_JSON`; per-tenant `mcpToken`; `MCP_AUTH_TOKEN` = admin.

## Quickstart

```bash
cp .env.example .env
cargo run -- --validate-config
cargo run -- --transport stdio
```
