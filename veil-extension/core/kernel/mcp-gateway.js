/**
 * VEIL v2.4 — Zero-Trust Model Context Protocol (MCP) Tool Security Gateway
 *
 * Implements Pillar R7: Autonomous Agent-to-Tool Mediation.
 *
 * Architecture:
 *   AGENT ➔ MCP JSON-RPC ➔ VEIL GATEWAY ➔ TAINT CHECK ➔ CAPABILITY CHECK ➔ PRE-STATE COMMITMENT ➔ EXECUTION ➔ RECEIPT
 */

(function () {
  const crypto = typeof require !== 'undefined' ? require('crypto') : null;

  function sha256(data) {
    const str = typeof data === 'string' ? data : JSON.stringify(data);
    if (crypto) {
      return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
    }
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(64, '0');
  }

  const MCP_TIERS = {
    TIER_0_READ_ONLY: 0,
    TIER_1_SANDBOXED: 1,
    TIER_2_STATE_ALTERING: 2,
    TIER_3_CRITICAL_EXECUTION: 3
  };

  const DEFAULT_TOOLS = {
    'read_file': { tier: MCP_TIERS.TIER_0_READ_ONLY, requiresStateCheck: false },
    'list_dir': { tier: MCP_TIERS.TIER_0_READ_ONLY, requiresStateCheck: false },
    'grep_search': { tier: MCP_TIERS.TIER_0_READ_ONLY, requiresStateCheck: false },
    'create_scratch_file': { tier: MCP_TIERS.TIER_1_SANDBOXED, requiresStateCheck: false },
    'write_file': { tier: MCP_TIERS.TIER_2_STATE_ALTERING, requiresStateCheck: true },
    'database_update': { tier: MCP_TIERS.TIER_2_STATE_ALTERING, requiresStateCheck: true },
    'execute_command': { tier: MCP_TIERS.TIER_3_CRITICAL_EXECUTION, requiresStateCheck: true },
    'shell_exec': { tier: MCP_TIERS.TIER_3_CRITICAL_EXECUTION, requiresStateCheck: true },
    'delete_resource': { tier: MCP_TIERS.TIER_3_CRITICAL_EXECUTION, requiresStateCheck: true }
  };

  class ZeroTrustMcpGateway {
    constructor(options = {}) {
      this.tools = new Map(Object.entries(DEFAULT_TOOLS));
      this.consumedNonces = new Set();
      this.toolLedger = [];
      this.secret = options.secret || 'VEIL_MCP_GATEWAY_SECRET_339182';
      this.handlers = new Map();
    }

    /**
     * Registers or updates a tool policy in the gateway.
     */
    registerTool(toolName, definition) {
      this.tools.set(toolName, {
        tier: definition.tier ?? MCP_TIERS.TIER_2_STATE_ALTERING,
        requiresStateCheck: !!definition.requiresStateCheck,
        handler: definition.handler || null
      });
    }

    /**
     * Registers an execution handler for mock or live tool dispatch.
     */
    setHandler(toolName, handlerFn) {
      this.handlers.set(toolName, handlerFn);
    }

    /**
     * Mediates an incoming MCP tool call.
     *
     * @param {Object} callRequest
     *   - toolName: string
     *   - arguments: object
     *   - caller: { agentId, origin }
     *   - capabilityToken: object (optional for Tier 0, required for Tier >= 1)
     *   - taintTags: string[]
     *   - preStateHash: string
     *   - currentStateHash: string
     * @returns {Object} Mediation verdict and execution outcome / receipt
     */
    mediateToolCall(callRequest) {
      const {
        toolName,
        arguments: args = {},
        caller = { agentId: 'anonymous_agent', origin: 'unknown' },
        capabilityToken,
        taintTags = [],
        preStateHash,
        currentStateHash
      } = callRequest;

      // 1. Tool Lookup
      const toolDef = this.tools.get(toolName);
      if (!toolDef) {
        return {
          status: 'BLOCKED',
          error: 'ERR_UNKNOWN_TOOL',
          reason: `Tool '${toolName}' is not registered in VEIL MCP Security Gateway`
        };
      }

      // 2. Taint Boundary Enforcement
      const isTainted = taintTags.some(t =>
        t === 'TAINT_UNTRUSTED_DOM' ||
        t === 'TAINT_INDIRECT_PROMPT' ||
        t === 'TAINT_REMOTE_CONTENT'
      );

      if (isTainted && toolDef.tier >= MCP_TIERS.TIER_2_STATE_ALTERING) {
        return {
          status: 'BLOCKED',
          error: 'ERR_TAINT_PROPAGATION_DETECTED',
          reason: `Tainted input cannot invoke Tier ${toolDef.tier} tool '${toolName}'`
        };
      }

      // 3. Capability Token Verification (Required for Tier >= 1)
      if (toolDef.tier >= MCP_TIERS.TIER_1_SANDBOXED) {
        if (!capabilityToken) {
          return {
            status: 'BLOCKED',
            error: 'ERR_MISSING_CAPABILITY_TOKEN',
            reason: `Tier ${toolDef.tier} tool '${toolName}' requires an authorized Capability Token`
          };
        }

        if (capabilityToken.targetTool && capabilityToken.targetTool !== toolName) {
          return {
            status: 'BLOCKED',
            error: 'ERR_CAPABILITY_TOOL_MISMATCH',
            reason: `Capability minted for '${capabilityToken.targetTool}', not '${toolName}'`
          };
        }

        if (capabilityToken.expiresAt && Date.now() > capabilityToken.expiresAt) {
          return {
            status: 'BLOCKED',
            error: 'ERR_CAPABILITY_EXPIRED',
            reason: 'Capability token has expired'
          };
        }

        if (this.consumedNonces.has(capabilityToken.nonce)) {
          return {
            status: 'BLOCKED',
            error: 'ERR_TOKEN_REPLAY',
            reason: `Capability nonce '${capabilityToken.nonce}' already consumed`
          };
        }
      }

      // 4. Pre-State Commitment Binding (TOCTOU guard)
      if (toolDef.requiresStateCheck && preStateHash && currentStateHash) {
        if (preStateHash !== currentStateHash) {
          return {
            status: 'BLOCKED',
            error: 'ERR_STATE_DESYNCHRONIZATION',
            reason: `Target state changed between authorization (${preStateHash.slice(0, 8)}) and execution (${currentStateHash.slice(0, 8)})`
          };
        }
      }

      // 5. Tier 3 Out-of-band Confirmation Requirement
      if (toolDef.tier === MCP_TIERS.TIER_3_CRITICAL_EXECUTION && !callRequest.userConfirmation) {
        return {
          status: 'CONFIRM_REQUIRED',
          error: 'ERR_REQUIRES_EXPLICIT_CONFIRMATION',
          reason: `Tier 3 critical tool '${toolName}' requires out-of-band user approval`
        };
      }

      // Record consumed nonce if capability was provided
      if (capabilityToken && capabilityToken.nonce) {
        this.consumedNonces.add(capabilityToken.nonce);
      }

      // 6. Execution Dispatch
      let executionOutput = { executed: true, result: 'SUCCESS' };
      const handler = this.handlers.get(toolName) || toolDef.handler;
      if (typeof handler === 'function') {
        try {
          executionOutput = handler(args);
        } catch (err) {
          executionOutput = { executed: false, error: err.message };
        }
      }

      // 7. Post-State Hash & Non-repudiable Action Receipt
      const postStateHash = sha256({ preStateHash, result: executionOutput });
      const receiptId = `mcp_rec_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const receipt = {
        receiptId,
        schema: 'veil.mcp_receipt/v1',
        timestamp: Date.now(),
        toolName,
        caller,
        tier: toolDef.tier,
        preStateHash: preStateHash || null,
        postStateHash,
        argumentsHash: sha256(args),
        status: executionOutput.error ? 'FAILED' : 'SUCCESS',
        integritySignature: sha256(`${receiptId}:${toolName}:${postStateHash}:${this.secret}`)
      };

      this.toolLedger.push(receipt);

      return {
        status: 'ALLOWED',
        output: executionOutput,
        receipt
      };
    }

    /**
     * Verifies an MCP tool receipt offline.
     */
    verifyToolReceipt(receipt) {
      if (!receipt || !receipt.receiptId || !receipt.integritySignature) {
        return { valid: false, error: 'ERR_MALFORMED_RECEIPT' };
      }
      const expectedSig = sha256(`${receipt.receiptId}:${receipt.toolName}:${receipt.postStateHash}:${this.secret}`);
      if (receipt.integritySignature !== expectedSig) {
        return { valid: false, error: 'ERR_INVALID_SIGNATURE' };
      }
      return { valid: true, receiptId: receipt.receiptId, toolName: receipt.toolName };
    }
  }

  const defaultGateway = new ZeroTrustMcpGateway();

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      ZeroTrustMcpGateway,
      MCP_TIERS,
      defaultGateway
    };
  }

  if (typeof window !== 'undefined') {
    window.VeilMcpGateway = {
      ZeroTrustMcpGateway,
      MCP_TIERS,
      defaultGateway
    };
  }
})();
