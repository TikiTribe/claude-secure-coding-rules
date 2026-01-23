# Model Context Protocol (MCP) Security Rules

Security rules for Claude Code when working with Model Context Protocol (MCP) systems.

## Overview

**Standard**: OWASP MCP Top 10:2025
**Scope**: MCP servers, clients, tools, and agent integrations
**Risk Profile**: Token exposure, privilege escalation, tool poisoning, prompt injection

The Model Context Protocol (MCP) enables AI assistants to securely connect with tools, data sources, and services. However, MCP introduces unique security challenges around token management, context isolation, tool integrity, and autonomous agent actions.

---

## MCP01:2025 - Token Mismanagement & Secret Exposure

**Risk Level**: Critical
**CWE Coverage**: CWE-798, CWE-522, CWE-312

### Rule: Never Hardcode Credentials in MCP Configurations

**Level**: `strict`

**When**: Configuring MCP servers, clients, or tools that require authentication.

**Do**:
```typescript
// MCP Server - Use environment variables and secret managers
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({
  name: "secure-server",
  version: "1.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

// Load credentials from environment at runtime
const API_KEY = process.env.GITHUB_TOKEN;
if (!API_KEY) {
  throw new Error("GITHUB_TOKEN environment variable required");
}

// Use short-lived tokens with least privilege
const octokit = new Octokit({
  auth: API_KEY,
  // Token should have minimal scopes (e.g., repo:read only)
});
```

**Don't**:
```typescript
// VULNERABLE: Hardcoded credentials in source code
const server = new Server({
  name: "insecure-server",
  version: "1.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

// VULNERABLE: Token in code
const octokit = new Octokit({
  auth: "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
});

// VULNERABLE: Credentials in config file checked into git
const config = {
  apiKey: "sk-1234567890",
  databaseUrl: "postgresql://user:password@localhost/db"
};
```

**Why**: MCP systems often have long-lived sessions where tokens can leak through logs, context memory, or prompt injection attacks. Hardcoded credentials enable complete environment compromise.

**Refs**: OWASP MCP01:2025, CWE-798, CWE-522, NIST SP 800-204A

---

### Rule: Redact Secrets from Logs and Context

**Level**: `strict`

**When**: Logging MCP operations, storing context, or maintaining conversation history.

**Do**:
```python
import re
import logging
from typing import Any, Dict

# Secret patterns to redact
SECRET_PATTERNS = [
    (re.compile(r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}'), 'GITHUB_TOKEN'),
    (re.compile(r'sk-[A-Za-z0-9]{48}'), 'OPENAI_KEY'),
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'), 'BEARER_TOKEN'),
    (re.compile(r'"password"\s*:\s*"[^"]*"'), '"password":"[REDACTED]"'),
]

def redact_secrets(text: str) -> str:
    """Remove sensitive data before logging or storing in context."""
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(f'[{replacement}_REDACTED]', redacted)
    return redacted

class SecureMCPServer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        # Redact before logging
        safe_args = redact_secrets(str(arguments))
        self.logger.info(f"Tool called: {tool_name} with args: {safe_args}")
        
        result = await self.execute_tool(tool_name, arguments)
        
        # Redact result before storing in context
        safe_result = redact_secrets(str(result))
        return safe_result
    
    async def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        # Implementation
        pass
```

**Don't**:
```python
# VULNERABLE: Raw logging exposes secrets
class InsecureMCPServer:
    async def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        # VULNERABLE: Logs may contain tokens
        print(f"Tool: {tool_name}, Args: {arguments}")
        
        result = await self.execute_tool(tool_name, arguments)
        
        # VULNERABLE: Full result stored in context memory
        self.context_history.append({
            "tool": tool_name,
            "args": arguments,  # May contain secrets
            "result": result    # May contain secrets
        })
        return result
```

**Why**: Secrets in logs or context memory can be extracted through prompt injection ("show me your configuration"), log scraping, or context recall attacks.

**Refs**: OWASP MCP01:2025, CWE-532, CWE-312

---

### Rule: Use Short-Lived, Scoped Tokens

**Level**: `strict`

**When**: Issuing tokens for MCP server access or tool authentication.

**Do**:
```python
from datetime import datetime, timedelta
import jwt
import secrets

class MCPTokenManager:
    def __init__(self, signing_key: str):
        self.signing_key = signing_key
    
    def issue_token(self, agent_id: str, scopes: list[str], 
                   duration_minutes: int = 30) -> str:
        """Issue short-lived, scoped token for MCP session."""
        # Token expires after session duration (max 30 minutes)
        expiry = datetime.utcnow() + timedelta(minutes=min(duration_minutes, 30))
        
        # Bind token to specific agent and scopes
        payload = {
            "sub": agent_id,
            "scopes": scopes,  # e.g., ["repo:read", "issues:write"]
            "exp": expiry,
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)  # Unique token ID
        }
        
        token = jwt.encode(payload, self.signing_key, algorithm="HS256")
        return token
    
    def validate_token(self, token: str, required_scope: str) -> dict:
        """Validate token and check scope."""
        try:
            payload = jwt.decode(token, self.signing_key, algorithms=["HS256"])
            
            # Verify scope
            if required_scope not in payload.get("scopes", []):
                raise PermissionError(f"Token lacks scope: {required_scope}")
            
            return payload
        except jwt.ExpiredSignatureError:
            raise PermissionError("Token expired")
        except jwt.InvalidTokenError:
            raise PermissionError("Invalid token")
```

**Don't**:
```python
# VULNERABLE: Long-lived tokens without expiration
class InsecureTokenManager:
    def issue_token(self, agent_id: str) -> str:
        # VULNERABLE: No expiration
        # VULNERABLE: No scope limiting
        payload = {
            "sub": agent_id,
            "admin": True  # VULNERABLE: Overly broad permissions
        }
        return jwt.encode(payload, self.signing_key, algorithm="HS256")
```

**Why**: Long-lived tokens increase attack surface. If leaked through logs or context, they provide extended unauthorized access.

**Refs**: OWASP MCP01:2025, CWE-613, RFC 8725

---

## MCP02:2025 - Privilege Escalation via Scope Creep

**Risk Level**: High
**CWE Coverage**: CWE-269, CWE-266, CWE-250

### Rule: Implement Least Privilege for MCP Tools

**Level**: `strict`

**When**: Defining tool capabilities and permissions for MCP servers.

**Do**:
```typescript
// MCP Server with granular scopes
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { z } from "zod";

const server = new Server({
  name: "github-mcp",
  version: "1.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

// Define minimal scopes per tool
server.setRequestHandler("tools/list", async () => ({
  tools: [
    {
      name: "read_issue",
      description: "Read GitHub issue (read-only)",
      inputSchema: z.object({
        owner: z.string(),
        repo: z.string(),
        issue_number: z.number()
      }),
      // Required scope: read-only
      requiredScopes: ["repo:read", "issues:read"]
    },
    {
      name: "create_issue",
      description: "Create GitHub issue (write access)",
      inputSchema: z.object({
        owner: z.string(),
        repo: z.string(),
        title: z.string(),
        body: z.string()
      }),
      // More restrictive scope for write operations
      requiredScopes: ["issues:write"]
    }
  ]
}));

// Enforce scope validation before execution
server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;
  
  // Validate token has required scopes
  const token = request.headers?.authorization?.replace("Bearer ", "");
  const scopes = await validateTokenScopes(token);
  
  const tool = getToolDefinition(name);
  if (!hasRequiredScopes(scopes, tool.requiredScopes)) {
    throw new Error(`Insufficient permissions. Required: ${tool.requiredScopes.join(", ")}`);
  }
  
  return executeTool(name, args);
});
```

**Don't**:
```typescript
// VULNERABLE: Overly broad permissions
const server = new Server({
  name: "insecure-github-mcp",
  version: "1.0.0"
});

server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;
  
  // VULNERABLE: No scope validation
  // VULNERABLE: Single token with admin access for all operations
  const octokit = new Octokit({ auth: process.env.ADMIN_TOKEN });
  
  // Any tool can perform any action
  return executeTool(name, args, octokit);
});
```

**Why**: Scope creep allows tools to accumulate excessive privileges over time. An attacker exploiting weak scope enforcement can perform unauthorized actions like repository modification or data exfiltration.

**Refs**: OWASP MCP02:2025, CWE-269, NIST SP 800-162

---

### Rule: Require Approval for High-Risk Operations

**Level**: `strict`

**When**: MCP tools perform destructive or high-impact operations.

**Do**:
```python
from enum import Enum
from typing import Optional
import asyncio

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ApprovalRequired(Exception):
    """Raised when operation requires human approval."""
    pass

class MCPToolExecutor:
    def __init__(self):
        self.pending_approvals = {}
    
    async def execute_tool(self, tool_name: str, args: dict, 
                          risk_level: RiskLevel) -> dict:
        """Execute tool with risk-based approval gates."""
        
        # High-risk operations require human approval
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            approval_id = await self.request_approval(tool_name, args, risk_level)
            
            # Wait for approval (with timeout)
            approved = await self.wait_for_approval(approval_id, timeout=300)
            if not approved:
                raise ApprovalRequired(
                    f"Operation '{tool_name}' requires approval. "
                    f"Approval ID: {approval_id}"
                )
        
        # Execute with guardrails
        return await self._execute_with_guardrails(tool_name, args)
    
    async def request_approval(self, tool_name: str, args: dict, 
                              risk_level: RiskLevel) -> str:
        """Request human-in-the-loop approval."""
        approval_id = self._generate_approval_id()
        
        # Notify human operator
        await self._send_approval_request({
            "approval_id": approval_id,
            "tool": tool_name,
            "arguments": args,
            "risk_level": risk_level.value,
            "justification": f"High-risk operation requires manual review"
        })
        
        self.pending_approvals[approval_id] = {"status": "pending"}
        return approval_id
    
    async def _execute_with_guardrails(self, tool_name: str, args: dict) -> dict:
        """Execute with runtime safety checks."""
        # Validate arguments against schema
        # Check for dangerous patterns
        # Log execution with immutable audit trail
        pass

# Tool definitions with risk levels
TOOL_REGISTRY = {
    "read_file": {"risk": RiskLevel.LOW},
    "search_code": {"risk": RiskLevel.LOW},
    "create_branch": {"risk": RiskLevel.MEDIUM},
    "merge_pr": {"risk": RiskLevel.HIGH},
    "delete_repository": {"risk": RiskLevel.CRITICAL},
}
```

**Don't**:
```python
# VULNERABLE: No approval gates for destructive operations
class InsecureToolExecutor:
    async def execute_tool(self, tool_name: str, args: dict):
        # VULNERABLE: Executes any operation without review
        # VULNERABLE: No risk assessment
        # VULNERABLE: No human-in-the-loop for critical actions
        return await self.tools[tool_name](**args)
```

**Why**: Autonomous agents can make destructive changes without human oversight. Approval gates prevent accidental or malicious high-impact operations.

**Refs**: OWASP MCP02:2025, CWE-648, ISO/IEC 23894

---

## MCP03:2025 - Tool Poisoning

**Risk Level**: Critical
**CWE Coverage**: CWE-494, CWE-829, CWE-345

### Rule: Verify Tool Manifest Integrity

**Level**: `strict`

**When**: Loading tool definitions, schemas, or MCP server configurations.

**Do**:
```typescript
import { createHash } from "crypto";
import { readFileSync } from "fs";
import { verify } from "jsonwebtoken";

interface SignedManifest {
  manifest: ToolManifest;
  signature: string;
  hash: string;
}

class SecureToolRegistry {
  private trustedPublicKey: string;
  private knownGoodHashes: Map<string, string>;
  
  constructor(publicKey: string) {
    this.trustedPublicKey = publicKey;
    this.knownGoodHashes = new Map();
  }
  
  async loadToolManifest(manifestPath: string): Promise<ToolManifest> {
    // Read signed manifest
    const signedData = JSON.parse(readFileSync(manifestPath, 'utf8'));
    
    // 1. Verify cryptographic signature
    this.verifySignature(signedData);
    
    // 2. Verify content hash
    this.verifyHash(signedData);
    
    // 3. Check against known-good hashes
    this.checkKnownGoodHash(signedData.manifest.name, signedData.hash);
    
    // 4. Validate semantic constraints
    this.validateSemanticConstraints(signedData.manifest);
    
    return signedData.manifest;
  }
  
  private verifySignature(signedData: SignedManifest): void {
    try {
      // Verify JWT signature from trusted source
      verify(signedData.signature, this.trustedPublicKey, {
        algorithms: ['RS256']
      });
    } catch (error) {
      throw new Error(`Invalid manifest signature: ${error.message}`);
    }
  }
  
  private verifyHash(signedData: SignedManifest): void {
    // Compute hash of manifest
    const computed = createHash('sha256')
      .update(JSON.stringify(signedData.manifest))
      .digest('hex');
    
    if (computed !== signedData.hash) {
      throw new Error('Manifest hash mismatch - possible tampering');
    }
  }
  
  private checkKnownGoodHash(name: string, hash: string): void {
    const knownHash = this.knownGoodHashes.get(name);
    if (knownHash && knownHash !== hash) {
      throw new Error(
        `Tool manifest for ${name} has changed unexpectedly. ` +
        `Expected: ${knownHash}, Got: ${hash}`
      );
    }
  }
  
  private validateSemanticConstraints(manifest: ToolManifest): void {
    // Enforce policy: "archive" operations cannot map to DELETE
    for (const tool of manifest.tools) {
      if (tool.name.includes('archive') && tool.method === 'DELETE') {
        throw new Error(
          `Policy violation: archive operation cannot use DELETE method`
        );
      }
      
      // Validate dangerous operations require explicit confirmation
      if (tool.destructive && !tool.requiresConfirmation) {
        throw new Error(
          `Policy violation: destructive operation must require confirmation`
        );
      }
    }
  }
}
```

**Don't**:
```typescript
// VULNERABLE: No integrity checks on tool manifests
class InsecureToolRegistry {
  async loadToolManifest(manifestUrl: string): Promise<ToolManifest> {
    // VULNERABLE: Fetches from arbitrary URL without verification
    const response = await fetch(manifestUrl);
    const manifest = await response.json();
    
    // VULNERABLE: No signature verification
    // VULNERABLE: No hash verification
    // VULNERABLE: No semantic validation
    
    return manifest;
  }
}
```

**Why**: Poisoned tool manifests can remap benign operations to destructive actions. An "archive" operation could secretly execute DELETE, causing data loss while appearing legitimate in logs.

**Refs**: OWASP MCP03:2025, CWE-494, CWE-345, SLSA Framework

---

### Rule: Implement Tool Schema Validation

**Level**: `strict`

**When**: Accepting tool definitions or schema updates in MCP systems.

**Do**:
```python
from typing import Any, Dict, List
from pydantic import BaseModel, validator, ValidationError
import json

class ToolDefinition(BaseModel):
    """Validated tool schema with semantic constraints."""
    name: str
    description: str
    method: str  # GET, POST, PUT, DELETE
    endpoint: str
    destructive: bool
    requires_confirmation: bool
    
    @validator('method')
    def validate_method(cls, v):
        allowed = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        if v not in allowed:
            raise ValueError(f'Invalid method: {v}')
        return v
    
    @validator('destructive', 'requires_confirmation')
    def validate_destructive_operations(cls, v, values):
        # Enforce policy: destructive operations require confirmation
        if values.get('destructive') and not values.get('requires_confirmation'):
            raise ValueError(
                'Destructive operations must require confirmation'
            )
        return v
    
    @validator('name', 'endpoint')
    def validate_semantic_mapping(cls, v, values, field):
        # Semantic constraint: "archive" should not map to DELETE
        if field.name == 'endpoint' and 'archive' in values.get('name', '').lower():
            if values.get('method') == 'DELETE':
                raise ValueError(
                    'Policy violation: archive operations cannot use DELETE method'
                )
        return v

class ToolSchemaValidator:
    def __init__(self, policy_file: str):
        self.policies = self._load_policies(policy_file)
    
    def validate_tool_schema(self, schema_data: Dict[str, Any]) -> ToolDefinition:
        """Validate tool schema against security policies."""
        try:
            # 1. Structural validation via Pydantic
            tool = ToolDefinition(**schema_data)
            
            # 2. Policy-based validation
            self._validate_against_policies(tool)
            
            # 3. Cross-field validation
            self._validate_cross_field_constraints(tool)
            
            return tool
            
        except ValidationError as e:
            raise ValueError(f"Tool schema validation failed: {e}")
    
    def _validate_against_policies(self, tool: ToolDefinition) -> None:
        """Validate against organizational security policies."""
        # Check tool against OPA/Rego policies
        for policy in self.policies:
            if not policy.evaluate(tool):
                raise ValueError(
                    f"Tool violates security policy: {policy.name}"
                )
    
    def _validate_cross_field_constraints(self, tool: ToolDefinition) -> None:
        """Validate semantic invariants."""
        # Example: Write operations to production require approval
        if 'production' in tool.endpoint and tool.method in ['POST', 'PUT', 'DELETE']:
            if not tool.requires_confirmation:
                raise ValueError(
                    "Production write operations require confirmation"
                )
```

**Don't**:
```python
# VULNERABLE: No schema validation
class InsecureToolRegistry:
    def register_tool(self, schema_data: dict):
        # VULNERABLE: Accepts arbitrary schema without validation
        # VULNERABLE: No semantic constraints
        # VULNERABLE: No policy enforcement
        self.tools[schema_data['name']] = schema_data
```

**Why**: Without schema validation, attackers can inject malicious tool definitions that bypass semantic constraints and execute dangerous operations under benign names.

**Refs**: OWASP MCP03:2025, CWE-20, CWE-1287

---

## MCP04:2025 - Software Supply Chain Attacks

**Risk Level**: High
**CWE Coverage**: CWE-1357, CWE-829

### Rule: Pin and Verify MCP Dependencies

**Level**: `strict`

**When**: Installing MCP server packages, SDKs, or tool dependencies.

**Do**:
```json
{
  "name": "secure-mcp-server",
  "version": "1.0.0",
  "dependencies": {
    "@modelcontextprotocol/sdk": "0.5.0",
    "@anthropic-ai/sdk": "0.27.0"
  },
  "devDependencies": {
    "@types/node": "20.10.0"
  },
  "overrides": {
    "minimatch": "9.0.3"
  },
  "scripts": {
    "preinstall": "npm audit --audit-level=high",
    "postinstall": "npm run verify-integrity"
  }
}
```

```bash
#!/bin/bash
# verify-integrity.sh - Verify package integrity

# Generate and verify lock file hash
echo "Verifying package-lock.json integrity..."
EXPECTED_HASH="sha256-abc123..."
ACTUAL_HASH=$(sha256sum package-lock.json | awk '{print $1}')

if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    echo "ERROR: package-lock.json hash mismatch"
    exit 1
fi

# Verify signatures using Sigstore
echo "Verifying package signatures..."
npx @sigstore/cli verify-npm @modelcontextprotocol/sdk

# Check for known vulnerabilities
npm audit --audit-level=moderate
```

**Don't**:
```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "*",
    "@anthropic-ai/sdk": "^0.27.0"
  }
}
```

```bash
# VULNERABLE: No verification
npm install
```

**Why**: Compromised dependencies can alter agent behavior or introduce backdoors. Supply chain attacks targeting MCP packages can affect all downstream users.

**Refs**: OWASP MCP04:2025, CWE-1357, SLSA Level 3

---

## MCP05:2025 - Command Injection & Execution

**Risk Level**: Critical
**CWE Coverage**: CWE-78, CWE-77, CWE-94

### Rule: Sanitize Tool Arguments Against Command Injection

**Level**: `strict`

**When**: MCP tools execute system commands, shell scripts, or code based on user input.

**Do**:
```python
import subprocess
import shlex
import re
from typing import List

class SafeCommandExecutor:
    # Allowlist of safe commands
    ALLOWED_COMMANDS = {
        'git': ['/usr/bin/git'],
        'npm': ['/usr/bin/npm', '/usr/local/bin/npm'],
        'python': ['/usr/bin/python3']
    }
    
    def execute_safe_command(self, command: str, args: List[str]) -> str:
        """Execute command with strict validation."""
        # 1. Validate command against allowlist
        if command not in self.ALLOWED_COMMANDS:
            raise ValueError(f"Command not allowed: {command}")
        
        # 2. Resolve to absolute path (prevent PATH hijacking)
        cmd_path = self._resolve_command_path(command)
        
        # 3. Validate all arguments
        safe_args = [self._sanitize_argument(arg) for arg in args]
        
        # 4. Execute without shell
        result = subprocess.run(
            [cmd_path] + safe_args,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            shell=False  # CRITICAL: Never use shell=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Command failed: {result.stderr}")
        
        return result.stdout
    
    def _resolve_command_path(self, command: str) -> str:
        """Resolve command to absolute path from allowlist."""
        allowed_paths = self.ALLOWED_COMMANDS[command]
        for path in allowed_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        raise ValueError(f"Command not found in allowlist: {command}")
    
    def _sanitize_argument(self, arg: str) -> str:
        """Validate and sanitize command argument."""
        # Reject arguments with shell metacharacters
        if re.search(r'[;&|`$(){}[\]<>]', arg):
            raise ValueError(f"Argument contains dangerous characters: {arg}")
        
        # Validate argument format (example: file paths)
        if '/' in arg or '\\' in arg:
            # Prevent path traversal
            if '..' in arg:
                raise ValueError("Path traversal detected")
            
            # Ensure path is within allowed directory
            abs_path = os.path.abspath(arg)
            if not abs_path.startswith('/allowed/workspace/'):
                raise ValueError("Path outside allowed workspace")
        
        return arg

# Usage in MCP tool
async def git_clone_tool(url: str, destination: str) -> dict:
    """Safe git clone implementation."""
    executor = SafeCommandExecutor()
    
    # Validate URL is from trusted source
    if not url.startswith('https://github.com/'):
        raise ValueError("Only GitHub HTTPS URLs allowed")
    
    try:
        output = executor.execute_safe_command(
            'git',
            ['clone', '--depth', '1', url, destination]
        )
        return {"success": True, "output": output}
    except Exception as e:
        return {"success": False, "error": str(e)}
```

**Don't**:
```python
# VULNERABLE: Command injection
import os

async def git_clone_tool(url: str, destination: str) -> dict:
    # VULNERABLE: Unsanitized input in shell command
    command = f"git clone {url} {destination}"
    os.system(command)  # VULNERABLE: shell=True equivalent
    
    # VULNERABLE: Using shell=True with user input
    subprocess.run(f"git clone {url} {destination}", shell=True)
    
    return {"success": True}
```

**Why**: Command injection allows attackers to execute arbitrary commands on the system. An attacker could inject `; rm -rf /` into a URL parameter.

**Refs**: OWASP MCP05:2025, CWE-78, OWASP A03:2025

---

## MCP06:2025 - Prompt Injection via Contextual Payloads

**Risk Level**: Critical
**CWE Coverage**: CWE-74, CWE-94

### Rule: Isolate and Validate Context Sources

**Level**: `strict`

**When**: MCP systems retrieve external data, user input, or tool outputs to include in prompts.

**Do**:
```typescript
import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';

class SecureContextManager {
  private readonly INSTRUCTION_DELIMITER = "===SYSTEM_INSTRUCTIONS_END===";
  
  async buildSecureContext(
    systemInstructions: string,
    userQuery: string,
    externalData: string[]
  ): Promise<string> {
    // 1. Clearly delimit system instructions from user content
    const context = [
      "=== SYSTEM INSTRUCTIONS (IMMUTABLE) ===",
      systemInstructions,
      this.INSTRUCTION_DELIMITER,
      "",
      "=== USER QUERY ===",
      this.sanitizeUserInput(userQuery),
      "",
      "=== EXTERNAL DATA (UNTRUSTED) ===",
    ];
    
    // 2. Sanitize and mark external data as untrusted
    for (const data of externalData) {
      const sanitized = this.sanitizeExternalData(data);
      context.push(`[EXTERNAL]: ${sanitized}`);
    }
    
    return context.join("\n");
  }
  
  private sanitizeUserInput(input: string): string {
    // Remove potential instruction injection patterns
    let sanitized = input;
    
    // Strip meta-instruction attempts
    const injectionPatterns = [
      /ignore\s+(previous|above|all)\s+instructions?/gi,
      /new\s+instructions?:/gi,
      /system\s*:/gi,
      /\[SYSTEM\]/gi,
      /forget\s+(everything|all|previous)/gi,
    ];
    
    for (const pattern of injectionPatterns) {
      sanitized = sanitized.replace(pattern, '[FILTERED]');
    }
    
    return sanitized;
  }
  
  private sanitizeExternalData(data: string): string {
    // 1. Parse as markdown to neutralize formatting attacks
    const html = marked.parse(data);
    
    // 2. Sanitize HTML to remove scripts
    const clean = DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'code', 'pre'],
      ALLOWED_ATTR: []
    });
    
    // 3. Validate length to prevent context overflow attacks
    if (clean.length > 10000) {
      return clean.substring(0, 10000) + "\n[TRUNCATED]";
    }
    
    return clean;
  }
  
  validateResponse(response: string): void {
    // Detect if model leaked system instructions
    if (response.includes(this.INSTRUCTION_DELIMITER)) {
      throw new Error("Response contains system instruction delimiter");
    }
    
    // Check for secret patterns (token leakage)
    const secretPatterns = [
      /ghp_[A-Za-z0-9]{36}/,
      /sk-[A-Za-z0-9]{48}/,
      /Bearer\s+[A-Za-z0-9\-._~+/]+/
    ];
    
    for (const pattern of secretPatterns) {
      if (pattern.test(response)) {
        throw new Error("Response contains potential secret");
      }
    }
  }
}
```

**Don't**:
```typescript
// VULNERABLE: No input sanitization or context isolation
class InsecureContextManager {
  async buildContext(
    systemInstructions: string,
    userQuery: string,
    externalData: string[]
  ): Promise<string> {
    // VULNERABLE: Direct concatenation allows injection
    return `
      ${systemInstructions}
      
      User query: ${userQuery}
      
      External data: ${externalData.join("\n")}
    `;
  }
}
```

**Why**: Prompt injection allows attackers to override system instructions, extract secrets from context, or manipulate model behavior through crafted payloads in external data.

**Refs**: OWASP MCP06:2025, OWASP LLM01, CWE-74

---

## MCP07:2025 - Insufficient Authentication & Authorization

**Risk Level**: Critical
**CWE Coverage**: CWE-287, CWE-306, CWE-862

### Rule: Implement Mutual Authentication for MCP Connections

**Level**: `strict`

**When**: Establishing connections between MCP clients and servers.

**Do**:
```python
import ssl
import jwt
from datetime import datetime, timedelta
from typing import Optional

class SecureMCPServer:
    def __init__(self, server_cert: str, server_key: str, ca_cert: str):
        self.server_cert = server_cert
        self.server_key = server_key
        self.ca_cert = ca_cert
        self.jwt_secret = os.environ["JWT_SECRET"]
    
    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with mutual TLS (mTLS)."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load server certificate and private key
        context.load_cert_chain(self.server_cert, self.server_key)
        
        # Require client certificate (mutual TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.ca_cert)
        
        # Use strong TLS version and ciphers
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM')
        
        return context
    
    async def authenticate_request(self, request: dict) -> Optional[dict]:
        """Authenticate and authorize MCP request."""
        # 1. Extract and validate JWT token
        auth_header = request.get("headers", {}).get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise PermissionError("Missing authentication token")
        
        token = auth_header.replace("Bearer ", "")
        
        try:
            # 2. Verify JWT signature and expiration
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "require": ["sub", "scopes", "exp"]
                }
            )
        except jwt.ExpiredSignatureError:
            raise PermissionError("Token expired")
        except jwt.InvalidTokenError as e:
            raise PermissionError(f"Invalid token: {e}")
        
        # 3. Validate agent identity from mTLS certificate
        client_cert = request.get("client_certificate")
        if not self._validate_certificate_identity(client_cert, payload["sub"]):
            raise PermissionError("Certificate does not match token identity")
        
        # 4. Check token revocation list
        if await self._is_token_revoked(payload.get("jti")):
            raise PermissionError("Token has been revoked")
        
        return payload
    
    def _validate_certificate_identity(self, cert: dict, subject: str) -> bool:
        """Verify client certificate matches claimed identity."""
        cert_subject = cert.get("subject", {}).get("CN", "")
        return cert_subject == subject
    
    async def _is_token_revoked(self, token_id: str) -> bool:
        """Check if token is in revocation list."""
        # Check against Redis/database revocation list
        return False  # Implementation
```

**Don't**:
```python
# VULNERABLE: No authentication
class InsecureMCPServer:
    def __init__(self):
        pass
    
    async def handle_request(self, request: dict):
        # VULNERABLE: No authentication check
        # VULNERABLE: No authorization validation
        # VULNERABLE: No TLS/encryption
        return await self.process_request(request)
```

**Why**: Without proper authentication, any client can connect to MCP servers and execute tools. Insufficient authorization allows privilege escalation.

**Refs**: OWASP MCP07:2025, CWE-287, CWE-306, NIST SP 800-63B

---

## MCP08:2025 - Lack of Audit and Telemetry

**Risk Level**: Medium
**CWE Coverage**: CWE-778, CWE-223

### Rule: Maintain Immutable Audit Logs

**Level**: `warning`

**When**: Logging MCP tool invocations, context changes, or security events.

**Do**:
```python
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Optional

class ImmutableAuditLogger:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.previous_hash = self._get_last_log_hash()
    
    async def log_tool_invocation(
        self,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ) -> None:
        """Log tool invocation with tamper-evident chaining."""
        
        # Redact sensitive data
        safe_args = self._redact_secrets(arguments)
        safe_result = self._redact_secrets(result) if result else None
        
        # Create log entry
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": agent_id,
            "tool_name": tool_name,
            "arguments": safe_args,
            "result": safe_result,
            "error": error,
            "previous_hash": self.previous_hash
        }
        
        # Compute hash for tamper detection
        entry_json = json.dumps(entry, sort_keys=True)
        current_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["hash"] = current_hash
        
        # Append to log (immutable, append-only)
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        
        # Update chain
        self.previous_hash = current_hash
        
        # Send to SIEM for centralized monitoring
        await self._send_to_siem(entry)
    
    def verify_log_integrity(self) -> bool:
        """Verify audit log has not been tampered with."""
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
        
        prev_hash = None
        for line in lines:
            entry = json.loads(line)
            
            # Verify chain
            if entry.get("previous_hash") != prev_hash:
                return False
            
            # Verify hash
            claimed_hash = entry.pop("hash")
            computed_hash = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest()
            
            if claimed_hash != computed_hash:
                return False
            
            prev_hash = claimed_hash
        
        return True
    
    def _redact_secrets(self, data: Any) -> Any:
        """Redact secrets before logging."""
        # Implementation from MCP01
        pass
    
    async def _send_to_siem(self, entry: dict) -> None:
        """Send to centralized SIEM for monitoring."""
        # Send to Splunk, ELK, Azure Sentinel, etc.
        pass
```

**Don't**:
```python
# VULNERABLE: No audit logging
class NoLogging:
    async def execute_tool(self, tool_name: str, args: dict):
        # VULNERABLE: No logging of tool invocations
        # VULNERABLE: No audit trail
        return await self.tools[tool_name](**args)

# VULNERABLE: Mutable logs
class InsecureLogging:
    def log_event(self, event: dict):
        # VULNERABLE: Logs can be modified
        # VULNERABLE: No tamper detection
        # VULNERABLE: No secrets redaction
        with open('events.log', 'w') as f:  # Overwrites
            f.write(json.dumps(event))
```

**Why**: Without immutable audit logs, attackers can cover their tracks by deleting or modifying log entries. Tamper-evident chaining enables detection of log manipulation.

**Refs**: OWASP MCP08:2025, CWE-778, NIST SP 800-92

---

## MCP09:2025 - Shadow MCP Servers

**Risk Level**: High
**CWE Coverage**: CWE-1008

### Rule: Implement MCP Server Discovery and Governance

**Level**: `warning`

**When**: Deploying or discovering MCP servers in an organization.

**Do**:
```python
import requests
from typing import List, Dict
from dataclasses import dataclass
from datetime import datetime

@dataclass
class MCPServerInventory:
    server_id: str
    endpoint: str
    owner: str
    purpose: str
    approved: bool
    security_reviewed: bool
    last_audit: datetime
    
class MCPGovernanceFramework:
    def __init__(self, registry_url: str):
        self.registry_url = registry_url
        self.approved_servers = self._load_approved_servers()
    
    async def register_mcp_server(
        self,
        endpoint: str,
        owner: str,
        purpose: str,
        security_config: Dict
    ) -> bool:
        """Register MCP server with governance approval."""
        
        # 1. Security baseline check
        if not await self._validate_security_baseline(endpoint, security_config):
            raise ValueError("Server does not meet security baseline")
        
        # 2. Require security review for approval
        review_id = await self._request_security_review({
            "endpoint": endpoint,
            "owner": owner,
            "purpose": purpose,
            "config": security_config
        })
        
        # 3. Wait for approval
        print(f"Security review requested: {review_id}")
        print("Server will be blocked until approved by security team")
        
        return False  # Blocked until approved
    
    async def discover_shadow_servers(self) -> List[str]:
        """Detect unauthorized MCP servers on network."""
        discovered = []
        
        # 1. Network scan for MCP server patterns
        # Scan for common MCP ports, endpoints, or service advertisements
        
        # 2. Check against approved registry
        for server in self._scan_network_for_mcp():
            if server not in self.approved_servers:
                discovered.append(server)
                await self._alert_security_team(
                    f"Shadow MCP server detected: {server}"
                )
        
        return discovered
    
    async def _validate_security_baseline(
        self,
        endpoint: str,
        config: Dict
    ) -> bool:
        """Validate server meets minimum security requirements."""
        checks = [
            self._check_tls_enabled(endpoint),
            self._check_authentication_required(config),
            self._check_audit_logging_enabled(config),
            self._check_no_default_credentials(config),
            self._check_rate_limiting_enabled(config),
        ]
        
        results = await asyncio.gather(*checks)
        return all(results)
    
    async def _check_tls_enabled(self, endpoint: str) -> bool:
        """Verify TLS is required."""
        return endpoint.startswith("https://")
    
    async def _check_authentication_required(self, config: Dict) -> bool:
        """Verify authentication is enabled."""
        return config.get("auth_required", False)
    
    async def _alert_security_team(self, message: str) -> None:
        """Alert security team of governance violation."""
        # Send to security operations center
        pass
```

**Don't**:
```python
# VULNERABLE: No server governance
class NoGovernance:
    def deploy_mcp_server(self):
        # VULNERABLE: Anyone can deploy MCP servers
        # VULNERABLE: No security review
        # VULNERABLE: No discovery mechanism
        # VULNERABLE: No registry
        server = MCPServer()
        server.start()
```

**Why**: Shadow MCP servers bypass security controls, using default credentials and permissive configurations. They create unmonitored attack surfaces.

**Refs**: OWASP MCP09:2025, CWE-1008, NIST SP 800-53 CM-8

---

## MCP10:2025 - Context Injection & Over-Sharing

**Risk Level**: High
**CWE Coverage**: CWE-200, CWE-668

### Rule: Implement Context Isolation Between Sessions

**Level**: `strict`

**When**: Managing conversation context, memory, or state in MCP systems.

**Do**:
```typescript
import { randomUUID } from "crypto";

interface SessionContext {
  sessionId: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  isolationLevel: "strict" | "user" | "shared";
  allowedDataScopes: string[];
}

class SecureContextManager {
  private sessions: Map<string, SessionContext> = new Map();
  private contextData: Map<string, Map<string, any>> = new Map();
  
  createIsolatedSession(
    userId: string,
    isolationLevel: "strict" | "user" | "shared",
    ttlMinutes: number = 30
  ): string {
    const sessionId = randomUUID();
    const now = new Date();
    
    const session: SessionContext = {
      sessionId,
      userId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + ttlMinutes * 60000),
      isolationLevel,
      allowedDataScopes: this.determineAllowedScopes(userId, isolationLevel)
    };
    
    this.sessions.set(sessionId, session);
    this.contextData.set(sessionId, new Map());
    
    return sessionId;
  }
  
  async addToContext(
    sessionId: string,
    key: string,
    value: any,
    sensitivity: "public" | "internal" | "confidential"
  ): Promise<void> {
    // 1. Validate session exists and not expired
    const session = this.getValidSession(sessionId);
    
    // 2. Check if data scope is allowed
    if (!session.allowedDataScopes.includes(key)) {
      throw new Error(`Data scope '${key}' not allowed for this session`);
    }
    
    // 3. Redact sensitive data
    const sanitized = this.sanitizeValue(value, sensitivity);
    
    // 4. Store in isolated context
    const sessionContext = this.contextData.get(sessionId)!;
    sessionContext.set(key, {
      value: sanitized,
      sensitivity,
      addedAt: new Date(),
      ttl: this.getTTLForSensitivity(sensitivity)
    });
    
    // 5. Enforce size limits to prevent memory exhaustion
    if (sessionContext.size > 100) {
      this.evictOldestEntries(sessionContext, 10);
    }
  }
  
  async getFromContext(
    sessionId: string,
    key: string,
    requestingUserId: string
  ): Promise<any> {
    // 1. Validate session
    const session = this.getValidSession(sessionId);
    
    // 2. Verify requesting user has access
    if (!this.canAccessSession(session, requestingUserId)) {
      throw new Error("Access denied to session context");
    }
    
    // 3. Check data hasn't expired
    const sessionContext = this.contextData.get(sessionId)!;
    const entry = sessionContext.get(key);
    
    if (!entry) {
      return null;
    }
    
    if (this.isExpired(entry)) {
      sessionContext.delete(key);
      return null;
    }
    
    return entry.value;
  }
  
  async destroySession(sessionId: string): Promise<void> {
    // Immediately clear all context data
    this.contextData.delete(sessionId);
    this.sessions.delete(sessionId);
  }
  
  private getValidSession(sessionId: string): SessionContext {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      throw new Error("Session not found");
    }
    
    if (new Date() > session.expiresAt) {
      this.destroySession(sessionId);
      throw new Error("Session expired");
    }
    
    return session;
  }
  
  private canAccessSession(
    session: SessionContext,
    requestingUserId: string
  ): boolean {
    switch (session.isolationLevel) {
      case "strict":
        // Only the session owner can access
        return session.userId === requestingUserId;
      
      case "user":
        // Users with same organization can access
        return this.isSameOrganization(session.userId, requestingUserId);
      
      case "shared":
        // Anyone can access (use cautiously)
        return true;
      
      default:
        return false;
    }
  }
  
  private sanitizeValue(value: any, sensitivity: string): any {
    if (sensitivity === "confidential") {
      // Hash or encrypt confidential data
      return this.encryptValue(value);
    }
    
    // Redact secrets even from "internal" data
    return this.redactSecrets(value);
  }
  
  private getTTLForSensitivity(sensitivity: string): number {
    // Confidential data expires quickly
    switch (sensitivity) {
      case "confidential": return 5 * 60 * 1000;  // 5 minutes
      case "internal": return 30 * 60 * 1000;      // 30 minutes
      case "public": return 60 * 60 * 1000;        // 1 hour
      default: return 30 * 60 * 1000;
    }
  }
}
```

**Don't**:
```typescript
// VULNERABLE: Shared context across sessions
class InsecureContextManager {
  private globalContext: Map<string, any> = new Map();
  
  addToContext(key: string, value: any): void {
    // VULNERABLE: All sessions share same context
    // VULNERABLE: No isolation
    // VULNERABLE: Data persists indefinitely
    this.globalContext.set(key, value);
  }
  
  getFromContext(key: string): any {
    // VULNERABLE: Any session can access any data
    return this.globalContext.get(key);
  }
}
```

**Why**: Context over-sharing allows sensitive information from one user or session to leak to another. Proper isolation prevents cross-session data exposure and context injection attacks.

**Refs**: OWASP MCP10:2025, CWE-200, CWE-668, ISO/IEC 27001

---

## MCP Operational Security - Resource Management & Resilience

**Category**: Production Hardening
**Risk Level**: High
**CWE Coverage**: CWE-400, CWE-770, CWE-307, CWE-209

These rules address operational security concerns for production MCP deployments, including resource limits, rate limiting, error handling, and concurrency management.

### Rule: Enforce Request Size and Timeout Limits

**Level**: `strict`

**When**: Handling incoming MCP requests or executing tools that may consume significant resources.

**Do**:
```python
from fastapi import FastAPI, Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import asyncio
from typing import Callable

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size: int = 10 * 1024 * 1024):  # 10MB default
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next: Callable):
        # Check Content-Length header
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_size:
            raise HTTPException(
                status_code=413,
                detail=f"Request body too large. Maximum: {self.max_size} bytes"
            )
        return await call_next(request)

app = FastAPI()
app.add_middleware(RequestSizeLimitMiddleware, max_size=10 * 1024 * 1024)

class TimeoutExecutor:
    """Execute MCP tools with timeout enforcement."""
    
    def __init__(self, default_timeout: int = 30):
        self.default_timeout = default_timeout
    
    async def execute_with_timeout(
        self,
        tool_name: str,
        args: dict,
        timeout: int = None
    ) -> dict:
        """Execute tool with timeout protection."""
        timeout = timeout or self.default_timeout
        
        try:
            result = await asyncio.wait_for(
                self._execute_tool(tool_name, args),
                timeout=timeout
            )
            return {"success": True, "result": result}
        
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Tool '{tool_name}' exceeded {timeout}s timeout. "
                f"Operation cancelled to prevent resource exhaustion."
            )
    
    async def _execute_tool(self, tool_name: str, args: dict) -> any:
        # Actual tool execution
        pass
```

**Don't**:
```python
# VULNERABLE: No size limits
app = FastAPI()  # Accepts unlimited request sizes

# VULNERABLE: No timeout enforcement
async def execute_tool(tool_name: str, args: dict):
    # Can run indefinitely, exhausting resources
    return await tools[tool_name](**args)
```

**Why**: Unbounded requests enable DoS attacks through memory exhaustion. Indefinite tool execution allows attackers to consume system resources and block other legitimate requests.

**Refs**: CWE-770, CWE-400, OWASP API4:2023

---

### Rule: Implement Per-User Rate Limiting

**Level**: `strict`

**When**: MCP servers handling requests from multiple users, agents, or API clients.

**Do**:
```python
from redis.asyncio import Redis
from datetime import datetime
from fastapi import Request, HTTPException
import hashlib

class PerUserRateLimiter:
    """Distributed per-user rate limiter using Redis."""
    
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
    
    async def check_rate_limit(
        self,
        user_id: str,
        limit: int = 100,
        window_seconds: int = 60
    ) -> dict:
        """Check if user has exceeded rate limit."""
        # Create sliding window key
        now = int(datetime.utcnow().timestamp())
        window_start = now - window_seconds
        
        # Use sorted set for sliding window
        key = f"rate_limit:{user_id}"
        
        # Remove old entries
        await self.redis.zremrangebyscore(key, 0, window_start)
        
        # Count requests in current window
        current_count = await self.redis.zcard(key)
        
        if current_count >= limit:
            # Get time until oldest request expires
            oldest = await self.redis.zrange(key, 0, 0, withscores=True)
            retry_after = int(oldest[0][1] + window_seconds - now) if oldest else window_seconds
            
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Try again in {retry_after}s",
                headers={"Retry-After": str(retry_after)}
            )
        
        # Add current request
        await self.redis.zadd(key, {str(now): now})
        await self.redis.expire(key, window_seconds)
        
        return {
            "allowed": True,
            "remaining": limit - current_count - 1,
            "reset_at": now + window_seconds
        }

# FastAPI middleware implementation
class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis_url: str, limit: int = 100):
        super().__init__(app)
        self.redis = Redis.from_url(redis_url)
        self.limiter = PerUserRateLimiter(self.redis)
        self.limit = limit
    
    async def dispatch(self, request: Request, call_next):
        # Extract user ID from JWT or API key
        user_id = self.get_user_id(request)
        
        # Check rate limit
        limit_info = await self.limiter.check_rate_limit(user_id, self.limit)
        
        # Add rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.limit)
        response.headers["X-RateLimit-Remaining"] = str(limit_info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(limit_info["reset_at"])
        
        return response
    
    def get_user_id(self, request: Request) -> str:
        """Extract user ID from request."""
        # From JWT token
        token = request.headers.get("authorization", "").replace("Bearer ", "")
        if token:
            # Decode JWT to get user_id
            pass
        
        # Fallback to IP address (less ideal)
        return request.client.host

app.add_middleware(RateLimitMiddleware, redis_url="redis://localhost", limit=100)
```

**Don't**:
```python
# VULNERABLE: Global rate limit shared across all users
request_count = 0
RATE_LIMIT = 1000

async def handle_request(request):
    global request_count
    request_count += 1
    
    if request_count > RATE_LIMIT:
        raise Exception("Rate limit exceeded")  # Blocks ALL users
    
    return await process_request(request)
```

**Why**: Global rate limits allow a single malicious user to exhaust the quota for all legitimate users, causing service-wide DoS. Per-user limits isolate abuse.

**Refs**: CWE-307, CWE-799, OWASP API4:2023

---

### Rule: Sanitize Error Messages for External Responses

**Level**: `strict`

**When**: Returning error responses to MCP clients or logging exceptions.

**Do**:
```python
import logging
from enum import Enum
from typing import Optional
import traceback

class ErrorCode(Enum):
    """Safe error codes for external responses."""
    INVALID_INPUT = "INVALID_INPUT"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    TIMEOUT = "TIMEOUT"

class SecureErrorHandler:
    """Handle errors with sanitized external messages and detailed logging."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def handle_error(
        self,
        error: Exception,
        request_id: str,
        user_id: Optional[str] = None
    ) -> dict:
        """Return sanitized error to client, log full details server-side."""
        
        # Log full error details server-side (with secrets redacted)
        self.logger.error(
            f"Request {request_id} failed: {type(error).__name__}",
            exc_info=error,
            extra={
                "request_id": request_id,
                "user_id": user_id,
                "error_type": type(error).__name__
            }
        )
        
        # Return sanitized error to client
        if isinstance(error, ValidationError):
            return {
                "error": ErrorCode.INVALID_INPUT.value,
                "message": "Invalid input parameters. Check your request.",
                "request_id": request_id
            }
        
        elif isinstance(error, PermissionError):
            return {
                "error": ErrorCode.PERMISSION_DENIED.value,
                "message": "Insufficient permissions for this operation.",
                "request_id": request_id
            }
        
        elif isinstance(error, TimeoutError):
            return {
                "error": ErrorCode.TIMEOUT.value,
                "message": "Operation timed out. Try again later.",
                "request_id": request_id
            }
        
        else:
            # NEVER expose internal error details
            return {
                "error": ErrorCode.INTERNAL_ERROR.value,
                "message": "An internal error occurred. Contact support with request ID.",
                "request_id": request_id
            }

# FastAPI exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    request_id = request.headers.get("X-Request-ID", "unknown")
    user_id = getattr(request.state, "user_id", None)
    
    error_handler = SecureErrorHandler()
    error_response = error_handler.handle_error(exc, request_id, user_id)
    
    return JSONResponse(
        status_code=500,
        content=error_response
    )
```

**Don't**:
```python
# VULNERABLE: Exposing internal implementation details
@app.exception_handler(Exception)
async def insecure_error_handler(request: Request, exc: Exception):
    # VULNERABLE: Raw exception message leaks file paths, DB structure, versions
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),  # "FileNotFoundError: /var/app/secrets/api_key.txt"
            "traceback": traceback.format_exc(),  # Full stack trace!
            "type": type(exc).__name__
        }
    )
```

**Why**: Raw exception messages expose sensitive implementation details (file paths, database schema, library versions, internal IPs) that help attackers map the system and identify vulnerabilities.

**Refs**: CWE-209, CWE-497, OWASP A05:2021

---

### Rule: Implement Bounded Concurrency with Resource Cleanup

**Level**: `strict`

**When**: Executing async operations, managing thread pools, or handling concurrent MCP requests.

**Do**:
```python
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
import asyncio
import signal
import sys

class ManagedExecutor:
    """Thread pool executor with bounded concurrency and cleanup."""
    
    def __init__(self, max_workers: int = 10, max_concurrent: int = 50):
        # Bounded thread pool
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="mcp-worker"
        )
        
        # Semaphore to limit concurrent operations
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Track active tasks for graceful shutdown
        self.active_tasks = set()
        
        # Register cleanup handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire executor slot with automatic cleanup."""
        async with self.semaphore:
            task = asyncio.current_task()
            self.active_tasks.add(task)
            
            try:
                yield self.executor
            finally:
                self.active_tasks.discard(task)
    
    async def execute_blocking(self, func, *args, **kwargs):
        """Execute blocking function in thread pool."""
        async with self.acquire() as executor:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(executor, func, *args, **kwargs)
    
    async def shutdown(self, timeout: int = 30):
        """Gracefully shutdown executor."""
        # Cancel pending tasks
        for task in self.active_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.active_tasks:
            await asyncio.wait(self.active_tasks, timeout=timeout)
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True, timeout=timeout)
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        asyncio.create_task(self.shutdown())

# Global executor instance
executor = ManagedExecutor(max_workers=10, max_concurrent=50)

# Usage in MCP server
async def execute_tool(tool_name: str, args: dict):
    """Execute tool with bounded concurrency."""
    # Blocking operation runs in thread pool with limits
    result = await executor.execute_blocking(
        blocking_tool_function,
        tool_name,
        args
    )
    return result

# Cleanup on application shutdown
@app.on_event("shutdown")
async def shutdown_event():
    await executor.shutdown()
```

**Don't**:
```python
# VULNERABLE: Unbounded executor creates unlimited threads
async def execute_tool(tool_name: str, args: dict):
    loop = asyncio.get_event_loop()
    
    # VULNERABLE: None creates unbounded thread pool
    # Each call spawns a new thread - no limit!
    result = await loop.run_in_executor(
        None,  # Unbounded default executor
        blocking_tool_function,
        tool_name,
        args
    )
    return result

# VULNERABLE: No cleanup - resource leaks
```

**Why**: Unbounded thread pools create unlimited threads under load, causing memory exhaustion and system crashes. Missing cleanup handlers leak resources and prevent graceful shutdown.

**Refs**: CWE-400, CWE-770, CWE-404

---

## Quick Reference

| Rule | Level | Primary Risk | OWASP MCP / CWE |
|------|-------|--------------|-----------------|
| Never hardcode MCP credentials | strict | Token exposure | MCP01, CWE-798 |
| Redact secrets from logs/context | strict | Secret leakage | MCP01, CWE-532 |
| Use short-lived, scoped tokens | strict | Credential theft | MCP01, CWE-613 |
| Implement least privilege for tools | strict | Privilege escalation | MCP02, CWE-269 |
| Require approval for high-risk ops | strict | Unauthorized actions | MCP02, CWE-648 |
| Verify tool manifest integrity | strict | Tool poisoning | MCP03, CWE-494 |
| Validate tool schemas | strict | Schema manipulation | MCP03, CWE-20 |
| Pin and verify dependencies | strict | Supply chain attack | MCP04, CWE-1357 |
| Sanitize command arguments | strict | Command injection | MCP05, CWE-78 |
| Isolate and validate context | strict | Prompt injection | MCP06, CWE-74 |
| Mutual authentication (mTLS) | strict | Unauthorized access | MCP07, CWE-287 |
| Maintain immutable audit logs | warning | Incident response | MCP08, CWE-778 |
| Implement server governance | warning | Shadow IT | MCP09, CWE-1008 |
| Isolate session contexts | strict | Context over-sharing | MCP10, CWE-200 |
| Enforce request size/timeout limits | strict | Resource exhaustion | Operational, CWE-770 |
| Per-user rate limiting | strict | DoS attacks | Operational, CWE-307 |
| Sanitize error messages | strict | Information disclosure | Operational, CWE-209 |
| Bounded concurrency with cleanup | strict | Resource leaks | Operational, CWE-400 |

---

## Standards & References

- **OWASP MCP Top 10:2025** - https://owasp.org/www-project-mcp-top-10/
- **Model Context Protocol** - https://modelcontextprotocol.io/
- **CWE Top 25** - https://cwe.mitre.org/top25/
- **NIST AI RMF** - https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- **SLSA Framework** - https://slsa.dev/
- **NIST SP 800-204A** - Microservices Security
- **ISO/IEC 27001** - Information Security Management

---

## Version History

- **v1.0.0** (2026-01-23) - Initial release covering OWASP MCP Top 10:2025
