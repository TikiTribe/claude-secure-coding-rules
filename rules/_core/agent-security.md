# Agent Security - Core Security Rules

This file provides security rules for agentic AI systems that perform autonomous actions, use tools, and execute multi-step tasks.

## Overview

**Scope**: AI agents with tool use, code execution, file system access, and autonomous decision-making
**Standards**: OWASP LLM Top 10, NIST AI RMF, Google SAIF
**Focus**: Action validation, tool security, permission boundaries, and execution isolation

---

## Tool Use Security

### Rule: Validate Tool Calls Before Execution

**Level**: `strict`

**When**: Agent selects and invokes tools based on LLM reasoning.

**Do**:
```python
from pydantic import BaseModel, validator
from typing import Any
import json

class ToolCall(BaseModel):
    tool_name: str
    parameters: dict

    @validator('tool_name')
    def validate_tool_name(cls, v):
        allowed_tools = ['read_file', 'write_file', 'search', 'calculate']
        if v not in allowed_tools:
            raise ValueError(f"Tool '{v}' not in allowlist")
        return v

class SecureToolExecutor:
    def __init__(self, tools: dict, permission_checker):
        self.tools = tools
        self.permission_checker = permission_checker

    def execute(self, tool_call: ToolCall, context: dict) -> Any:
        """Execute tool with validation and sandboxing."""
        # Validate tool exists
        if tool_call.tool_name not in self.tools:
            raise ToolNotFoundError(f"Unknown tool: {tool_call.tool_name}")

        tool = self.tools[tool_call.tool_name]

        # Check permissions
        if not self.permission_checker.can_execute(
            user=context['user'],
            tool=tool_call.tool_name,
            params=tool_call.parameters
        ):
            raise PermissionError(f"Not authorized for {tool_call.tool_name}")

        # Validate parameters against tool schema
        validated_params = tool.validate_params(tool_call.parameters)

        # Log before execution
        audit_logger.info(
            "Tool execution",
            extra={
                'tool': tool_call.tool_name,
                'params': self._sanitize_for_log(validated_params),
                'user': context['user'].id
            }
        )

        # Execute in sandbox
        result = self._execute_sandboxed(tool, validated_params, context)

        return result

    def _execute_sandboxed(self, tool, params, context):
        """Execute tool with resource limits and isolation."""
        import resource
        import signal

        # Set resource limits
        def set_limits():
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))  # 30s CPU
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)  # 512MB

        # Execute with timeout
        def timeout_handler(signum, frame):
            raise TimeoutError("Tool execution timeout")

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(60)  # 60s wall clock

        try:
            return tool.execute(**params)
        finally:
            signal.alarm(0)
```

**Don't**:
```python
# VULNERABLE: Direct execution without validation
def execute_tool(tool_name, params):
    return tools[tool_name](**params)

# VULNERABLE: No permission checks
def agent_action(llm_output):
    tool_call = parse_tool_call(llm_output)
    return globals()[tool_call['name']](**tool_call['params'])
```

**Why**: Compromised or manipulated agents can invoke dangerous tools. Validation prevents unauthorized actions and parameter injection.

**Refs**: OWASP LLM07 (Insecure Plugin Design), NIST AI RMF MANAGE 1.3, MITRE ATLAS AML.T0051

---

### Rule: Implement Tool Permission Boundaries

**Level**: `strict`

**When**: Defining what tools an agent can access and under what conditions.

**Do**:
```python
from enum import Enum
from typing import Set

class PermissionLevel(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"

class ToolPermissionPolicy:
    def __init__(self):
        self.tool_permissions = {
            'read_file': {
                'required_level': PermissionLevel.READ,
                'allowed_paths': ['/data/', '/config/'],
                'blocked_paths': ['/secrets/', '/credentials/'],
                'max_file_size': 10 * 1024 * 1024  # 10MB
            },
            'write_file': {
                'required_level': PermissionLevel.WRITE,
                'allowed_paths': ['/output/', '/tmp/'],
                'blocked_paths': ['/system/', '/etc/'],
                'require_confirmation': True
            },
            'execute_code': {
                'required_level': PermissionLevel.EXECUTE,
                'allowed_languages': ['python'],
                'blocked_imports': ['os', 'subprocess', 'socket'],
                'require_confirmation': True,
                'sandbox_required': True
            },
            'web_request': {
                'required_level': PermissionLevel.READ,
                'allowed_domains': ['api.example.com'],
                'blocked_domains': ['*.internal', 'localhost'],
                'max_requests_per_minute': 10
            }
        }

    def check_permission(self, user, tool_name: str, params: dict) -> bool:
        policy = self.tool_permissions.get(tool_name)
        if not policy:
            return False

        # Check user permission level
        if not user.has_permission(policy['required_level']):
            return False

        # Check tool-specific constraints
        if tool_name == 'read_file':
            return self._check_file_access(params.get('path'), policy)
        elif tool_name == 'execute_code':
            return self._check_code_safety(params.get('code'), policy)

        return True

    def _check_file_access(self, path: str, policy: dict) -> bool:
        # Normalize path to prevent traversal
        import os
        normalized = os.path.normpath(path)

        # Check blocked paths first
        for blocked in policy['blocked_paths']:
            if normalized.startswith(blocked):
                return False

        # Check allowed paths
        for allowed in policy['allowed_paths']:
            if normalized.startswith(allowed):
                return True

        return False
```

**Don't**:
```python
# VULNERABLE: No permission boundaries
def can_use_tool(tool_name):
    return True  # All tools available

# VULNERABLE: Overly broad permissions
allowed_paths = ['/']  # Full filesystem access
```

**Why**: Principle of least privilege limits damage from compromised agents. Specific boundaries prevent unauthorized data access or system modification.

**Refs**: NIST AI RMF GOVERN 1.2, ISO/IEC 23894 A.1 Accountability, OWASP A01:2025

---

## Code Execution Security

### Rule: Sandbox Agent-Generated Code

**Level**: `strict`

**When**: Agent generates and executes code as part of its tasks.

**Do**:
```python
import ast
import RestrictedPython
from RestrictedPython import compile_restricted, safe_builtins

class CodeSandbox:
    def __init__(self):
        self.allowed_builtins = {
            **safe_builtins,
            'len': len,
            'range': range,
            'enumerate': enumerate,
            'zip': zip,
            'map': map,
            'filter': filter,
            'sorted': sorted,
            'sum': sum,
            'min': min,
            'max': max,
            'abs': abs,
            'round': round,
        }
        self.blocked_names = {
            'eval', 'exec', 'compile', 'open', 'input',
            '__import__', 'globals', 'locals', 'vars',
            'getattr', 'setattr', 'delattr', 'hasattr'
        }

    def validate_code(self, code: str) -> bool:
        """Static analysis of code safety."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            raise CodeValidationError(f"Syntax error: {e}")

        for node in ast.walk(tree):
            # Block dangerous calls
            if isinstance(node, ast.Call):
                if hasattr(node.func, 'id') and node.func.id in self.blocked_names:
                    raise CodeValidationError(f"Blocked function: {node.func.id}")

            # Block imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                raise CodeValidationError("Imports not allowed in sandbox")

        return True

    def execute(self, code: str, local_vars: dict = None) -> dict:
        """Execute code in restricted environment."""
        self.validate_code(code)

        # Compile with RestrictedPython
        byte_code = compile_restricted(
            code,
            filename='<agent_code>',
            mode='exec'
        )

        # Execute with restricted globals
        restricted_globals = {
            '__builtins__': self.allowed_builtins,
            '_print_': lambda x: None,  # Disable print
            '_getattr_': lambda obj, name: getattr(obj, name) if not name.startswith('_') else None,
        }

        local_namespace = local_vars or {}

        exec(byte_code, restricted_globals, local_namespace)

        return local_namespace
```

**Don't**:
```python
# VULNERABLE: Direct exec of agent code
def run_agent_code(code):
    exec(code)

# VULNERABLE: eval with user/agent input
result = eval(agent_generated_expression)
```

**Why**: Unrestricted code execution allows arbitrary system access. Sandboxing limits what generated code can do.

**Refs**: OWASP LLM06 (Excessive Agency), CWE-94, NIST SSDF PW.5.1

---

### Rule: Limit Agent Autonomy Scope

**Level**: `strict`

**When**: Configuring how much autonomous action an agent can take.

**Do**:
```python
from enum import IntEnum
from typing import List

class AutonomyLevel(IntEnum):
    SUGGEST = 1      # Only suggest actions, human executes
    CONFIRM = 2      # Execute after human confirmation
    BOUNDED = 3      # Execute within strict limits automatically
    SUPERVISED = 4   # Execute with monitoring, can be stopped
    AUTONOMOUS = 5   # Full autonomy (rarely appropriate)

class AgentAutonomyController:
    def __init__(self, default_level: AutonomyLevel = AutonomyLevel.CONFIRM):
        self.default_level = default_level
        self.action_limits = {
            'max_actions_per_task': 20,
            'max_cost_usd': 10.0,
            'max_files_modified': 5,
            'max_api_calls': 50,
            'require_confirmation_for': [
                'delete_file', 'send_email', 'make_purchase',
                'modify_permissions', 'external_api_call'
            ]
        }

    def request_action(self, action: str, params: dict, context: dict) -> dict:
        """Process action request based on autonomy level."""
        level = context.get('autonomy_level', self.default_level)

        # Check action limits
        if not self._within_limits(action, context):
            return {
                'approved': False,
                'reason': 'Action limit exceeded',
                'require_human': True
            }

        # High-risk actions always need confirmation
        if action in self.action_limits['require_confirmation_for']:
            return {
                'approved': False,
                'reason': f'Action {action} requires confirmation',
                'require_human': True
            }

        if level == AutonomyLevel.SUGGEST:
            return {
                'approved': False,
                'suggestion': self._format_suggestion(action, params),
                'require_human': True
            }
        elif level == AutonomyLevel.CONFIRM:
            return {
                'approved': False,
                'pending_confirmation': True,
                'action': action,
                'params': params
            }
        elif level == AutonomyLevel.BOUNDED:
            if self._is_within_bounds(action, params):
                return {'approved': True}
            return {'approved': False, 'require_human': True}

        return {'approved': False, 'reason': 'Unknown autonomy level'}

    def _within_limits(self, action: str, context: dict) -> bool:
        """Check if action is within cumulative limits."""
        stats = context.get('session_stats', {})

        if stats.get('action_count', 0) >= self.action_limits['max_actions_per_task']:
            return False
        if stats.get('total_cost', 0) >= self.action_limits['max_cost_usd']:
            return False
        if stats.get('files_modified', 0) >= self.action_limits['max_files_modified']:
            return False

        return True
```

**Don't**:
```python
# VULNERABLE: Unlimited autonomous actions
def agent_loop():
    while not done:
        action = agent.decide_action()
        execute(action)  # No limits or confirmation

# VULNERABLE: No cost controls
def execute_task(task):
    while True:
        result = expensive_api_call()  # Unlimited API calls
```

**Why**: Unrestricted autonomy can lead to runaway costs, unintended consequences, or exploitation. Humans should remain in control of high-impact decisions.

**Refs**: OWASP LLM06 (Excessive Agency), NIST AI RMF GOVERN 3.2, ISO/IEC 23894 A.1

---

## Input/Output Security

### Rule: Validate Agent Outputs Before Action

**Level**: `strict`

**When**: Agent outputs will trigger actions, API calls, or system changes.

**Do**:
```python
from pydantic import BaseModel, validator
from typing import Union, List
import re

class FileWriteAction(BaseModel):
    path: str
    content: str

    @validator('path')
    def validate_path(cls, v):
        # Prevent path traversal
        if '..' in v or v.startswith('/'):
            raise ValueError("Invalid path")
        # Allowlist of writable directories
        allowed_prefixes = ['output/', 'results/', 'tmp/']
        if not any(v.startswith(p) for p in allowed_prefixes):
            raise ValueError(f"Path must start with: {allowed_prefixes}")
        return v

    @validator('content')
    def validate_content(cls, v):
        # Check for potentially malicious content
        dangerous_patterns = [
            r'<script',
            r'javascript:',
            r'data:text/html',
            r'\beval\s*\(',
            r'\bexec\s*\('
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("Content contains potentially dangerous patterns")
        return v

class APICallAction(BaseModel):
    endpoint: str
    method: str
    body: dict

    @validator('endpoint')
    def validate_endpoint(cls, v):
        # Only allow specific API endpoints
        allowed = [
            'https://api.example.com/data',
            'https://api.example.com/reports'
        ]
        if v not in allowed:
            raise ValueError(f"Endpoint not in allowlist: {v}")
        return v

    @validator('method')
    def validate_method(cls, v):
        if v.upper() not in ['GET', 'POST']:
            raise ValueError("Only GET and POST allowed")
        return v.upper()

class ActionValidator:
    def validate(self, action_type: str, action_data: dict):
        validators = {
            'file_write': FileWriteAction,
            'api_call': APICallAction,
        }

        validator_class = validators.get(action_type)
        if not validator_class:
            raise ValueError(f"Unknown action type: {action_type}")

        return validator_class(**action_data)
```

**Don't**:
```python
# VULNERABLE: Direct action execution
def execute_agent_output(output):
    if output['action'] == 'write_file':
        with open(output['path'], 'w') as f:  # No path validation
            f.write(output['content'])

# VULNERABLE: Trusting agent-specified URLs
def call_api(agent_output):
    requests.post(agent_output['url'], json=agent_output['data'])
```

**Why**: Agent outputs can be manipulated through prompt injection or model errors. Validation prevents unintended file writes, API calls, or system modifications.

**Refs**: OWASP LLM02 (Insecure Output Handling), NIST AI RMF MEASURE 2.9

---

### Rule: Implement Multi-Step Confirmation for High-Risk Actions

**Level**: `strict`

**When**: Agent actions have significant, potentially irreversible consequences.

**Do**:
```python
class HighRiskActionHandler:
    HIGH_RISK_ACTIONS = {
        'delete_data': {'confirmation_count': 2, 'cooldown_seconds': 30},
        'send_external': {'confirmation_count': 1, 'cooldown_seconds': 10},
        'modify_config': {'confirmation_count': 2, 'cooldown_seconds': 60},
        'financial_transaction': {'confirmation_count': 3, 'cooldown_seconds': 120}
    }

    def __init__(self):
        self.pending_confirmations = {}

    async def request_high_risk_action(
        self,
        action_type: str,
        params: dict,
        user_context: dict
    ) -> dict:
        """Handle high-risk action with multiple confirmations."""
        if action_type not in self.HIGH_RISK_ACTIONS:
            return {'status': 'not_high_risk', 'proceed': True}

        config = self.HIGH_RISK_ACTIONS[action_type]
        action_id = self._generate_action_id(action_type, params)

        # Check for existing pending confirmation
        if action_id in self.pending_confirmations:
            pending = self.pending_confirmations[action_id]
            pending['confirmations'] += 1

            if pending['confirmations'] >= config['confirmation_count']:
                # Check cooldown
                elapsed = time.time() - pending['first_request']
                if elapsed < config['cooldown_seconds']:
                    return {
                        'status': 'cooldown',
                        'wait_seconds': config['cooldown_seconds'] - elapsed
                    }

                # Execute action
                del self.pending_confirmations[action_id]
                return {'status': 'approved', 'proceed': True}

            return {
                'status': 'pending',
                'confirmations_received': pending['confirmations'],
                'confirmations_required': config['confirmation_count']
            }

        # First request - create pending confirmation
        self.pending_confirmations[action_id] = {
            'action_type': action_type,
            'params': params,
            'confirmations': 1,
            'first_request': time.time(),
            'user_id': user_context['user_id']
        }

        # Notify user
        await self._notify_user(
            user_context,
            f"High-risk action '{action_type}' requested. "
            f"Requires {config['confirmation_count']} confirmations."
        )

        return {
            'status': 'confirmation_required',
            'confirmations_received': 1,
            'confirmations_required': config['confirmation_count'],
            'cooldown_seconds': config['cooldown_seconds']
        }
```

**Don't**:
```python
# VULNERABLE: Immediate execution of dangerous actions
def handle_action(action):
    if action['type'] == 'delete_all_data':
        delete_all_data()  # No confirmation!

# VULNERABLE: Single confirmation for critical actions
def delete_account(user_id):
    if confirm_once():
        actually_delete(user_id)
```

**Why**: High-risk actions need friction to prevent accidental or malicious execution. Multiple confirmations with delays allow users to catch mistakes.

**Refs**: NIST AI RMF GOVERN 3.2, ISO/IEC 23894 A.10 Safety

---

## Session Security

### Rule: Isolate Agent Sessions

**Level**: `warning`

**When**: Multiple agents or users share infrastructure.

**Do**:
```python
import uuid
from contextlib import contextmanager

class AgentSessionManager:
    def __init__(self):
        self.sessions = {}

    @contextmanager
    def create_session(self, user_id: str, config: dict):
        """Create isolated agent session."""
        session_id = str(uuid.uuid4())

        session = AgentSession(
            session_id=session_id,
            user_id=user_id,
            # Isolated working directory
            work_dir=f"/tmp/agent_sessions/{session_id}",
            # Session-specific memory
            memory=SessionMemory(max_size=1000),
            # Resource limits
            limits={
                'max_tokens': config.get('max_tokens', 10000),
                'max_time_seconds': config.get('max_time', 300),
                'max_tool_calls': config.get('max_tools', 50)
            },
            # Session-specific permissions
            permissions=self._derive_permissions(user_id, config)
        )

        # Create isolated filesystem
        os.makedirs(session.work_dir, mode=0o700, exist_ok=True)

        self.sessions[session_id] = session

        try:
            yield session
        finally:
            # Cleanup
            self._cleanup_session(session)

    def _cleanup_session(self, session):
        """Clean up session resources."""
        # Remove working directory
        import shutil
        if os.path.exists(session.work_dir):
            shutil.rmtree(session.work_dir)

        # Clear memory
        session.memory.clear()

        # Remove from active sessions
        del self.sessions[session.session_id]

        # Log session end
        audit_logger.info(
            "Agent session ended",
            extra={
                'session_id': session.session_id,
                'user_id': session.user_id,
                'tool_calls': session.stats.get('tool_calls', 0)
            }
        )
```

**Don't**:
```python
# VULNERABLE: Shared state between sessions
global_memory = {}

def agent_action(user_id, action):
    global_memory[action['key']] = action['value']  # Shared!

# VULNERABLE: No cleanup
def run_agent(task):
    create_temp_files()
    do_work()
    # Files left behind
```

**Why**: Session isolation prevents data leakage between users and limits blast radius of compromised sessions.

**Refs**: OWASP LLM05 (Supply Chain Vulnerabilities), CWE-200, NIST AI RMF MANAGE 2.4

---

## Monitoring & Audit

### Rule: Log All Agent Actions

**Level**: `warning`

**When**: Agent performs any action beyond pure reasoning.

**Do**:
```python
import json
import time
from datetime import datetime

class AgentAuditLogger:
    def __init__(self):
        self.logger = logging.getLogger('agent_audit')

    def log_action(
        self,
        session_id: str,
        action_type: str,
        action_params: dict,
        result: dict,
        context: dict
    ):
        """Log agent action with full context for audit."""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': session_id,
            'user_id': context.get('user_id'),
            'action_type': action_type,
            'action_params': self._sanitize_params(action_params),
            'result_status': result.get('status'),
            'result_summary': self._summarize_result(result),
            'reasoning': context.get('agent_reasoning', '')[:500],  # Truncate
            'tool_chain': context.get('tool_chain', []),
            'tokens_used': context.get('tokens_used', 0),
            'latency_ms': context.get('latency_ms', 0)
        }

        self.logger.info(json.dumps(entry))

    def log_security_event(
        self,
        session_id: str,
        event_type: str,
        severity: str,
        details: dict
    ):
        """Log security-relevant events."""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': session_id,
            'event_type': event_type,
            'severity': severity,
            'details': details
        }

        if severity in ['HIGH', 'CRITICAL']:
            self.logger.warning(json.dumps(entry))
            # Trigger alert
            self._send_alert(entry)
        else:
            self.logger.info(json.dumps(entry))

    def _sanitize_params(self, params: dict) -> dict:
        """Remove sensitive data from params."""
        sensitive_keys = ['password', 'token', 'secret', 'key', 'credential']
        sanitized = {}
        for k, v in params.items():
            if any(s in k.lower() for s in sensitive_keys):
                sanitized[k] = '[REDACTED]'
            else:
                sanitized[k] = v
        return sanitized
```

**Don't**:
```python
# VULNERABLE: No audit logging
def execute_tool(tool, params):
    return tool(**params)

# VULNERABLE: Logging sensitive data
logger.info(f"API call with key: {api_key}")
```

**Why**: Audit logs enable incident investigation, compliance verification, and detection of agent misuse or compromise.

**Refs**: OWASP A09:2025 (Logging Failures), NIST AI RMF MEASURE 1.1, ISO/IEC 23894 A.11

---

## Quick Reference

| Rule | Level | Primary Risk | Key Control |
|------|-------|--------------|-------------|
| Validate Tool Calls | strict | Unauthorized execution | Allowlist + validation |
| Tool Permission Boundaries | strict | Privilege escalation | Least privilege |
| Sandbox Generated Code | strict | Arbitrary code execution | RestrictedPython |
| Limit Autonomy Scope | strict | Runaway actions | Confirmation gates |
| Validate Agent Outputs | strict | Malicious outputs | Schema validation |
| Multi-Step Confirmation | strict | Irreversible damage | Multiple confirmations |
| Isolate Sessions | warning | Data leakage | Session isolation |
| Log All Actions | warning | Undetected misuse | Comprehensive audit |

---

## Version History

- **v1.0.0** - Initial release for agentic AI security patterns
