# CrewAI Security Rules

Security rules for CrewAI multi-agent development in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/_core/agent-security.md` - Agent security patterns
- `rules/backend/langchain/CLAUDE.md` - LangChain security (CrewAI uses LangChain)

---

## Inter-Agent Security

### Rule: Implement Agent Trust Boundaries

**Level**: `strict`

**When**: Configuring multi-agent crews.

**Do**:
```python
from crewai import Agent, Crew, Task

# Safe: Define clear roles with limited capabilities
researcher = Agent(
    role="Research Analyst",
    goal="Find and summarize information",
    backstory="Expert at finding information",
    tools=[search_tool],  # Limited tools
    allow_delegation=False,  # Cannot delegate to other agents
    verbose=False,  # Don't log sensitive data
    max_iter=10,  # Limit iterations
    max_rpm=10  # Rate limit
)

# Safe: Separate agents for different trust levels
class SecureCrewFactory:
    @staticmethod
    def create_read_only_agent(name: str, tools: list) -> Agent:
        """Agents that can only read data"""
        return Agent(
            role=name,
            tools=[t for t in tools if t.name in READ_ONLY_TOOLS],
            allow_delegation=False,
            max_iter=5
        )

    @staticmethod
    def create_write_agent(name: str, tools: list) -> Agent:
        """Agents that can modify data.

        human_input is a Task-level parameter, not Agent-level.
        Require approval by setting human_input=True on the Task
        that uses this agent (see Secure Task Delegation rule).
        """
        return Agent(
            role=name,
            tools=tools,
            allow_delegation=False,
            max_iter=3
        )
```

**Don't**:
```python
# VULNERABLE: All agents can delegate to each other
agent1 = Agent(role="Agent1", allow_delegation=True)
agent2 = Agent(role="Agent2", allow_delegation=True)
# Circular delegation, privilege escalation possible

# VULNERABLE: Shared tools without restrictions
all_tools = [shell_tool, file_tool, db_tool, api_tool]
agent = Agent(role="Worker", tools=all_tools)  # Too many capabilities

# VULNERABLE: No iteration limits
agent = Agent(role="Worker", max_iter=1000)  # Can run forever

# VULNERABLE: human_input on Agent() is silently ignored — it is not
# a valid Agent parameter. Place it on Task() instead.
agent = Agent(role="Worker", human_input=True)  # Has no effect
```

**Why**: Unrestricted agent capabilities and delegation enable privilege escalation and uncontrolled behavior.

**Refs**: OWASP LLM06:2025, MITRE ATLAS AML.T0051, CWE-269

---

### Rule: Secure Task Delegation

**Level**: `strict`

**When**: Configuring task delegation between agents.

**Do**:
```python
from crewai import Crew, Process, Task

# Safe: Explicit task dependencies with validation
def create_secure_tasks():
    research_task = Task(
        description="Research the topic: {topic}",
        agent=researcher,
        expected_output="Summary of findings",
        output_file="research.md"  # Controlled output location
    )

    analysis_task = Task(
        description="Analyze the research findings",
        agent=analyst,
        expected_output="Analysis report",
        context=[research_task],  # Explicit dependency
        human_input=True  # Require human approval before execution
        # human_input belongs here on Task(), not on Agent()
    )

    return [research_task, analysis_task]

# Safe: Crew with process controls
crew = Crew(
    agents=[researcher, analyst],
    tasks=create_secure_tasks(),
    process=Process.sequential,  # Controlled execution order
    verbose=False,
    max_rpm=20,  # Global rate limit
    memory=False  # Disable shared memory if not needed
)
```

**Don't**:
```python
# VULNERABLE: Hierarchical process without controls
crew = Crew(
    agents=agents,
    tasks=tasks,
    process=Process.hierarchical,
    manager_llm=llm  # Manager can delegate anything
)

# VULNERABLE: Task with user-controlled description
task = Task(
    description=user_input,  # Injection risk
    agent=agent
)

# VULNERABLE: No output validation
task = Task(
    description="Generate code",
    agent=coder,
    # No expected_output validation
)
```

**Why**: Uncontrolled delegation allows agents to assign tasks beyond their authorization, potentially executing dangerous operations.

**Refs**: OWASP LLM06:2025, CWE-863

---

## Memory Security

### Rule: Isolate Crew Memory

**Level**: `strict`

**When**: Using CrewAI memory features.

**Do**:
```python
from crewai import Crew

# Safe: Disable memory for sensitive operations
crew = Crew(
    agents=agents,
    tasks=tasks,
    memory=False  # No persistent memory
)

# Safe: If memory is needed, instantiate a separate Crew per session.
# CrewAI's memory backend is scoped to each Crew instance, so creating
# one Crew per user/session prevents cross-session data leakage.
class SecureCrew:
    def __init__(self, crew_id: str):
        self.crew_id = crew_id

    def run(self, inputs: dict):
        # New Crew instance per invocation — memory does not bleed
        # across instances when memory=True is scoped this way.
        crew = Crew(
            agents=self.agents,
            tasks=self.tasks,
            memory=True,
            embedder={
                "provider": "openai",
                "config": {"model": "text-embedding-3-small"}
            }
        )

        try:
            result = crew.kickoff(inputs=self._sanitize_inputs(inputs))
        finally:
            # Clean up sensitive memory after use
            if self.should_clear_memory:
                self._clear_memory()

        return result

    def _sanitize_inputs(self, inputs: dict) -> dict:
        return {k: str(v)[:1000] for k, v in inputs.items()}
```

**Don't**:
```python
# VULNERABLE: Shared memory across crews/users
crew = Crew(
    agents=agents,
    tasks=tasks,
    memory=True  # Default memory shared across all calls to this instance
)
# Different users' data could leak into each other's context

# VULNERABLE: No memory cleanup
def process_request(user_data):
    result = crew.kickoff(inputs=user_data)
    return result
    # Sensitive data persists in memory for the next caller
```

**Why**: Shared memory between crews or sessions enables cross-user data leakage and context poisoning.

**Refs**: CWE-200, CWE-359, OWASP LLM01:2025

---

## Tool Security

### Rule: Validate Agent Tool Usage

**Level**: `strict`

**When**: Assigning tools to CrewAI agents.

**Do**:
```python
from pathlib import Path

from crewai_tools import BaseTool
from pydantic import BaseModel, Field

# Safe: Tool with strict input validation
class SecureFileReadTool(BaseTool):
    name: str = "Read File"
    description: str = "Read contents of allowed files"

    class InputSchema(BaseModel):
        filename: str = Field(..., pattern=r'^[a-zA-Z0-9_-]+\.(txt|json|md)$')

    args_schema = InputSchema  # wire schema so CrewAI enforces it

    def _run(self, filename: str) -> str:
        # Validate against allowlist
        allowed_dir = Path("/app/data").resolve()
        file_path = (allowed_dir / filename).resolve()

        if not file_path.is_relative_to(allowed_dir):
            return "Error: Access denied"

        if not file_path.exists():
            return "Error: File not found"

        return file_path.read_text()[:5000]

# Safe: Role-specific tool assignment
ROLE_TOOLS = {
    "researcher": [search_tool, read_tool],
    "analyst": [calculator_tool, chart_tool],
    "writer": [write_tool]  # Only writers can write
}

def get_tools_for_role(role: str) -> list:
    if role not in ROLE_TOOLS:
        raise ValueError(f"Unknown role: {role}")
    return ROLE_TOOLS[role]
```

**Don't**:
```python
# VULNERABLE: Agent with shell access
from crewai_tools import ShellTool
agent = Agent(role="Worker", tools=[ShellTool()])

# VULNERABLE: No input validation on tools
class UnsafeTool(BaseTool):
    def _run(self, command: str) -> str:
        import os
        return os.popen(command).read()

# VULNERABLE: All agents get all tools
for agent in agents:
    agent.tools = all_available_tools
```

**Why**: Unrestricted tool access enables agents to execute arbitrary code, access sensitive files, or perform unauthorized operations.

**Refs**: OWASP LLM06:2025, CWE-78, CWE-22

---

## Output Security

### Rule: Validate Crew Outputs

**Level**: `strict`

**When**: Processing results from crew execution.

**Do**:
```python
import json
from pydantic import BaseModel

class CrewOutput(BaseModel):
    summary: str
    findings: list[str]
    confidence: float

def process_crew_result(result) -> dict:
    # Validate output structure — use model_validate_json() (Pydantic v2).
    # parse_raw() was removed in Pydantic v2 and must not be used.
    try:
        parsed = CrewOutput.model_validate_json(result.raw)
    except Exception:
        raise ValueError("Invalid crew output format")

    # Sanitize output content
    sanitized = {
        "summary": sanitize_text(parsed.summary),
        "findings": [sanitize_text(f) for f in parsed.findings[:10]],
        "confidence": min(max(parsed.confidence, 0), 1)
    }

    # Check for sensitive data leakage
    if contains_sensitive_patterns(str(sanitized)):
        raise ValueError("Output contains sensitive data")

    return sanitized

def sanitize_text(text: str) -> str:
    # Remove potential code/scripts
    text = re.sub(r'<script.*?</script>', '', text, flags=re.DOTALL)
    # Limit length
    return text[:2000]
```

**Don't**:
```python
# VULNERABLE: Direct use of crew output
result = crew.kickoff(inputs=data)
return {"response": result.raw}  # Could contain anything

# VULNERABLE: No output validation
def get_analysis(topic):
    result = crew.kickoff(inputs={"topic": topic})
    exec(result.raw)  # Never execute crew output

# VULNERABLE: Output to uncontrolled location
task = Task(
    description="Save results",
    output_file=user_provided_path  # Path traversal
)

# VULNERABLE: parse_raw() removed in Pydantic v2 — use model_validate_json()
parsed = CrewOutput.parse_raw(result.raw)
```

**Why**: Crew outputs may contain malicious content, sensitive data, or injection payloads that must be validated before use.

**Refs**: OWASP LLM05:2025, CWE-94, CWE-200

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Implement agent trust boundaries | strict | OWASP LLM06:2025, CWE-269 |
| Secure task delegation | strict | OWASP LLM06:2025, CWE-863 |
| Isolate crew memory | strict | CWE-200, CWE-359 |
| Validate agent tool usage | strict | OWASP LLM06:2025, CWE-78 |
| Validate crew outputs | strict | OWASP LLM05:2025, CWE-94 |

---

## Version History

- **v2.0.0** - Audit defect fixes: OWASP LLM ref remapping to 2025 taxonomy, human_input moved to Task, Process import added, SecureFileReadTool corrected, memory isolation documented accurately, parse_raw replaced with model_validate_json
- **v1.0.0** - Initial CrewAI security rules
