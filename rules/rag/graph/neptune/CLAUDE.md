# CLAUDE.md - Amazon Neptune Security Rules

Security rules for Amazon Neptune graph database in RAG and knowledge graph applications.

## Prerequisites

- `rules/_core/rag-security.md` - RAG security foundations
- `rules/_core/graph-database-security.md` - Graph database security patterns

---

## Rule: IAM Authentication for Neptune

**Level**: `strict`

**When**: Connecting to Amazon Neptune from any application

**Do**: Use SigV4 signing with IAM roles for authentication

```python
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.process.anonymous_traversal import traversal
from neptune_sigv4_signer import SigV4WebSocketConnection
import boto3

def create_secure_neptune_connection(endpoint: str, region: str):
    """Create IAM-authenticated Neptune connection."""
    # Use IAM role credentials (not hardcoded keys)
    session = boto3.Session()
    credentials = session.get_credentials()

    # Create SigV4-signed connection
    connection = SigV4WebSocketConnection(
        host=endpoint,
        port=8182,
        region=region,
        credentials=credentials,
        pool_size=2,
        message_serializer='graphbinaryv1'
    )

    g = traversal().withRemote(connection)
    return g, connection

# Production usage with IAM role
g, conn = create_secure_neptune_connection(
    endpoint='your-cluster.region.neptune.amazonaws.com',
    region='us-east-1'
)

try:
    result = g.V().limit(10).toList()
finally:
    conn.close()
```

**Don't**: Use static credentials or disable IAM authentication

```python
# VULNERABLE: Hardcoded credentials
from gremlin_python.driver import client

# Never hardcode AWS credentials
connection = client.Client(
    'wss://cluster.neptune.amazonaws.com:8182/gremlin',
    'g',
    # No authentication - relies on network access only
)

# VULNERABLE: Hardcoded access keys
import os
os.environ['AWS_ACCESS_KEY_ID'] = 'AKIAIOSFODNN7EXAMPLE'  # Exposed
os.environ['AWS_SECRET_ACCESS_KEY'] = 'wJalrXUtnFEMI/K7MDENG'  # Exposed
```

**Why**: Neptune without IAM authentication relies solely on VPC network isolation. Compromised network access grants full database access. IAM provides identity-based access control, temporary credentials, and audit trails. Hardcoded credentials in code are easily leaked through version control or logs.

**Refs**: CWE-287 (Improper Authentication), CWE-798 (Hardcoded Credentials), AWS Neptune IAM Authentication

---

## Rule: Gremlin Injection Prevention

**Level**: `strict`

**When**: Building Gremlin traversals with user input

**Do**: Use parameterized traversals with bound variables

```python
from gremlin_python.process.graph_traversal import __
from gremlin_python.process.traversal import P, Cardinality
from typing import Any

def find_user_by_id(g, user_id: str):
    """Securely query user by ID with parameterized traversal."""
    # Validate input type and format
    if not isinstance(user_id, str) or not user_id.isalnum():
        raise ValueError("Invalid user ID format")

    # Use parameterized query with bound values
    return g.V().has('user', 'userId', user_id).elementMap().toList()

def find_connected_entities(g, entity_id: str, edge_label: str, max_depth: int = 2):
    """Securely traverse graph with validated parameters."""
    # Whitelist allowed edge labels
    allowed_edges = {'knows', 'owns', 'manages', 'references'}
    if edge_label not in allowed_edges:
        raise ValueError(f"Invalid edge label: {edge_label}")

    # Validate depth limit
    max_depth = min(max(1, max_depth), 5)  # Clamp between 1-5

    # Parameterized traversal - values are bound, not interpolated
    return (g.V(entity_id)
            .repeat(__.out(edge_label))
            .times(max_depth)
            .dedup()
            .elementMap()
            .toList())

def search_by_properties(g, vertex_label: str, properties: dict[str, Any]):
    """Search vertices with multiple property filters."""
    # Whitelist vertex labels
    allowed_labels = {'user', 'document', 'organization'}
    if vertex_label not in allowed_labels:
        raise ValueError(f"Invalid vertex label")

    # Build traversal with safe property binding
    traversal = g.V().hasLabel(vertex_label)

    for key, value in properties.items():
        # Whitelist property names
        if not key.isalnum() or len(key) > 50:
            raise ValueError(f"Invalid property name: {key}")
        # Values are bound as parameters, not string interpolated
        traversal = traversal.has(key, value)

    return traversal.limit(100).elementMap().toList()
```

**Don't**: Concatenate user input into Gremlin query strings

```python
# VULNERABLE: String concatenation injection
def find_user_unsafe(g, user_id: str):
    # Attacker input: "').drop().V().has('user', 'id', '"
    query = f"g.V().has('user', 'userId', '{user_id}').elementMap()"
    return g.submit(query).all().result()

# VULNERABLE: Format string injection
def search_unsafe(g, label: str, property_name: str, value: str):
    # Attacker can inject arbitrary traversal steps
    query = "g.V().hasLabel('{}').has('{}', '{}')".format(label, property_name, value)
    return g.submit(query).all().result()

# VULNERABLE: Dynamic edge traversal without validation
def traverse_unsafe(g, start_id: str, edge: str):
    # Attacker input for edge: "').drop().V().out('"
    return eval(f"g.V('{start_id}').out('{edge}').toList()")
```

**Why**: Gremlin injection allows attackers to modify graph traversals, potentially dropping vertices/edges, exfiltrating data, or causing denial of service. Neptune's Gremlin endpoint executes submitted strings as code. Parameterized traversals using the Python API bind values safely without interpretation.

**Refs**: CWE-943 (NoSQL Injection), OWASP A03:2025 (Injection), CWE-94 (Code Injection)

---

## Rule: openCypher Injection Prevention

**Level**: `strict`

**When**: Building openCypher queries against Neptune with user input

**Do**: Use parameterized MATCH/RETURN statements with named parameters; never interpolate user values into the query string

```python
import boto3
import json
from typing import Any

def find_document_nodes(session, endpoint: str, doc_id: str, max_hops: int = 2):
    """Parameterized MATCH query — doc_id never touches the query string."""
    # Clamp depth to prevent unbounded traversal (LLM06:2025 guard)
    max_hops = min(max(1, max_hops), 4)

    query = (
        "MATCH (d:Document {id: $docId})-[*1..$hops]-(related) "
        "RETURN related LIMIT 100"
    )
    # Parameters are transmitted as a separate JSON object, not interpolated
    params = {"docId": doc_id, "hops": max_hops}

    # Neptune openCypher HTTP endpoint via boto3 neptunedata client
    client = session.client("neptunedata", endpoint_url=f"https://{endpoint}:8182")
    response = client.execute_open_cypher_query(
        openCypherQuery=query,
        parameters=json.dumps(params)
    )
    return response.get("results", [])

def search_entities_by_label(
    session, endpoint: str, label: str, property_name: str, search_value: str
):
    """Whitelist node labels and property names; bind the search value as a parameter."""
    allowed_labels = {"Document", "User", "Organization", "Concept"}
    allowed_properties = {"title", "name", "category", "status"}

    if label not in allowed_labels:
        raise ValueError(f"Disallowed label: {label}")
    if property_name not in allowed_properties:
        raise ValueError(f"Disallowed property: {property_name}")
    if len(search_value) > 256:
        raise ValueError("Search value too long")

    # label and property_name come from whitelists — safe to interpolate.
    # search_value is a bound parameter — never interpolated.
    query = f"MATCH (n:{label}) WHERE n.{property_name} CONTAINS $val RETURN n LIMIT 50"
    params = {"val": search_value}

    client = session.client("neptunedata", endpoint_url=f"https://{endpoint}:8182")
    response = client.execute_open_cypher_query(
        openCypherQuery=query,
        parameters=json.dumps(params)
    )
    return response.get("results", [])
```

**Don't**: Concatenate user values into openCypher query strings

```python
# VULNERABLE: Direct interpolation — attacker controls graph traversal
def find_unsafe(session, endpoint, doc_id: str):
    # Attacker input: "x') MATCH (n) DETACH DELETE n //"
    query = f"MATCH (d:Document {{id: '{doc_id}'}}) RETURN d"
    # Injection deletes the entire graph
    client = session.client("neptunedata", endpoint_url=f"https://{endpoint}:8182")
    client.execute_open_cypher_query(openCypherQuery=query)

# VULNERABLE: Unvalidated label from user input
def search_unsafe(session, endpoint, label: str, value: str):
    query = f"MATCH (n:{label} {{name: '{value}'}}) RETURN n"
    # Attacker supplies label "x}) RETURN 1 UNION MATCH (n" to alter query structure
    client = session.client("neptunedata", endpoint_url=f"https://{endpoint}:8182")
    client.execute_open_cypher_query(openCypherQuery=query)
```

**Why**: Neptune accepts openCypher alongside Gremlin and SPARQL. The `execute_open_cypher_query` API accepts a `parameters` argument that binds values server-side. Skipping it and interpolating user input directly into the query string lets attackers alter MATCH patterns, inject DETACH DELETE, or exfiltrate data across node labels. Agent-driven RAG traversals (LLM06:2025) amplify the risk because the LLM controls query construction autonomously.

**Refs**: CWE-943 (NoSQL Injection), OWASP A03:2025 (Injection), LLM06:2025 (Excessive Agency), AWS Neptune openCypher Developer Guide

---

## Rule: SPARQL Injection Prevention

**Level**: `strict`

**When**: Building SPARQL queries for Neptune with user input

**Do**: Use parameterized SPARQL queries with proper escaping

```python
from SPARQLWrapper import SPARQLWrapper, JSON
from neptune_sigv4_signer import SigV4SPARQLWrapper
import re
from typing import Optional

def create_secure_sparql_client(endpoint: str, region: str):
    """Create IAM-authenticated SPARQL client."""
    return SigV4SPARQLWrapper(
        endpoint=f"https://{endpoint}:8182/sparql",
        region=region,
        returnFormat=JSON
    )

def escape_sparql_literal(value: str) -> str:
    """Escape special characters for SPARQL string literals."""
    # Escape backslashes first, then other special chars
    value = value.replace('\\', '\\\\')
    value = value.replace('"', '\\"')
    value = value.replace("'", "\\'")
    value = value.replace('\n', '\\n')
    value = value.replace('\r', '\\r')
    value = value.replace('\t', '\\t')
    return value

def validate_uri(uri: str) -> bool:
    """Validate URI format for SPARQL."""
    uri_pattern = r'^https?://[^\s<>"{}|\\^`\[\]]+$'
    return bool(re.match(uri_pattern, uri))

def find_entity_relations(sparql: SPARQLWrapper, entity_uri: str):
    """Securely query entity relations with validated URI."""
    if not validate_uri(entity_uri):
        raise ValueError("Invalid URI format")

    # Use SPARQL parameterization with VALUES clause
    query = """
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

    SELECT ?predicate ?object ?label
    WHERE {
        VALUES ?subject { <%s> }
        ?subject ?predicate ?object .
        OPTIONAL { ?object rdfs:label ?label }
    }
    LIMIT 100
    """ % entity_uri  # URI already validated

    sparql.setQuery(query)
    return sparql.query().convert()

def search_by_label(sparql: SPARQLWrapper, search_term: str, limit: int = 50):
    """Search entities by label with escaped literal."""
    # Validate and escape search term
    if len(search_term) > 200:
        raise ValueError("Search term too long")

    escaped_term = escape_sparql_literal(search_term)
    limit = min(max(1, limit), 1000)  # Clamp limit

    query = f"""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

    SELECT ?entity ?label
    WHERE {{
        ?entity rdfs:label ?label .
        FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{escaped_term}")))
    }}
    LIMIT {limit}
    """

    sparql.setQuery(query)
    return sparql.query().convert()
```

**Don't**: Concatenate unescaped user input into SPARQL queries

```python
# VULNERABLE: Direct string interpolation
def search_unsafe(sparql, search_term: str):
    # Attacker input: '")) . ?s ?p ?o } LIMIT 10000 #'
    query = f"""
    SELECT ?entity WHERE {{
        ?entity rdfs:label "{search_term}"
    }}
    """
    sparql.setQuery(query)
    return sparql.query().convert()

# VULNERABLE: Unvalidated URI injection
def get_entity_unsafe(sparql, uri: str):
    # Attacker can inject arbitrary graph patterns
    query = f"SELECT * WHERE {{ <{uri}> ?p ?o }}"
    sparql.setQuery(query)
    return sparql.query().convert()

# VULNERABLE: No escaping of special characters
def filter_unsafe(sparql, property_value: str):
    # Injection via: value" || true) . ?x ?y ?z } #
    query = f'SELECT ?s WHERE {{ ?s ?p "{property_value}" }}'
    sparql.setQuery(query)
    return sparql.query().convert()
```

**Why**: SPARQL injection allows attackers to modify queries to extract unauthorized data, enumerate the entire graph, or bypass access controls. Unescaped string literals and unvalidated URIs enable query structure manipulation. Proper escaping and URI validation prevent interpretation of special characters.

**Refs**: CWE-943 (NoSQL Injection), OWASP A03:2025 (Injection), CWE-89 (SQL Injection)

---

## Rule: VPC Security Configuration

**Level**: `strict`

**When**: Deploying Amazon Neptune clusters

**Do**: Configure proper VPC isolation with security groups

```python
import boto3
from typing import List

def create_secure_neptune_vpc_config(
    vpc_id: str,
    private_subnet_ids: List[str],
    allowed_security_group_ids: List[str]
) -> dict:
    """Generate secure Neptune VPC configuration."""
    ec2 = boto3.client('ec2')

    # Create dedicated security group for Neptune
    sg_response = ec2.create_security_group(
        GroupName='neptune-cluster-sg',
        Description='Security group for Neptune cluster - restricted access',
        VpcId=vpc_id,
        TagSpecifications=[{
            'ResourceType': 'security-group',
            'Tags': [{'Key': 'Purpose', 'Value': 'Neptune-Database'}]
        }]
    )
    neptune_sg_id = sg_response['GroupId']

    # Allow inbound only from specific application security groups
    for app_sg_id in allowed_security_group_ids:
        ec2.authorize_security_group_ingress(
            GroupId=neptune_sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 8182,
                'ToPort': 8182,
                'UserIdGroupPairs': [{'GroupId': app_sg_id}]
            }]
        )

    # No public access - Neptune must be in private subnets
    # Verify subnets are private (no direct internet gateway route)
    for subnet_id in private_subnet_ids:
        subnet = ec2.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
        if subnet.get('MapPublicIpOnLaunch', False):
            raise ValueError(f"Subnet {subnet_id} allows public IPs - use private subnets only")

    return {
        'DBSubnetGroupName': 'neptune-private-subnet-group',
        'VpcSecurityGroupIds': [neptune_sg_id],
        'SubnetIds': private_subnet_ids
    }

def validate_neptune_security_config(cluster_identifier: str):
    """Audit Neptune cluster security configuration."""
    neptune = boto3.client('neptune')
    ec2 = boto3.client('ec2')

    cluster = neptune.describe_db_clusters(
        DBClusterIdentifier=cluster_identifier
    )['DBClusters'][0]

    issues = []

    # Check IAM authentication is enabled
    if not cluster.get('IAMDatabaseAuthenticationEnabled', False):
        issues.append("CRITICAL: IAM authentication is disabled")

    # Check encryption at rest
    if not cluster.get('StorageEncrypted', False):
        issues.append("CRITICAL: Storage encryption is disabled")

    # Check security groups don't allow 0.0.0.0/0
    for sg in cluster.get('VpcSecurityGroups', []):
        sg_details = ec2.describe_security_groups(
            GroupIds=[sg['VpcSecurityGroupId']]
        )['SecurityGroups'][0]

        for rule in sg_details.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    issues.append(f"CRITICAL: Security group {sg['VpcSecurityGroupId']} allows all IPs")

    # Check deletion protection
    if not cluster.get('DeletionProtection', False):
        issues.append("WARNING: Deletion protection is disabled")

    return issues
```

**Don't**: Expose Neptune to public internet or use permissive security groups

```python
# VULNERABLE: Public subnet deployment
neptune_config = {
    'PubliclyAccessible': True,  # Neptune should never be public
    'SubnetIds': public_subnet_ids
}

# VULNERABLE: Overly permissive security group
ec2.authorize_security_group_ingress(
    GroupId=neptune_sg_id,
    IpPermissions=[{
        'IpProtocol': 'tcp',
        'FromPort': 8182,
        'ToPort': 8182,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Allows entire internet
    }]
)

# VULNERABLE: Wide port range
ec2.authorize_security_group_ingress(
    GroupId=neptune_sg_id,
    IpPermissions=[{
        'IpProtocol': '-1',  # All protocols
        'IpRanges': [{'CidrIp': '10.0.0.0/8'}]  # Entire private range
    }]
)
```

**Why**: Neptune does not support public endpoints by design and must be deployed in VPCs. However, misconfigured security groups can still expose the database to unauthorized internal networks or be accessed via compromised EC2 instances. Defense in depth requires restricting access to specific application security groups on port 8182 only.

**Refs**: CWE-284 (Improper Access Control), AWS Neptune Security Best Practices, CWE-732 (Incorrect Permission Assignment)

---

## Rule: CloudTrail Audit Logging

**Level**: `warning`

**When**: Operating Neptune in production environments

**Do**: Enable comprehensive audit logging with CloudTrail and Neptune audit logs

```python
import boto3
import json
from datetime import datetime, timedelta
from typing import List

def enable_neptune_audit_logging(cluster_identifier: str, s3_bucket: str):
    """Enable Neptune audit logs with S3 export."""
    neptune = boto3.client('neptune')

    # Enable audit logs for the cluster
    neptune.modify_db_cluster(
        DBClusterIdentifier=cluster_identifier,
        CloudwatchLogsExportConfiguration={
            'EnableLogTypes': ['audit']
        },
        EnableCloudwatchLogsExports=['audit']
    )

    # Create CloudWatch log group for Neptune
    logs = boto3.client('logs')
    log_group = f'/aws/neptune/{cluster_identifier}/audit'

    try:
        logs.create_log_group(
            logGroupName=log_group,
            tags={'Purpose': 'Neptune-Audit', 'Compliance': 'Required'}
        )
    except logs.exceptions.ResourceAlreadyExistsException:
        pass

    # Set retention policy
    logs.put_retention_policy(
        logGroupName=log_group,
        retentionInDays=365  # Adjust based on compliance requirements
    )

    return {'log_group': log_group, 'status': 'enabled'}

def configure_neptune_cloudtrail(trail_name: str, s3_bucket: str):
    """Configure CloudTrail for Neptune API monitoring."""
    cloudtrail = boto3.client('cloudtrail')

    # Create or update trail for Neptune events
    cloudtrail.create_trail(
        Name=trail_name,
        S3BucketName=s3_bucket,
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
        Tags=[{'Key': 'Purpose', 'Value': 'Neptune-API-Audit'}]
    )

    # Enable management and data events
    cloudtrail.put_event_selectors(
        TrailName=trail_name,
        EventSelectors=[{
            'ReadWriteType': 'All',
            'IncludeManagementEvents': True,
            'DataResources': [{
                'Type': 'AWS::Neptune::DBCluster',
                'Values': ['arn:aws:neptune:*']
            }]
        }]
    )

    cloudtrail.start_logging(Name=trail_name)
    return {'trail': trail_name, 'status': 'logging'}

def query_neptune_audit_events(
    cluster_identifier: str,
    hours_back: int = 24,
    event_types: List[str] = None
):
    """Query Neptune audit logs for security events."""
    logs = boto3.client('logs')
    log_group = f'/aws/neptune/{cluster_identifier}/audit'

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours_back)

    # Query for suspicious patterns
    filter_pattern = ' '.join([
        '[timestamp, requestId, query]',
        '?drop ?delete ?remove ?truncate'  # Destructive operations
    ]) if not event_types else ' '.join(event_types)

    response = logs.filter_log_events(
        logGroupName=log_group,
        startTime=int(start_time.timestamp() * 1000),
        endTime=int(end_time.timestamp() * 1000),
        filterPattern=filter_pattern
    )

    return [{
        'timestamp': event['timestamp'],
        'message': event['message']
    } for event in response.get('events', [])]
```

**Don't**: Operate Neptune without audit logging or ignore log analysis

```python
# VULNERABLE: No audit logging configured
neptune.modify_db_cluster(
    DBClusterIdentifier=cluster_id,
    CloudwatchLogsExportConfiguration={
        'DisableLogTypes': ['audit']  # Disabling audit logs
    }
)

# VULNERABLE: No log retention policy (logs auto-delete)
# Missing: logs.put_retention_policy()

# VULNERABLE: No monitoring of destructive operations
# Missing: Alerts for DROP, DELETE, bulk modifications

# VULNERABLE: No CloudTrail for API calls
# Cannot detect: Who modified cluster settings, IAM changes
```

**Why**: Without audit logging, security incidents cannot be detected, investigated, or proven for compliance. Neptune audit logs capture query patterns, and CloudTrail captures API calls for configuration changes. Both are essential for detecting injection attempts, unauthorized access, data exfiltration, and meeting compliance requirements (SOC2, HIPAA, GDPR). In RAG pipelines, audit logs are the primary control for detecting sensitive data leakage through graph traversal (LLM02:2025).

**Refs**: CWE-778 (Insufficient Logging), OWASP A09:2025 (Security Logging and Monitoring Failures), LLM02:2025 (Sensitive Information Disclosure), AWS Neptune Audit Logs

---

## Rule: Cross-Account IAM Access for Neptune

**Level**: `strict`

**When**: Granting another AWS account access to a Neptune cluster (shared analytics, hub-and-spoke RAG pipelines, multi-tenant environments)

**Do**: Use IAM role trust policies scoped to a specific cross-account role ARN; restrict Neptune permissions to the exact cluster ARN; use short-lived STS tokens

```python
import boto3
import json

def create_cross_account_neptune_role(
    trusted_account_id: str,
    trusted_role_name: str,
    cluster_arn: str,
    current_account_id: str,
) -> str:
    """
    Create an IAM role in the Neptune-owning account that the trusted account
    can assume. Returns the new role ARN.

    Trust is scoped to a specific role in the trusted account, not the entire
    account, to enforce least-privilege cross-account access.
    """
    iam = boto3.client("iam")

    # Trust policy: only the named role in the named account may assume this role.
    # aws:PrincipalArn in the Condition ensures the exact role is matched even
    # when the trusted account later adds more roles.
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountAssume",
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{trusted_account_id}:role/{trusted_role_name}"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalArn": (
                            f"arn:aws:iam::{trusted_account_id}:role/{trusted_role_name}"
                        )
                    }
                }
            }
        ]
    }

    # Permission policy: read-only Neptune data-plane actions, scoped to one cluster.
    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "NeptuneReadOnly",
                "Effect": "Allow",
                "Action": [
                    "neptune-db:ReadDataViaQuery",
                    "neptune-db:GetQueryStatus",
                    "neptune-db:CancelQuery",
                ],
                # Scope to the exact cluster ARN — never use "*"
                "Resource": cluster_arn,
            }
        ]
    }

    role_name = f"neptune-cross-acct-{trusted_account_id[:8]}"

    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description=(
            f"Cross-account Neptune read access for account {trusted_account_id}"
        ),
        MaxSessionDuration=3600,  # 1 hour — short-lived tokens
        Tags=[
            {"Key": "TrustedAccount", "Value": trusted_account_id},
            {"Key": "ClusterArn", "Value": cluster_arn},
        ],
    )

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="NeptuneReadOnlyPolicy",
        PolicyDocument=json.dumps(permission_policy),
    )

    return f"arn:aws:iam::{current_account_id}:role/{role_name}"


def assume_cross_account_neptune_role(role_arn: str, session_name: str) -> dict:
    """
    Called from the trusted account to obtain short-lived credentials
    for the Neptune-owning account's role.
    """
    sts = boto3.client("sts")

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=900,  # 15 minutes — minimum viable session
    )
    return response["Credentials"]


def validate_cross_account_trust_policy(role_name: str) -> list:
    """Audit an existing role's trust policy for overly-broad principals."""
    iam = boto3.client("iam")
    issues = []

    role = iam.get_role(RoleName=role_name)["Role"]
    trust = role["AssumeRolePolicyDocument"]

    for stmt in trust.get("Statement", []):
        principal = stmt.get("Principal", {})

        # Wildcard principal grants access to any AWS identity
        if principal == "*" or principal.get("AWS") == "*":
            issues.append(f"CRITICAL: Role {role_name} trusts wildcard principal")

        # Entire-account principal without Condition is too broad
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for arn in aws_principals:
            if arn.endswith(":root") and not stmt.get("Condition"):
                issues.append(
                    f"WARNING: Role {role_name} trusts account root without Condition — "
                    "scope to a specific role ARN"
                )

    return issues
```

**Don't**: Use wildcard principals, trust entire accounts without conditions, or grant write access across accounts

```python
# VULNERABLE: Wildcard principal — any AWS identity can assume this role
trust_policy = {
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "*"},  # Anyone in AWS
        "Action": "sts:AssumeRole"
    }]
}

# VULNERABLE: Entire account without Condition — any role/user in that account
trust_policy = {
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},  # Too broad
        "Action": "sts:AssumeRole"
        # No Condition to restrict to a specific role
    }]
}

# VULNERABLE: Cross-account write permissions on Neptune
permission_policy = {
    "Statement": [{
        "Effect": "Allow",
        "Action": "neptune-db:*",   # Includes WriteDataViaQuery, DeleteDataViaQuery
        "Resource": "*"             # All clusters in the account
    }]
}
```

**Why**: Cross-account Neptune access requires two gates: the trust policy on the IAM role (who may assume it) and the permission policy (what they can do once assumed). A wildcard or over-broad trust policy lets any identity in the trusted account assume the role, not just the intended service. Granting write permissions across accounts violates least-privilege and enables data destruction or exfiltration from a compromised third-party workload. Agent-driven RAG pipelines (LLM06:2025) that autonomously assume cross-account roles amplify the blast radius of misconfigured trust.

**Refs**: CWE-284 (Improper Access Control), CWE-732 (Incorrect Permission Assignment), OWASP A03:2025 (Injection), LLM06:2025 (Excessive Agency), AWS IAM Cross-Account Access, AWS Neptune IAM Database Authentication

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| IAM authentication | strict | CWE-287, CWE-798 |
| Gremlin injection prevention | strict | CWE-943, OWASP A03:2025 |
| openCypher injection prevention | strict | CWE-943, OWASP A03:2025, LLM06:2025 |
| SPARQL injection prevention | strict | CWE-943, CWE-89, OWASP A03:2025 |
| VPC security configuration | strict | CWE-284, CWE-732 |
| CloudTrail audit logging | warning | CWE-778, OWASP A09:2025, LLM02:2025 |
| Cross-account IAM access | strict | CWE-284, CWE-732, LLM06:2025 |

---

## Version History

- **v2.0.0** - Add openCypher injection rule, cross-account IAM rule; update OWASP refs to 2025; add LLM Top 10 2025 refs
- **v1.0.0** - Initial Amazon Neptune security rules
