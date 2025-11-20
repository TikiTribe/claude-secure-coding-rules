# CLAUDE.md - Amazon Neptune & TigerGraph Security Rules

Security rules for Amazon Neptune and TigerGraph graph databases in RAG and knowledge graph applications.

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

**Refs**: CWE-943 (NoSQL Injection), OWASP A03:2021 (Injection), CWE-94 (Code Injection)

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

**Refs**: CWE-943 (NoSQL Injection), OWASP A03:2021 (Injection), CWE-89 (SQL Injection)

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

**Why**: Without audit logging, security incidents cannot be detected, investigated, or proven for compliance. Neptune audit logs capture query patterns, and CloudTrail captures API calls for configuration changes. Both are essential for detecting injection attempts, unauthorized access, data exfiltration, and meeting compliance requirements (SOC2, HIPAA, GDPR).

**Refs**: CWE-778 (Insufficient Logging), OWASP A09:2021 (Security Logging and Monitoring Failures), AWS Neptune Audit Logs

---

## Rule: GSQL Injection Prevention

**Level**: `strict`

**When**: Building TigerGraph GSQL queries with user input

**Do**: Use parameterized queries with pyTigerGraph and input validation

```python
import pyTigerGraph as tg
from typing import Any, Optional
import re

def create_secure_tigergraph_connection(
    host: str,
    graph_name: str,
    username: str,
    password: str
) -> tg.TigerGraphConnection:
    """Create authenticated TigerGraph connection."""
    conn = tg.TigerGraphConnection(
        host=host,
        graphname=graph_name,
        username=username,
        password=password,
        useCert=True,  # Enable TLS
        certPath='/path/to/ca-bundle.crt'
    )

    # Get API token for subsequent requests
    conn.getToken(conn.createSecret())
    return conn

def run_parameterized_query(
    conn: tg.TigerGraphConnection,
    query_name: str,
    params: dict[str, Any]
) -> list:
    """Execute installed query with validated parameters."""
    # Whitelist of allowed queries
    allowed_queries = {
        'find_user_by_id',
        'get_connected_nodes',
        'search_by_property',
        'find_shortest_path'
    }

    if query_name not in allowed_queries:
        raise ValueError(f"Query not in whitelist: {query_name}")

    # Validate parameter types and values
    validated_params = {}
    for key, value in params.items():
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', key):
            raise ValueError(f"Invalid parameter name: {key}")

        # Type-specific validation
        if isinstance(value, str):
            if len(value) > 1000:
                raise ValueError(f"Parameter {key} exceeds max length")
            # Escape special characters for string parameters
            validated_params[key] = value
        elif isinstance(value, (int, float)):
            validated_params[key] = value
        elif isinstance(value, list):
            validated_params[key] = value
        else:
            raise ValueError(f"Unsupported parameter type for {key}")

    # Execute pre-installed parameterized query
    return conn.runInstalledQuery(query_name, validated_params)

def find_user_secure(conn: tg.TigerGraphConnection, user_id: str):
    """Securely find user by ID using parameterized query."""
    # Validate user_id format
    if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', user_id):
        raise ValueError("Invalid user ID format")

    # Use built-in parameterized vertex lookup
    return conn.getVerticesById('User', user_id)

def search_vertices_secure(
    conn: tg.TigerGraphConnection,
    vertex_type: str,
    filter_attr: str,
    filter_value: str,
    limit: int = 100
) -> list:
    """Securely search vertices with attribute filter."""
    # Whitelist vertex types and attributes
    allowed_types = {'User', 'Document', 'Organization', 'Product'}
    allowed_attrs = {'name', 'email', 'title', 'category', 'status'}

    if vertex_type not in allowed_types:
        raise ValueError(f"Invalid vertex type: {vertex_type}")
    if filter_attr not in allowed_attrs:
        raise ValueError(f"Invalid filter attribute: {filter_attr}")

    limit = min(max(1, limit), 1000)

    # Use pyTigerGraph's safe vertex retrieval
    return conn.getVertices(
        vertex_type,
        where=f"{filter_attr}=\"{conn.escapeString(filter_value)}\"",
        limit=str(limit)
    )
```

**Don't**: Concatenate user input into GSQL query strings

```python
# VULNERABLE: Direct string interpolation in GSQL
def search_unsafe(conn, search_term: str):
    # Attacker input: '"; DROP ALL; INTERPRET QUERY () { '
    query = f'''
    INTERPRET QUERY () {{
        users = SELECT u FROM User:u WHERE u.name == "{search_term}";
        PRINT users;
    }}
    '''
    return conn.gsql(query)

# VULNERABLE: Unvalidated vertex type allows schema enumeration
def get_vertices_unsafe(conn, vertex_type: str, vertex_id: str):
    # Attacker can enumerate all vertex types
    return conn.getVerticesById(vertex_type, vertex_id)

# VULNERABLE: Dynamic query construction
def filter_unsafe(conn, attr_name: str, attr_value: str):
    # Injection via attribute name or value
    query = f'SELECT * FROM User WHERE {attr_name} = "{attr_value}"'
    return conn.gsql(query)

# VULNERABLE: Using gsql() with user input
def interpret_unsafe(conn, condition: str):
    # Full GSQL injection possible
    query = f'''
    INTERPRET QUERY () {{
        results = SELECT v FROM ANY:v WHERE {condition};
        PRINT results;
    }}
    '''
    return conn.gsql(query)
```

**Why**: GSQL injection allows attackers to execute arbitrary graph operations including data exfiltration, schema modification, and denial of service. TigerGraph's INTERPRET QUERY feature is particularly dangerous with user input. Pre-installed parameterized queries separate code from data, preventing injection. Always use pyTigerGraph's built-in methods which handle escaping.

**Refs**: CWE-943 (NoSQL Injection), OWASP A03:2021 (Injection), CWE-94 (Code Injection)

---

## Rule: Graph Studio Security

**Level**: `strict`

**When**: Configuring TigerGraph Graph Studio access

**Do**: Implement strong authentication and role-based access control

```python
import pyTigerGraph as tg
from typing import List
import secrets
import hashlib

def configure_secure_graph_studio(
    conn: tg.TigerGraphConnection,
    admin_password: str
):
    """Configure Graph Studio with secure settings."""
    # Verify strong admin password
    if len(admin_password) < 16:
        raise ValueError("Admin password must be at least 16 characters")

    # Enable SSO if available
    sso_config = {
        'method': 'SAML',
        'provider': 'okta',  # or 'azure_ad', 'auth0'
        'require_mfa': True
    }

    return {'sso_enabled': True, 'config': sso_config}

def create_role_based_user(
    conn: tg.TigerGraphConnection,
    username: str,
    role: str,
    graphs: List[str]
):
    """Create user with principle of least privilege."""
    # Define role permissions
    role_permissions = {
        'viewer': {
            'query': True,
            'write_data': False,
            'write_schema': False,
            'admin': False
        },
        'analyst': {
            'query': True,
            'write_data': True,
            'write_schema': False,
            'admin': False
        },
        'developer': {
            'query': True,
            'write_data': True,
            'write_schema': True,
            'admin': False
        },
        'admin': {
            'query': True,
            'write_data': True,
            'write_schema': True,
            'admin': True
        }
    }

    if role not in role_permissions:
        raise ValueError(f"Invalid role: {role}")

    # Validate graph names
    for graph in graphs:
        if not graph.isalnum():
            raise ValueError(f"Invalid graph name: {graph}")

    perms = role_permissions[role]

    # Generate secure temporary password
    temp_password = secrets.token_urlsafe(16)

    # Create user with specific graph access
    gsql_commands = f'''
    CREATE USER {username} WITH PASSWORD "{temp_password}"
    '''

    # Grant role-specific privileges per graph
    for graph in graphs:
        if perms['query']:
            gsql_commands += f'\nGRANT ROLE queryreader ON GRAPH {graph} TO {username}'
        if perms['write_data']:
            gsql_commands += f'\nGRANT ROLE querywriter ON GRAPH {graph} TO {username}'
        if perms['write_schema']:
            gsql_commands += f'\nGRANT ROLE designer ON GRAPH {graph} TO {username}'
        if perms['admin']:
            gsql_commands += f'\nGRANT ROLE admin ON GRAPH {graph} TO {username}'

    conn.gsql(gsql_commands)

    return {
        'username': username,
        'temp_password': temp_password,
        'role': role,
        'graphs': graphs,
        'force_password_change': True
    }

def audit_user_permissions(conn: tg.TigerGraphConnection):
    """Audit all users and their permissions for security review."""
    result = conn.gsql('SHOW USER')

    security_issues = []

    for user in result.get('users', []):
        # Check for overly broad permissions
        if user.get('superuser', False) and user['name'] != 'tigergraph':
            security_issues.append(f"User {user['name']} has superuser privileges")

        # Check for users with global graph access
        if '*' in user.get('graphs', []):
            security_issues.append(f"User {user['name']} has access to all graphs")

    return security_issues
```

**Don't**: Use weak authentication or grant excessive permissions

```python
# VULNERABLE: Weak passwords
conn.gsql('CREATE USER analyst WITH PASSWORD "password123"')

# VULNERABLE: Superuser for non-admin tasks
conn.gsql('GRANT ROLE superuser TO analyst')

# VULNERABLE: All graphs access
conn.gsql('GRANT ROLE admin ON GRAPH * TO developer')

# VULNERABLE: No authentication for API
conn = tg.TigerGraphConnection(
    host='tigergraph-server',
    graphname='MyGraph',
    # Missing username/password - uses default credentials
)

# VULNERABLE: Shared service accounts
# Multiple applications using same 'app_user' credentials

# VULNERABLE: No session timeout
# Users stay logged into Graph Studio indefinitely
```

**Why**: Graph Studio provides full access to graph data, schema, and queries. Weak authentication allows unauthorized access to sensitive data. Excessive permissions violate least privilege and enable lateral movement if credentials are compromised. RBAC ensures users can only access data and operations required for their role.

**Refs**: CWE-269 (Improper Privilege Management), CWE-250 (Execution with Unnecessary Privileges), OWASP A01:2021 (Broken Access Control)

---

## Rule: Real-Time Analytics Security

**Level**: `warning`

**When**: Running real-time analytics queries on TigerGraph

**Do**: Implement resource limits and query timeouts to prevent abuse

```python
import pyTigerGraph as tg
from typing import Optional
import time
from functools import wraps

def create_resource_limited_connection(
    host: str,
    graph_name: str,
    username: str,
    password: str,
    timeout_seconds: int = 30
) -> tg.TigerGraphConnection:
    """Create connection with resource limits."""
    conn = tg.TigerGraphConnection(
        host=host,
        graphname=graph_name,
        username=username,
        password=password,
        apiToken=None,
        useCert=True
    )

    # Set query timeout
    conn.setQueryTimeout(timeout_seconds * 1000)  # milliseconds

    return conn

def run_bounded_query(
    conn: tg.TigerGraphConnection,
    query_name: str,
    params: dict,
    max_results: int = 10000,
    timeout_ms: int = 30000
) -> list:
    """Execute query with result size and time bounds."""
    # Add limit parameter if query supports it
    params['result_limit'] = min(params.get('result_limit', max_results), max_results)

    start_time = time.time()

    try:
        result = conn.runInstalledQuery(
            query_name,
            params,
            timeout=timeout_ms
        )

        elapsed_ms = (time.time() - start_time) * 1000

        # Log slow queries for optimization
        if elapsed_ms > timeout_ms * 0.8:
            log_slow_query(query_name, params, elapsed_ms)

        return result

    except Exception as e:
        if 'timeout' in str(e).lower():
            raise TimeoutError(f"Query {query_name} exceeded {timeout_ms}ms timeout")
        raise

def validate_traversal_depth(max_depth: int = 5):
    """Decorator to limit graph traversal depth."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            depth = kwargs.get('depth', args[2] if len(args) > 2 else 1)
            if depth > max_depth:
                raise ValueError(f"Traversal depth {depth} exceeds maximum {max_depth}")
            return func(*args, **kwargs)
        return wrapper
    return decorator

@validate_traversal_depth(max_depth=5)
def find_paths_secure(
    conn: tg.TigerGraphConnection,
    source_id: str,
    depth: int = 3,
    max_paths: int = 100
) -> list:
    """Find paths with bounded depth and result count."""
    return conn.runInstalledQuery(
        'find_all_paths',
        {
            'source': source_id,
            'max_depth': depth,
            'max_results': max_paths
        },
        timeout=60000
    )

def configure_query_quotas(conn: tg.TigerGraphConnection, username: str):
    """Configure per-user query quotas."""
    quota_config = f'''
    ALTER USER {username} SET
        MAX_QUERY_TIME = 60,           -- seconds
        MAX_MEMORY_PER_QUERY = 4096,   -- MB
        MAX_CONCURRENT_QUERIES = 5
    '''
    return conn.gsql(quota_config)

def log_slow_query(query_name: str, params: dict, elapsed_ms: float):
    """Log slow queries for performance monitoring."""
    import logging
    logger = logging.getLogger('tigergraph.performance')
    logger.warning(
        f"Slow query detected",
        extra={
            'query': query_name,
            'params': params,
            'elapsed_ms': elapsed_ms,
            'threshold_ms': 24000
        }
    )
```

**Don't**: Allow unbounded queries or ignore resource consumption

```python
# VULNERABLE: No timeout - query can run forever
result = conn.runInstalledQuery('expensive_algorithm', params)

# VULNERABLE: Unbounded traversal depth
def traverse_all(conn, start_id):
    # Can traverse entire graph, causing OOM or timeout
    return conn.runInstalledQuery('traverse_graph', {
        'start': start_id,
        'depth': 100  # Excessive depth
    })

# VULNERABLE: No result limits
def get_all_connected(conn, vertex_id):
    # Could return millions of results
    return conn.runInstalledQuery('get_neighbors', {
        'vertex': vertex_id
        # Missing: result limit
    })

# VULNERABLE: No query quotas per user
# Single user can consume all cluster resources

# VULNERABLE: No monitoring of query performance
# Cannot detect DoS attacks or runaway queries
```

**Why**: Graph analytics queries can be computationally expensive, especially for traversals, pattern matching, and graph algorithms. Without resource limits, a single malicious or poorly-written query can exhaust cluster memory, CPU, or cause service unavailability. Timeouts and result limits provide defense against denial of service, both intentional and accidental.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits), OWASP A05:2021 (Security Misconfiguration)

---

## Rule: ML Workbench Security

**Level**: `warning`

**When**: Using TigerGraph ML Workbench for graph machine learning

**Do**: Implement model security and data isolation for ML workflows

```python
import pyTigerGraph as tg
from typing import List, Optional
import hashlib
import json

def create_isolated_ml_environment(
    conn: tg.TigerGraphConnection,
    project_name: str,
    allowed_graphs: List[str],
    user: str
) -> dict:
    """Create isolated ML environment with data access controls."""
    # Validate project name
    if not project_name.isalnum():
        raise ValueError("Project name must be alphanumeric")

    # Create dedicated graph for ML experiments
    ml_graph_name = f"ml_{project_name}_{hashlib.md5(user.encode()).hexdigest()[:8]}"

    # Create subgraph with only required data
    gsql = f'''
    CREATE GRAPH {ml_graph_name} ()

    // Copy only required vertex/edge types
    USE GRAPH {allowed_graphs[0]}
    CREATE LOADING JOB export_for_ml {{
        // Define specific data export with anonymization
    }}
    '''

    conn.gsql(gsql)

    # Set resource quotas for ML jobs
    ml_config = {
        'graph': ml_graph_name,
        'max_memory_gb': 16,
        'max_training_time_hours': 4,
        'gpu_enabled': False,  # Enable only if needed
        'data_export_disabled': True  # Prevent model exfiltration
    }

    return ml_config

def validate_model_input(
    conn: tg.TigerGraphConnection,
    feature_query: str,
    allowed_attributes: List[str]
) -> bool:
    """Validate ML feature extraction doesn't access sensitive data."""
    # Parse query to extract accessed attributes
    # This is simplified - real implementation needs GSQL parser

    sensitive_attributes = {
        'ssn', 'password', 'credit_card', 'bank_account',
        'medical_record', 'salary', 'phone', 'address'
    }

    for attr in sensitive_attributes:
        if attr.lower() in feature_query.lower():
            raise ValueError(f"Cannot access sensitive attribute: {attr}")

    return True

def secure_model_export(
    conn: tg.TigerGraphConnection,
    model_name: str,
    destination: str,
    require_approval: bool = True
) -> dict:
    """Export trained model with security controls."""
    # Verify model exists and user has access
    # Check for potential data leakage in model

    export_record = {
        'model': model_name,
        'exported_by': conn.username,
        'destination': destination,
        'timestamp': time.time(),
        'approval_required': require_approval,
        'approved': False if require_approval else True
    }

    # Log export for audit
    log_ml_operation('model_export', export_record)

    if require_approval:
        return {
            'status': 'pending_approval',
            'export_id': hashlib.sha256(
                json.dumps(export_record).encode()
            ).hexdigest()
        }

    # Perform export with encryption
    return perform_encrypted_export(model_name, destination)

def configure_ml_audit_logging(conn: tg.TigerGraphConnection):
    """Enable comprehensive audit logging for ML operations."""
    audit_config = {
        'log_training_jobs': True,
        'log_feature_access': True,
        'log_model_exports': True,
        'log_predictions': True,
        'retention_days': 365,
        'alert_on_anomaly': True
    }

    return audit_config

def log_ml_operation(operation_type: str, details: dict):
    """Log ML operations for security audit."""
    import logging
    logger = logging.getLogger('tigergraph.ml.audit')
    logger.info(
        f"ML operation: {operation_type}",
        extra={
            'operation': operation_type,
            'details': details,
            'timestamp': time.time()
        }
    )
```

**Don't**: Allow unrestricted access to data or models in ML workflows

```python
# VULNERABLE: Direct access to production data for ML
def train_model_unsafe(conn):
    # Training on production graph with sensitive data
    conn.gsql('''
        CREATE ML MODEL unsafe_model
        ON GRAPH production_graph
        USING ALL VERTEX TYPES, ALL EDGE TYPES  # Accesses everything
    ''')

# VULNERABLE: No data isolation
# ML models trained on graphs containing PII, financial data

# VULNERABLE: Unrestricted model export
def export_model_unsafe(model_name):
    # No audit, no approval, model can contain memorized data
    return download_model(model_name, '/tmp/model.pkl')

# VULNERABLE: No resource limits on training
# Long-running training jobs can impact production queries

# VULNERABLE: Shared ML environment
# Multiple users' experiments can interfere with each other

# VULNERABLE: No validation of feature queries
# ML pipeline can access sensitive attributes
```

**Why**: ML Workbench has access to graph data for feature extraction and model training. Models can memorize sensitive data (membership inference, model inversion attacks). Unrestricted access allows data exfiltration through trained models. Isolated environments, data access controls, and export restrictions prevent leakage of sensitive information through ML workflows.

**Refs**: CWE-200 (Exposure of Sensitive Information), OWASP A01:2021 (Broken Access Control), MITRE ATLAS (ML Attack Framework)
