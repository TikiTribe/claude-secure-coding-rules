# SQL Security Rules

Security rules for SQL development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Query Security

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Building queries with any external input.

**Do**:
```sql
-- Safe: Parameterized queries (syntax varies by database)

-- PostgreSQL
PREPARE user_query (text, int) AS
  SELECT * FROM users WHERE email = $1 AND status = $2;
EXECUTE user_query('user@example.com', 1);

-- MySQL
PREPARE stmt FROM 'SELECT * FROM users WHERE email = ? AND status = ?';
SET @email = 'user@example.com';
SET @status = 1;
EXECUTE stmt USING @email, @status;

-- SQL Server
EXEC sp_executesql
  N'SELECT * FROM users WHERE email = @email AND status = @status',
  N'@email NVARCHAR(255), @status INT',
  @email = 'user@example.com',
  @status = 1;
```

**Don't**:
```sql
-- VULNERABLE: String concatenation (shown for awareness)
-- These patterns should NEVER be used

-- Concatenation (application code builds this)
-- "SELECT * FROM users WHERE email = '" + userInput + "'"

-- Dynamic SQL without parameterization
DECLARE @sql NVARCHAR(MAX);
SET @sql = 'SELECT * FROM users WHERE email = ''' + @userEmail + '''';
EXEC(@sql);  -- SQL injection vulnerability
```

**Why**: SQL injection is consistently in the OWASP Top 10. It allows attackers to read, modify, or delete data, and potentially execute system commands.

**Refs**: CWE-89, OWASP A03:2025

---

### Rule: Validate Dynamic Identifiers

**Level**: `strict`

**When**: Table or column names come from external sources.

**Do**:
```sql
-- Safe: Whitelist allowed identifiers
-- PostgreSQL
CREATE OR REPLACE FUNCTION safe_query(table_name TEXT)
RETURNS SETOF RECORD AS $$
BEGIN
  IF table_name NOT IN ('users', 'orders', 'products') THEN
    RAISE EXCEPTION 'Invalid table name';
  END IF;

  RETURN QUERY EXECUTE format('SELECT * FROM %I', table_name);
END;
$$ LANGUAGE plpgsql;

-- SQL Server: Whitelist approach
CREATE PROCEDURE SafeQuery
  @TableName NVARCHAR(128)
AS
BEGIN
  IF @TableName NOT IN ('users', 'orders', 'products')
    THROW 50001, 'Invalid table name', 1;

  DECLARE @sql NVARCHAR(MAX) = N'SELECT * FROM ' + QUOTENAME(@TableName);
  EXEC sp_executesql @sql;
END;
```

**Don't**:
```sql
-- VULNERABLE: Unvalidated dynamic identifiers

-- Direct concatenation
DECLARE @sql NVARCHAR(MAX) = 'SELECT * FROM ' + @tableName;
EXEC(@sql);

-- No whitelist validation
EXECUTE format('SELECT * FROM %I', user_provided_table);  -- Could be system tables
```

**Why**: Even with proper quoting, allowing arbitrary table names can expose sensitive system tables or data from other tenants.

**Refs**: CWE-89, CWE-943

---

## Access Control

### Rule: Implement Least Privilege

**Level**: `strict`

**When**: Creating database users and granting permissions.

**Do**:
```sql
-- Safe: Create role with minimal permissions
CREATE ROLE app_reader;
GRANT SELECT ON users, orders, products TO app_reader;

-- Safe: Separate roles for different operations
CREATE ROLE app_writer;
GRANT INSERT, UPDATE ON orders TO app_writer;
-- No DELETE permission

-- Safe: Row-level security (PostgreSQL)
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_orders ON orders
  FOR ALL TO app_user
  USING (user_id = current_setting('app.current_user_id')::INT);

-- Safe: Schema isolation
CREATE SCHEMA tenant_data;
GRANT USAGE ON SCHEMA tenant_data TO app_user;
```

**Don't**:
```sql
-- VULNERABLE: Excessive privileges
GRANT ALL PRIVILEGES ON *.* TO 'app_user'@'%';

-- VULNERABLE: Using superuser for application
CREATE USER app WITH SUPERUSER PASSWORD 'password';

-- VULNERABLE: No row-level security
-- Application can access any user's data with:
-- SELECT * FROM orders WHERE user_id = <any_id>
```

**Why**: Excessive privileges allow SQL injection to cause maximum damage. Least privilege limits the blast radius of security breaches.

**Refs**: CWE-250, CWE-732, OWASP A01:2025

---

### Rule: Protect Sensitive Data

**Level**: `strict`

**When**: Storing sensitive information in databases.

**Do**:
```sql
-- Safe: Hash passwords (done in application, stored as hash)
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,  -- bcrypt/argon2 hash
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Safe: Encrypt sensitive columns
-- PostgreSQL with pgcrypto
CREATE TABLE sensitive_data (
  id SERIAL PRIMARY KEY,
  encrypted_ssn BYTEA,  -- Encrypted at application layer
  ssn_hash VARCHAR(64)  -- For lookups (SHA-256 + salt)
);

-- Safe: Column-level permissions
REVOKE ALL ON users FROM app_reader;
GRANT SELECT (id, email, created_at) ON users TO app_reader;
-- password_hash not accessible

-- Safe: Audit logging
CREATE TABLE audit_log (
  id SERIAL PRIMARY KEY,
  user_id INT,
  action VARCHAR(50),
  table_name VARCHAR(100),
  record_id INT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Don't**:
```sql
-- VULNERABLE: Storing plaintext passwords
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255),
  password VARCHAR(255)  -- Plaintext!
);

-- VULNERABLE: Storing unencrypted PII
CREATE TABLE customers (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255),
  ssn VARCHAR(11),        -- Plaintext SSN
  credit_card VARCHAR(16)  -- Plaintext CC
);

-- VULNERABLE: No access controls on sensitive data
GRANT SELECT ON users TO public;
```

**Why**: Data breaches expose sensitive information. Encryption and access controls limit damage when breaches occur.

**Refs**: CWE-312, CWE-319, OWASP A02:2025

---

## Stored Procedures

### Rule: Secure Stored Procedure Design

**Level**: `warning`

**When**: Creating stored procedures and functions.

**Do**:
```sql
-- Safe: Input validation in procedures
CREATE OR REPLACE FUNCTION get_user(p_user_id INT)
RETURNS TABLE (id INT, email VARCHAR, created_at TIMESTAMP) AS $$
BEGIN
  -- Validate input
  IF p_user_id <= 0 THEN
    RAISE EXCEPTION 'Invalid user ID';
  END IF;

  RETURN QUERY
    SELECT u.id, u.email, u.created_at
    FROM users u
    WHERE u.id = p_user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Safe: Set search_path for SECURITY DEFINER
ALTER FUNCTION get_user(INT) SET search_path = public;

-- Safe: Explicit permissions
REVOKE ALL ON FUNCTION get_user(INT) FROM public;
GRANT EXECUTE ON FUNCTION get_user(INT) TO app_user;
```

**Don't**:
```sql
-- VULNERABLE: Dynamic SQL without parameterization
CREATE PROCEDURE search_users(IN search_term VARCHAR(255))
BEGIN
  SET @sql = CONCAT('SELECT * FROM users WHERE name LIKE ''%', search_term, '%''');
  PREPARE stmt FROM @sql;
  EXECUTE stmt;
END;

-- VULNERABLE: SECURITY DEFINER without search_path
CREATE FUNCTION admin_query()
RETURNS SETOF users AS $$
  SELECT * FROM users;
$$ LANGUAGE sql SECURITY DEFINER;
-- Attacker could manipulate search_path

-- VULNERABLE: No input validation
CREATE PROCEDURE delete_order(order_id INT)
AS $$
  DELETE FROM orders WHERE id = order_id;  -- No ownership check
$$ LANGUAGE sql;
```

**Why**: Stored procedures can be entry points for SQL injection. SECURITY DEFINER functions run with elevated privileges and need careful design.

**Refs**: CWE-89, CWE-269

---

## Query Construction

### Rule: Limit Query Results

**Level**: `warning`

**When**: Querying data that will be returned to users.

**Do**:
```sql
-- Safe: Always use LIMIT for user-facing queries
SELECT id, name, email
FROM users
WHERE status = 'active'
ORDER BY created_at DESC
LIMIT 100 OFFSET 0;

-- Safe: Use pagination
SELECT *
FROM orders
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- Safe: Timeout for long-running queries (PostgreSQL)
SET statement_timeout = '30s';
SELECT * FROM large_table WHERE condition;

-- Safe: Resource limits in MySQL
SELECT /*+ MAX_EXECUTION_TIME(30000) */ *
FROM large_table;
```

**Don't**:
```sql
-- VULNERABLE: Unbounded queries
SELECT * FROM logs;  -- Could return millions of rows

-- VULNERABLE: No pagination
SELECT * FROM orders WHERE user_id = $1;  -- Could be huge

-- VULNERABLE: No timeout on complex queries
SELECT *
FROM a
JOIN b ON a.id = b.a_id
JOIN c ON b.id = c.b_id
WHERE complex_condition;  -- Could run forever
```

**Why**: Unbounded queries can cause denial of service, memory exhaustion, and expose more data than intended.

**Refs**: CWE-770, CWE-400

---

### Rule: Prevent UNION-Based Injection

**Level**: `strict`

**When**: Application uses UNION queries.

**Do**:
```sql
-- Safe: Static UNION queries
SELECT id, name, 'customer' AS type FROM customers
UNION ALL
SELECT id, name, 'vendor' AS type FROM vendors;

-- Safe: Use UNION only with known, static queries
-- Parameterize values, not structure
SELECT id, name FROM users WHERE id = $1
UNION
SELECT id, name FROM archived_users WHERE id = $1;
```

**Don't**:
```sql
-- VULNERABLE: Dynamic UNION (application code)
-- query = "SELECT name FROM users WHERE id = " + userId
-- + " UNION SELECT password FROM users--"

-- This pattern in application code enables:
-- Input: "1 UNION SELECT password FROM users--"
-- Results in: SELECT name FROM users WHERE id = 1
--             UNION SELECT password FROM users--
```

**Why**: UNION injection allows attackers to append additional queries, extracting data from any table the user has access to.

**Refs**: CWE-89, OWASP A03:2025

---

## Database Configuration

### Rule: Secure Database Configuration

**Level**: `strict`

**When**: Setting up database servers.

**Do**:
```sql
-- Safe: Disable dangerous features
-- MySQL
SET GLOBAL local_infile = 0;  -- Disable LOAD DATA LOCAL

-- PostgreSQL: Restrict file access
REVOKE ALL ON FUNCTION pg_read_file(text) FROM public;
REVOKE ALL ON FUNCTION pg_write_file(text, text) FROM public;

-- Safe: Require SSL connections
-- PostgreSQL pg_hba.conf
-- hostssl all all 0.0.0.0/0 scram-sha-256

-- Safe: Set password policies
-- SQL Server
ALTER LOGIN app_user WITH CHECK_POLICY = ON;
ALTER LOGIN app_user WITH CHECK_EXPIRATION = ON;

-- Safe: Audit configuration
-- PostgreSQL
ALTER SYSTEM SET log_statement = 'ddl';
ALTER SYSTEM SET log_connections = on;
```

**Don't**:
```sql
-- VULNERABLE: Allow file system access
GRANT FILE ON *.* TO 'app_user'@'%';

-- VULNERABLE: Disable SSL
-- PostgreSQL: host all all 0.0.0.0/0 md5

-- VULNERABLE: Weak authentication
CREATE USER app WITH PASSWORD 'password123';

-- VULNERABLE: No audit logging
ALTER SYSTEM SET log_statement = 'none';
```

**Why**: Misconfigured databases expose additional attack surface. FILE privilege allows reading system files; weak auth enables credential attacks.

**Refs**: CWE-16, CWE-732, OWASP A05:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Parameterized queries | strict | CWE-89 |
| Validate dynamic identifiers | strict | CWE-943 |
| Least privilege | strict | CWE-250 |
| Protect sensitive data | strict | CWE-312 |
| Secure stored procedures | warning | CWE-89 |
| Limit query results | warning | CWE-770 |
| Prevent UNION injection | strict | CWE-89 |
| Secure configuration | strict | CWE-16 |

---

## Version History

- **v1.0.0** - Initial SQL security rules
