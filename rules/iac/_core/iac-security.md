# Infrastructure as Code Security - Core Principles

This document establishes foundational security principles for all Infrastructure as Code implementations. These rules apply regardless of the specific IaC tool being used.

---

## State File Security

### Rule: Encrypt State Files at Rest

**Level**: `strict`

**When**: Configuring any IaC backend that stores state (Terraform, Pulumi, OpenTofu, etc.)

**Do**:
```hcl
# Terraform - S3 backend with encryption
terraform {
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "prod/infrastructure.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    dynamodb_table = "terraform-state-lock"
  }
}
```

```yaml
# Pulumi - Encrypted backend
name: my-project
runtime: python
backend:
  url: s3://company-pulumi-state?region=us-east-1&awssdk=v2
config:
  encryptionsalt: v1:abc123...
```

**Don't**:
```hcl
# VULNERABLE: Unencrypted local state
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# VULNERABLE: S3 without encryption
terraform {
  backend "s3" {
    bucket = "terraform-state"
    key    = "state.tfstate"
    # Missing: encrypt = true
    # Missing: kms_key_id
  }
}
```

**Why**: State files contain sensitive information including resource IDs, connection strings, passwords, and private keys. Unencrypted state files expose this data to anyone with storage access, leading to credential theft, infrastructure mapping for attacks, and compliance violations.

**Refs**: CWE-311 (Missing Encryption of Sensitive Data), NIST 800-53 SC-28 (Protection of Information at Rest), CIS AWS 2.1.1

---

### Rule: Restrict State File Access

**Level**: `strict`

**When**: Configuring backend storage permissions for IaC state

**Do**:
```jsonc
// AWS S3 bucket policy - restrict to specific roles
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthorizedAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::company-terraform-state",
        "arn:aws:s3:::company-terraform-state/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::123456789012:role/TerraformExecutionRole",
            "arn:aws:iam::123456789012:role/InfrastructureAdminRole"
          ]
        }
      }
    },
    {
      "Sid": "EnforceTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::company-terraform-state",
        "arn:aws:s3:::company-terraform-state/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

```hcl
# GCS bucket with IAM restrictions
resource "google_storage_bucket_iam_binding" "state_access" {
  bucket = google_storage_bucket.terraform_state.name
  role   = "roles/storage.objectAdmin"

  members = [
    "serviceAccount:terraform@project-id.iam.gserviceaccount.com",
  ]
}

# Block public access
resource "google_storage_bucket" "terraform_state" {
  name                        = "company-terraform-state"
  location                    = "US"
  uniform_bucket_level_access = true

  public_access_prevention = "enforced"
}
```

**Don't**:
```jsonc
// VULNERABLE: Public bucket policy
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::terraform-state/*"
    }
  ]
}
```

```hcl
# VULNERABLE: Overly permissive GCS access
resource "google_storage_bucket_iam_binding" "state_access" {
  bucket = google_storage_bucket.terraform_state.name
  role   = "roles/storage.admin"

  members = [
    "allUsers",  # Never do this
  ]
}
```

**Why**: Unrestricted state file access allows attackers to discover infrastructure topology, extract secrets, and plan targeted attacks. State files are high-value targets that should follow least-privilege access principles.

**Refs**: CWE-732 (Incorrect Permission Assignment), NIST 800-53 AC-6 (Least Privilege), CIS AWS 2.1.2

---

### Rule: Enable State Locking

**Level**: `strict`

**When**: Configuring IaC backends for team or automated use

**Do**:
```hcl
# Terraform with DynamoDB locking
terraform {
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "prod/infrastructure.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

# DynamoDB table for locking
resource "aws_dynamodb_table" "terraform_lock" {
  name         = "terraform-state-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Purpose = "Terraform state locking"
  }
}
```

```hcl
# Azure with blob lease locking
terraform {
  backend "azurerm" {
    resource_group_name  = "terraform-state-rg"
    storage_account_name = "companyterraformstate"
    container_name       = "tfstate"
    key                  = "prod.terraform.tfstate"
    use_azuread_auth     = true
  }
}
```

**Don't**:
```hcl
# VULNERABLE: No state locking
terraform {
  backend "s3" {
    bucket = "terraform-state"
    key    = "state.tfstate"
    # Missing: dynamodb_table for locking
  }
}

# DANGEROUS: Force unlock without investigation
# terraform force-unlock LOCK_ID  (run only after confirming no active operations)
```

**Why**: Concurrent state modifications corrupt state files, leading to resource duplication, orphaned resources, and infrastructure inconsistencies. State corruption requires manual intervention and can cause outages.

**Refs**: CWE-362 (Race Condition), NIST 800-53 SC-4 (Information in Shared Resources)

---

## Secrets Management

### Rule: Never Hardcode Credentials

**Level**: `strict`

**When**: Configuring providers, resources, or any component requiring authentication

**Do**:
```hcl
# Use environment variables
provider "aws" {
  region = var.aws_region
  # Credentials from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
}

# Use IAM roles (preferred)
provider "aws" {
  region = var.aws_region
  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/TerraformRole"
  }
}

# Reference secrets from secure stores
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/database/master-password"
}

resource "aws_db_instance" "main" {
  # ...
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}
```

```python
# Pulumi - Use config secrets
import pulumi
from pulumi_aws import rds

config = pulumi.Config()
db_password = config.require_secret("dbPassword")

database = rds.Instance("main",
    password=db_password,
    # ...
)
```

**Don't**:
```hcl
# VULNERABLE: Hardcoded credentials
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# VULNERABLE: Hardcoded database password
resource "aws_db_instance" "main" {
  identifier     = "prod-database"
  engine         = "postgres"
  engine_version = "14"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "SuperSecret123!"  # Never do this
}

# VULNERABLE: Credentials in tfvars committed to git
# terraform.tfvars
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Why**: Hardcoded credentials in IaC files are committed to version control, exposing them to anyone with repository access. Leaked credentials enable account takeover, data breaches, and cryptomining attacks. Credential rotation becomes impossible without code changes.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-259 (Hardcoded Password), NIST 800-53 IA-5 (Authenticator Management)

---

### Rule: Mark Sensitive Variables

**Level**: `strict`

**When**: Defining variables that contain secrets, passwords, keys, or tokens

**Do**:
```hcl
# Terraform - Mark variables as sensitive
variable "database_password" {
  description = "Master password for RDS instance"
  type        = string
  sensitive   = true
}

variable "api_key" {
  description = "API key for external service"
  type        = string
  sensitive   = true
}

# Mark output as sensitive
output "database_connection_string" {
  description = "Database connection string"
  value       = "postgresql://${aws_db_instance.main.username}:${var.database_password}@${aws_db_instance.main.endpoint}/${aws_db_instance.main.db_name}"
  sensitive   = true
}
```

```python
# Pulumi - Use secret outputs
import pulumi

pulumi.export("database_password", pulumi.Output.secret(db_password))
pulumi.export("api_key", pulumi.Output.secret(api_key))
```

**Don't**:
```hcl
# VULNERABLE: Unmarked sensitive variable
variable "database_password" {
  description = "Master password for RDS instance"
  type        = string
  # Missing: sensitive = true
}

# VULNERABLE: Exposing sensitive data in outputs
output "database_password" {
  value = var.database_password  # Will be shown in plaintext
}
```

**Why**: Unmarked sensitive values appear in plan output, state files, and logs in plaintext. This exposes secrets in CI/CD logs, shared terminals, and audit trails. Marking values as sensitive prevents accidental disclosure.

**Refs**: CWE-532 (Insertion of Sensitive Information into Log File), NIST 800-53 AU-3 (Content of Audit Records)

---

### Rule: Use Secret Management Services

**Level**: `warning`

**When**: Managing secrets for infrastructure resources

**Do**:
```hcl
# AWS Secrets Manager
resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "prod/database/credentials"
  recovery_window_in_days = 7

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

resource "aws_secretsmanager_secret_version" "database_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials.id
  secret_string = jsonencode({
    username = "admin"
    password = random_password.db_password.result
  })
}

# Reference in other resources
data "aws_secretsmanager_secret_version" "db_creds" {
  secret_id = aws_secretsmanager_secret.database_credentials.id
}

locals {
  db_credentials = jsondecode(data.aws_secretsmanager_secret_version.db_creds.secret_string)
}
```

```hcl
# HashiCorp Vault
provider "vault" {
  address = "https://vault.company.com:8200"
  # Auth via VAULT_TOKEN environment variable
}

data "vault_kv_secret_v2" "database" {
  mount = "secret"
  name  = "prod/database"
}

resource "aws_db_instance" "main" {
  password = data.vault_kv_secret_v2.database.data["password"]
}
```

```hcl
# Azure Key Vault
data "azurerm_key_vault_secret" "db_password" {
  name         = "database-password"
  key_vault_id = data.azurerm_key_vault.main.id
}

resource "azurerm_mssql_server" "main" {
  administrator_login_password = data.azurerm_key_vault_secret.db_password.value
}
```

**Don't**:
```hcl
# VULNERABLE: Generating secrets without storage
resource "random_password" "db_password" {
  length  = 16
  special = true
}

resource "aws_db_instance" "main" {
  password = random_password.db_password.result
  # Password only exists in state file, no secure backup
}

# VULNERABLE: Storing secrets in SSM without encryption
resource "aws_ssm_parameter" "db_password" {
  name  = "/prod/db/password"
  type  = "String"  # Should be SecureString
  value = var.db_password
}
```

**Why**: Dedicated secret management services provide encryption, access control, audit logging, and rotation capabilities. Storing secrets elsewhere leads to inconsistent security controls and makes rotation difficult.

**Refs**: CWE-522 (Insufficiently Protected Credentials), NIST 800-53 SC-12 (Cryptographic Key Establishment and Management)

---

## Module Supply Chain Security

### Rule: Pin Module Versions

**Level**: `strict`

**When**: Using external modules from registries or git repositories

**Do**:
```hcl
# Pin to specific version from registry
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"  # Exact version

  # ... configuration
}

# Pin to specific git tag
module "security_group" {
  source = "git::https://github.com/company/terraform-modules.git//security-group?ref=v2.3.1"

  # ... configuration
}

# Pin to specific commit (most secure)
module "custom" {
  source = "git::https://github.com/company/terraform-modules.git//custom?ref=abc123def456"

  # ... configuration
}

# Use version constraints carefully
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"  # Only patch updates, review before minor/major

  # ... configuration
}
```

**Don't**:
```hcl
# VULNERABLE: No version pinning
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  # Missing version - will use latest, which could be malicious
}

# VULNERABLE: Using main/master branch
module "custom" {
  source = "git::https://github.com/company/terraform-modules.git//custom?ref=main"
  # Main branch could be compromised
}

# VULNERABLE: Too loose version constraint
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = ">= 0.0.0"  # Accepts any version including malicious ones
}
```

**Why**: Unpinned modules can change without notice, introducing vulnerabilities, breaking changes, or malicious code. Supply chain attacks target popular modules. Version pinning ensures reproducible builds and allows security review before updates.

**Refs**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), NIST 800-53 SA-12 (Supply Chain Protection)

---

### Rule: Verify Module Sources

**Level**: `warning`

**When**: Adding new modules to infrastructure code

**Do**:
```hcl
# Use official HashiCorp partner/verified modules
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"  # Verified publisher
  version = "5.1.2"
}

# Use organization's private registry
module "compliance" {
  source  = "app.terraform.io/company/compliance/aws"
  version = "1.2.0"
}

# Use signed/verified git sources
module "internal" {
  source = "git::ssh://git@github.com/company/terraform-modules.git//network?ref=v1.0.0"
  # Using SSH ensures authentication
}
```

```hcl
# Implement module validation in CI
# .github/workflows/terraform.yml
# - name: Validate module sources
#   run: |
#     # Check for unapproved module sources
#     grep -r "source\s*=" . | grep -v "terraform-aws-modules" | grep -v "app.terraform.io/company"
```

**Don't**:
```hcl
# VULNERABLE: Untrusted public modules
module "sketchy" {
  source  = "random-user/unknown-module/aws"  # Unverified publisher
  version = "1.0.0"
}

# VULNERABLE: HTTP without authentication
module "unsafe" {
  source = "http://example.com/modules/network.zip"
  # No integrity verification
}

# RISKY: Arbitrary GitHub repositories
module "risky" {
  source = "github.com/unknown-org/terraform-module"
  # No way to verify integrity
}
```

**Why**: Malicious modules can exfiltrate secrets, create backdoors, or deploy cryptominers. The Terraform registry has verified publishers, but unverified modules could be malicious. Always audit module code before use.

**Refs**: CWE-494 (Download of Code Without Integrity Check), NIST 800-53 SA-12 (Supply Chain Protection)

---

### Rule: Audit Module Code Before Use

**Level**: `advisory`

**When**: First using a module or updating to a new version

**Do**:
```bash
# Download and review module source
terraform get
cd .terraform/modules/vpc
# Review all .tf files

# Check for suspicious patterns
grep -r "http\|curl\|wget" .terraform/modules/
grep -r "exec\|provisioner" .terraform/modules/
grep -r "external\|data.*external" .terraform/modules/

# Review provider requirements
grep -r "required_providers" .terraform/modules/

# Use automated scanning
checkov -d .terraform/modules/
tfsec .terraform/modules/
```

```hcl
# Document module audit in code
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"  # Audited: 2024-01-15, Ticket: SEC-1234

  # ... configuration
}
```

**Don't**:
```bash
# DANGEROUS: Using modules without review
terraform apply  # Never run without reviewing what modules do

# DANGEROUS: Updating without checking changelog
terraform init -upgrade  # Without reviewing version changes
```

**Why**: Even verified modules can contain vulnerabilities or unintended behaviors. Code review catches issues that automated scanning misses. Audit trails help with incident response and compliance.

**Refs**: CWE-1104 (Use of Unmaintained Third Party Components), NIST 800-53 SA-11 (Developer Security Testing)

---

## Drift Detection and Compliance

### Rule: Implement Continuous Drift Detection

**Level**: `warning`

**When**: Managing production infrastructure with IaC

**Do**:
```yaml
# GitHub Actions - Scheduled drift detection
name: Terraform Drift Detection
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:

jobs:
  detect-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        run: terraform init

      - name: Terraform Plan
        id: plan
        run: terraform plan -detailed-exitcode -out=plan.tfplan
        continue-on-error: true

      - name: Check for Drift
        if: steps.plan.outputs.exitcode == 2
        run: |
          echo "::error::Infrastructure drift detected!"
          terraform show plan.tfplan
          # Send alert to security team
          curl -X POST "${{ secrets.SLACK_WEBHOOK }}" \
            -H 'Content-type: application/json' \
            --data '{"text":"⚠️ Infrastructure drift detected in production!"}'
```

```hcl
# Use Terraform Cloud/Enterprise for continuous drift detection
terraform {
  cloud {
    organization = "company"

    workspaces {
      name = "production"
    }
  }
}

# Configure run triggers for drift detection
# In Terraform Cloud UI:
# - Enable "Automatic speculative plans"
# - Set health check frequency
```

**Don't**:
```bash
# DANGEROUS: Only running plan before changes
# Manual drift detection is unreliable

# DANGEROUS: Ignoring drift warnings
terraform apply -auto-approve  # Without reviewing changes

# DANGEROUS: Not alerting on drift
terraform plan  # Output goes to /dev/null
```

**Why**: Manual changes bypass IaC controls, creating security gaps and compliance violations. Drift indicates unauthorized modifications that may be security incidents. Regular detection allows rapid response to unauthorized changes.

**Refs**: CWE-1188 (Insecure Default Initialization of Resource), NIST 800-53 CM-3 (Configuration Change Control)

---

### Rule: Prevent Manual Infrastructure Changes

**Level**: `warning`

**When**: Operating production infrastructure

**Do**:
```hcl
# Use AWS Service Control Policies to prevent manual changes
resource "aws_organizations_policy" "prevent_manual_changes" {
  name        = "prevent-manual-infrastructure-changes"
  description = "Prevent manual changes to IaC-managed resources"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUntaggedResourceCreation"
        Effect    = "Deny"
        Action    = ["ec2:RunInstances", "rds:CreateDBInstance"]
        Resource  = "*"
        Condition = {
          Null = {
            "aws:RequestTag/ManagedBy" = "true"
          }
        }
      },
      {
        Sid      = "DenyConsoleChanges"
        Effect   = "Deny"
        Action   = ["*"]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/TerraformRole"
            ]
          }
          StringEquals = {
            "aws:RequestTag/ManagedBy" = "terraform"
          }
        }
      }
    ]
  })
}
```

```hcl
# Tag all resources as IaC-managed
locals {
  common_tags = {
    ManagedBy   = "terraform"
    Environment = var.environment
    Project     = var.project_name
    Repository  = var.repository_url
  }
}

resource "aws_instance" "example" {
  # ... configuration

  tags = merge(local.common_tags, {
    Name = "example-instance"
  })
}
```

**Don't**:
```hcl
# VULNERABLE: No protection against manual changes
resource "aws_instance" "example" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  # No tags - can't identify as IaC-managed
}

# VULNERABLE: No policy enforcement
# Allowing all users to make console changes
```

**Why**: Manual changes create configuration drift, security gaps, and audit trail breaks. Enforcing IaC-only changes ensures all modifications are reviewed, tested, and documented. This is essential for compliance and incident response.

**Refs**: NIST 800-53 CM-5 (Access Restrictions for Change), CIS AWS 1.22

---

## Policy as Code

### Rule: Implement Pre-Deployment Policy Checks

**Level**: `warning`

**When**: Running IaC in CI/CD pipelines

**Do**:
```yaml
# GitHub Actions with multiple policy tools
name: Terraform Security Scan
on:
  pull_request:
    paths:
      - '**.tf'
      - '**.tfvars'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform
          output_format: sarif
          soft_fail: false
          skip_check: CKV_AWS_999  # Document any skips

      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          soft_fail: false

      - name: Run Terrascan
        uses: tenable/terrascan-action@main
        with:
          iac_type: 'terraform'
          policy_type: 'aws'
          only_warn: false

      - name: Run OPA Policy Check
        uses: open-policy-agent/setup-opa@v2
        with:
          version: latest
      - run: |
          opa eval --data policies/ --input plan.json "data.terraform.deny[msg]"
```

```rego
# OPA policy for Terraform
# policies/terraform.rego
package terraform

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group_rule"
  resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
  resource.change.after.type == "ingress"
  msg := sprintf("Security group rule %s allows ingress from 0.0.0.0/0", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  not resource.change.after.server_side_encryption_configuration
  msg := sprintf("S3 bucket %s does not have encryption enabled", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  not resource.change.after.storage_encrypted
  msg := sprintf("RDS instance %s does not have storage encryption enabled", [resource.address])
}
```

**Don't**:
```yaml
# VULNERABLE: No policy checks
name: Terraform Apply
on: push
jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: terraform apply -auto-approve
      # No security scanning before apply
```

```yaml
# VULNERABLE: Soft fail on all checks
- name: Run Checkov
  uses: bridgecrewio/checkov-action@master
  with:
    soft_fail: true  # Allows all violations to pass
```

**Why**: Policy as Code catches security misconfigurations before deployment. Manual review misses issues that automated tools catch. Failing builds on violations prevents insecure configurations from reaching production.

**Refs**: NIST 800-53 SA-11 (Developer Security Testing), CIS AWS Foundations Benchmark

---

### Rule: Enforce Compliance Standards

**Level**: `advisory`

**When**: Operating in regulated environments

**Do**:
```yaml
# Checkov with compliance frameworks
- name: Run Checkov with CIS compliance
  uses: bridgecrewio/checkov-action@master
  with:
    directory: .
    framework: terraform
    check: CIS_AWS  # Check against CIS AWS Benchmark
    output_format: junitxml
    output_file_path: reports/

- name: Run Checkov with SOC2 compliance
  uses: bridgecrewio/checkov-action@master
  with:
    directory: .
    check: SOC2
```

```hcl
# Implement compliance tags
locals {
  compliance_tags = {
    DataClassification = var.data_classification  # public, internal, confidential, restricted
    ComplianceScope    = var.compliance_scope     # pci, hipaa, sox, none
    DataRetention      = var.retention_period
  }
}

# Validate compliance requirements
resource "aws_s3_bucket" "data" {
  bucket = "company-data-bucket"

  tags = merge(local.common_tags, local.compliance_tags)
}

# Enforce encryption for confidential data
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.key_id
    }
    bucket_key_enabled = true
  }
}
```

```rego
# OPA policy for compliance
package terraform.compliance

# PCI-DSS: Require encryption for payment data
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.after.tags.ComplianceScope == "pci"
  not has_kms_encryption(resource)
  msg := sprintf("PCI-scoped bucket %s must use KMS encryption", [resource.address])
}

# HIPAA: Require access logging
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.after.tags.ComplianceScope == "hipaa"
  not has_access_logging(resource)
  msg := sprintf("HIPAA-scoped bucket %s must have access logging enabled", [resource.address])
}
```

**Don't**:
```hcl
# VULNERABLE: No compliance tagging
resource "aws_s3_bucket" "pci_data" {
  bucket = "pci-card-data"
  # No compliance tags - can't enforce policies
  # No way to identify data sensitivity
}

# VULNERABLE: Ignoring compliance requirements
resource "aws_s3_bucket_server_side_encryption_configuration" "pci" {
  bucket = aws_s3_bucket.pci_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # PCI requires KMS, not S3-managed
    }
  }
}
```

**Why**: Compliance frameworks provide security requirements for regulated data. Automated enforcement prevents accidental violations that lead to audit findings, fines, and breaches. Tags enable policy engines to apply appropriate controls based on data sensitivity.

**Refs**: PCI-DSS 3.2.1, HIPAA Security Rule, NIST 800-53 SA-15 (Development Process)

---

## Provider and Resource Security

### Rule: Pin Provider Versions

**Level**: `strict`

**When**: Configuring Terraform providers

**Do**:
```hcl
terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.31.0"  # Allow only patch updates
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 3.85.0"  # Exact version for stability
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.10.0, < 6.0.0"  # Minor updates OK
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
```

```hcl
# Use dependency lock file
# Run: terraform init
# Commit: .terraform.lock.hcl

# This ensures everyone uses the same provider versions
```

**Don't**:
```hcl
# VULNERABLE: No version constraints
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Missing version - could get any version
    }
  }
}

# VULNERABLE: Too loose constraints
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 2.0"  # Allows any version 2.0+
    }
  }
}

# DANGEROUS: Not committing lock file
# In .gitignore (wrong - do not add this):
# .terraform.lock.hcl  # This file should be committed, not ignored!
```

**Why**: Unpinned providers can introduce breaking changes or vulnerabilities. The lock file ensures reproducible builds and prevents supply chain attacks through compromised provider versions.

**Refs**: CWE-1104 (Use of Unmaintained Third Party Components), NIST 800-53 SA-12 (Supply Chain Protection)

---

### Rule: Secure Provider Authentication

**Level**: `strict`

**When**: Configuring cloud provider authentication

**Do**:
```hcl
# AWS - Use IAM roles (preferred)
provider "aws" {
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::123456789012:role/TerraformRole"
    session_name = "terraform-${var.environment}"
    external_id  = var.external_id  # For cross-account
  }

  default_tags {
    tags = local.common_tags
  }
}

# Azure - Use service principal with OIDC
provider "azurerm" {
  features {}

  use_oidc        = true
  client_id       = var.azure_client_id
  tenant_id       = var.azure_tenant_id
  subscription_id = var.azure_subscription_id
}

# GCP - Use workload identity
provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  # Uses GOOGLE_APPLICATION_CREDENTIALS or workload identity
}
```

```yaml
# GitHub Actions - OIDC authentication
jobs:
  terraform:
    permissions:
      id-token: write
      contents: read

    steps:
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1
```

**Don't**:
```hcl
# VULNERABLE: Static credentials in provider
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# VULNERABLE: Service account key file
provider "google" {
  project     = "my-project"
  region      = "us-central1"
  credentials = file("service-account.json")  # Don't commit this
}
```

**Why**: Static credentials can be stolen and have unlimited lifetime. IAM roles and OIDC provide short-lived credentials with automatic rotation. Role assumption also provides audit trails of who performed actions.

**Refs**: CWE-798 (Hardcoded Credentials), NIST 800-53 IA-5 (Authenticator Management), CIS AWS 1.16

---

## Security Testing Integration

### Rule: Integrate Security Scanning in CI/CD

**Level**: `warning`

**When**: Setting up IaC CI/CD pipelines

**Do**:
```yaml
# Complete security pipeline
name: Terraform Security Pipeline
on:
  pull_request:
  push:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Format
        run: terraform fmt -check -recursive

      - name: Terraform Validate
        run: terraform validate

  security-scan:
    runs-on: ubuntu-latest
    needs: validate
    steps:
      - uses: actions/checkout@v4

      - name: tfsec
        uses: aquasecurity/tfsec-action@v1.0.0

      - name: Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          output_format: sarif
          output_file_path: results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

  plan:
    runs-on: ubuntu-latest
    needs: security-scan
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4

      - name: Terraform Plan
        run: terraform plan -out=plan.tfplan

      - name: Terraform Show
        run: terraform show -json plan.tfplan > plan.json

      - name: Policy Check
        run: |
          conftest test plan.json -p policies/

      - name: Comment PR
        uses: actions/github-script@v7
        with:
          script: |
            // Post plan output to PR comment
```

**Don't**:
```yaml
# DANGEROUS: No security checks
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: terraform apply -auto-approve
```

**Why**: Security scanning catches misconfigurations before they reach production. Automated checks are consistent and don't miss issues that manual review would. SARIF integration provides visibility in GitHub Security tab.

**Refs**: NIST 800-53 SA-11 (Developer Security Testing), CIS DevSecOps Benchmark

---

### Rule: Review Plan Output Before Apply

**Level**: `strict`

**When**: Applying infrastructure changes

**Do**:
```bash
# Always plan before apply
terraform plan -out=plan.tfplan

# Review the plan
terraform show plan.tfplan

# Apply the reviewed plan
terraform apply plan.tfplan
```

```yaml
# Require manual approval for production
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - name: Terraform Plan
        run: terraform plan -out=plan.tfplan

      - name: Upload Plan
        uses: actions/upload-artifact@v4
        with:
          name: terraform-plan
          path: plan.tfplan

  apply:
    runs-on: ubuntu-latest
    needs: plan
    environment: production  # Requires approval
    steps:
      - name: Download Plan
        uses: actions/download-artifact@v4
        with:
          name: terraform-plan

      - name: Terraform Apply
        run: terraform apply plan.tfplan
```

**Don't**:
```bash
# DANGEROUS: Apply without review
terraform apply -auto-approve

# DANGEROUS: Apply without plan file
terraform apply
# This creates a new plan that may differ from what was reviewed
```

**Why**: The plan shows exactly what will change. Applying without review can delete critical resources or create security vulnerabilities. Saved plan files ensure what was reviewed is what gets applied.

**Refs**: NIST 800-53 CM-3 (Configuration Change Control)

---

## Additional Security Practices

### Rule: Use Workspaces for Environment Isolation

**Level**: `advisory`

**When**: Managing multiple environments with the same IaC code

**Do**:
```hcl
# Use workspaces for environment isolation
# terraform workspace new production
# terraform workspace new staging

locals {
  environment = terraform.workspace

  environment_config = {
    production = {
      instance_type = "t3.large"
      min_size      = 3
      max_size      = 10
    }
    staging = {
      instance_type = "t3.small"
      min_size      = 1
      max_size      = 3
    }
  }
}

resource "aws_instance" "app" {
  instance_type = local.environment_config[local.environment].instance_type
  # ...
}
```

```hcl
# Or use separate state files per environment
terraform {
  backend "s3" {
    bucket = "company-terraform-state"
    key    = "env/${var.environment}/infrastructure.tfstate"
    # ...
  }
}
```

**Don't**:
```hcl
# DANGEROUS: Single state for all environments
terraform {
  backend "s3" {
    bucket = "terraform-state"
    key    = "all-environments.tfstate"
    # Production and staging in same state
  }
}

# RISKY: Hardcoded environment
locals {
  instance_type = "t3.large"  # Same for all environments
}
```

**Why**: Environment isolation prevents accidental production changes when working on staging. Separate states limit blast radius of mistakes. Workspace-specific configurations ensure appropriate resource sizing and security controls.

**Refs**: NIST 800-53 SC-32 (Information System Partitioning)

---

### Rule: Document Security Decisions

**Level**: `advisory`

**When**: Making security-related configuration choices

**Do**:
```hcl
# Document security decisions in code
resource "aws_security_group" "database" {
  name        = "database-sg"
  description = "Security group for database servers"
  vpc_id      = aws_vpc.main.id

  # SECURITY: Only allow traffic from application tier
  # Reviewed: 2024-01-15, Ticket: SEC-1234
  ingress {
    description     = "PostgreSQL from app servers only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  # SECURITY: No egress restrictions needed for database
  # Database makes no outbound connections
  # Reviewed: 2024-01-15
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    SecurityReview = "2024-01-15"
  })
}

# Document suppressed security findings
# tfsec:ignore:aws-ec2-no-public-egress-sgr
resource "aws_security_group_rule" "egress" {
  # Reason: Application requires access to external APIs
  # Compensating control: Egress is logged via VPC flow logs
  # Approved: SEC-1234
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.application.id
}
```

**Don't**:
```hcl
# POOR PRACTICE: No documentation
resource "aws_security_group" "database" {
  name   = "database-sg"
  vpc_id = aws_vpc.main.id

  # Why is this open?
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# POOR PRACTICE: Suppressing without reason
# tfsec:ignore:aws-ec2-no-public-egress-sgr
resource "aws_security_group_rule" "egress" {
  # No explanation why this is acceptable
  # ...
}
```

**Why**: Security decisions need context for future maintainers. Documented decisions enable proper review and audit. Suppression comments without reasons mask potential vulnerabilities. Security tickets provide traceability for compliance audits.

**Refs**: NIST 800-53 AU-3 (Content of Audit Records), CIS Controls 4.8

---

## Summary

These core IaC security principles apply to all Infrastructure as Code tools:

1. **State Security**: Encrypt, restrict access, enable locking
2. **Secrets Management**: Never hardcode, use secret stores, mark sensitive
3. **Supply Chain**: Pin versions, verify sources, audit code
4. **Drift Detection**: Continuous monitoring, prevent manual changes
5. **Policy as Code**: Automated security checks, compliance enforcement
6. **Provider Security**: Pin versions, use IAM roles/OIDC
7. **Testing Integration**: Security scanning in CI/CD, review before apply
8. **Documentation**: Document security decisions and suppressions

Apply these principles consistently across Terraform, Pulumi, CloudFormation, and other IaC tools to maintain secure infrastructure.
