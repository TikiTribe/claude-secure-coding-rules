# Terraform Security Rules

This document provides Terraform-specific security rules for Claude Code. These rules ensure infrastructure code follows security best practices and compliance requirements.

---

## Rule 1: Backend State Encryption

**Level**: `strict`

**When**: Configuring Terraform backend for state storage

**Do**:
```hcl
# AWS S3 with KMS encryption
terraform {
  backend "s3" {
    bucket         = "company-terraform-state-prod"
    key            = "infrastructure/prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    dynamodb_table = "terraform-state-lock"

    # Additional security settings
    # acl argument removed: ACL-based access control deprecated in TF AWS provider >= 4.x.
    # Public access is blocked via aws_s3_bucket_public_access_block (see below).
    skip_metadata_api_check = false
  }
}

# S3 bucket configuration for state
resource "aws_s3_bucket" "terraform_state" {
  bucket = "company-terraform-state-prod"

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name        = "Terraform State"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.key_id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS key for state encryption
resource "aws_kms_key" "terraform_state" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Terraform Role"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/TerraformRole"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name      = "terraform-state-key"
    ManagedBy = "terraform"
  }
}
```

```hcl
# GCS with Customer-Managed Encryption Key (CMEK)
#
# IMPORTANT: The GCS backend block's encryption_key field expects a 32-byte
# base64-encoded AES-256 Customer-Supplied Encryption Key (CSEK), NOT a
# Cloud KMS resource path. Placing a KMS path there causes terraform init to
# silently misconfigure encryption or fail at runtime.
#
# The correct approach for KMS-based CMEK is to configure it on the
# google_storage_bucket resource (default_kms_key_name), not in the backend block.
# The backend block below has no encryption_key argument; bucket-level CMEK
# is enforced via the resource definition.

resource "google_storage_bucket" "terraform_state" {
  name          = "terraform-state-${var.project_id}"
  location      = "US"
  force_destroy = false

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = "projects/${var.project_id}/locations/us/keyRings/terraform/cryptoKeys/state"
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 5
    }
    action {
      type = "Delete"
    }
  }
}

terraform {
  backend "gcs" {
    bucket = "terraform-state-PROJECT_ID"  # Set per-project via -backend-config
    prefix = "infrastructure"
    # CMEK is enforced at the bucket level (above). The backend block does not
    # accept a KMS key — the encryption_key field is for CSEK (32-byte base64
    # AES-256 key) only, not a KMS resource path.
  }
}
```

```hcl
# Azure Blob Storage with encryption
terraform {
  backend "azurerm" {
    resource_group_name  = "terraform-state-rg"
    storage_account_name = "companyterraformstate"
    container_name       = "tfstate"
    key                  = "prod.terraform.tfstate"
    use_azuread_auth     = true  # Use Azure AD instead of access keys
  }
}

# Storage account configuration
resource "azurerm_storage_account" "terraform_state" {
  name                     = "companyterraformstate"
  resource_group_name      = azurerm_resource_group.terraform_state.name
  location                 = azurerm_resource_group.terraform_state.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  min_tls_version                 = "TLS1_2"
  enable_https_traffic_only       = true
  allow_nested_items_to_be_public = false

  identity {
    type = "SystemAssigned"
  }

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action             = "Deny"
    ip_rules                   = var.allowed_ips
    virtual_network_subnet_ids = [azurerm_subnet.terraform.id]
  }

  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.terraform_state.id
    user_assigned_identity_id = azurerm_user_assigned_identity.terraform.id
  }

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

**Don't**:
```hcl
# VULNERABLE: Local state (unencrypted, no locking)
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
    region = "us-east-1"
    # Missing: encrypt = true
    # Missing: kms_key_id
    # Missing: dynamodb_table for locking
  }
}

# VULNERABLE: Using AES256 instead of KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # S3-managed, not customer-controlled
    }
  }
}

# VULNERABLE: No versioning
resource "aws_s3_bucket" "terraform_state" {
  bucket = "terraform-state"
  # Missing versioning - can't recover from corruption
}
```

**Why**: State files contain sensitive information including resource IDs, connection strings, passwords, and potentially private keys. Unencrypted state exposes this data to anyone with storage access. KMS/CMEK encryption provides customer-controlled keys with audit trails. Versioning enables recovery from corruption or accidental deletion.

**Refs**: CWE-311 (Missing Encryption of Sensitive Data), NIST 800-53 SC-28 (Protection of Information at Rest), CIS AWS 2.1.1, Checkov CKV_AWS_41

---

## Rule 2: No Hardcoded Credentials

**Level**: `strict`

**When**: Configuring providers, data sources, or resources requiring authentication

**Do**:
```hcl
# Use environment variables for provider authentication
provider "aws" {
  region = var.aws_region
  # AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from environment
  # Or use IAM role
}

# Use IAM roles (preferred for AWS)
provider "aws" {
  region = var.aws_region

  assume_role {
    role_arn     = var.terraform_role_arn
    session_name = "terraform-${var.environment}"
    external_id  = var.external_id
  }
}

# Use data sources for secrets
data "aws_secretsmanager_secret_version" "database" {
  secret_id = "prod/database/credentials"
}

locals {
  db_credentials = jsondecode(data.aws_secretsmanager_secret_version.database.secret_string)
}

resource "aws_db_instance" "main" {
  identifier     = "production-database"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  username = local.db_credentials.username
  password = local.db_credentials.password

  # ... other configuration
}

# Use variables for sensitive inputs
variable "api_key" {
  description = "API key for external service"
  type        = string
  sensitive   = true
}

# Use Vault for secrets
data "vault_kv_secret_v2" "app_secrets" {
  mount = "secret"
  name  = "app/production"
}

resource "kubernetes_secret" "app" {
  metadata {
    name = "app-secrets"
  }

  data = {
    api_key = data.vault_kv_secret_v2.app_secrets.data["api_key"]
  }
}
```

```hcl
# Generate passwords securely
resource "random_password" "database" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Store generated password in Secrets Manager
resource "aws_secretsmanager_secret" "database" {
  name                    = "prod/database/master-password"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username = "admin"
    password = random_password.database.result
  })
}
```

**Don't**:
```hcl
# VULNERABLE: Hardcoded credentials in provider
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# VULNERABLE: Hardcoded database password
resource "aws_db_instance" "main" {
  identifier     = "production-database"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  username       = "admin"
  password       = "SuperSecretPassword123!"  # Never do this
}

# VULNERABLE: Hardcoded API key
resource "aws_ssm_parameter" "api_key" {
  name  = "/app/api_key"
  type  = "SecureString"
  value = "sk-1234567890abcdef"  # Never do this
}

# VULNERABLE: Credentials in terraform.tfvars (committed to git)
# terraform.tfvars
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
db_password    = "SuperSecretPassword123!"

# VULNERABLE: Credentials in local variables
locals {
  db_password = "SuperSecretPassword123!"  # Will be in state file
}
```

**Why**: Hardcoded credentials in Terraform files are committed to version control, exposing them to anyone with repository access. Credentials in state files persist even after removal from code. Leaked credentials enable account takeover, data breaches, and cryptomining attacks. Credential rotation requires code changes when hardcoded.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-259 (Hardcoded Password), NIST 800-53 IA-5 (Authenticator Management), Checkov CKV_AWS_41, tfsec aws-vpc-no-public-ingress-sgr

---

## Rule 3: Provider Version Pinning

**Level**: `strict`

**When**: Configuring Terraform providers in required_providers block

**Do**:
```hcl
terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.31.0"  # Allow patch updates only
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 3.85.0"  # Exact version for critical infrastructure
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.10.0, < 6.0.0"  # Allow minor updates
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      # Two-component pessimistic constraint: ~> 2.24 allows MINOR + PATCH updates
      # (>= 2.24.0, < 3.0.0). For patch-only updates, use ~> 2.24.0 (three components).
      version = "~> 2.24"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

# Always commit the lock file
# .terraform.lock.hcl should be in version control

# Document provider update procedures
# 1. Review changelog for security fixes
# 2. Test in non-production environment
# 3. Update version constraint
# 4. Run terraform init -upgrade
# 5. Review terraform plan for unexpected changes
# 6. Commit updated .terraform.lock.hcl
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
      version = ">= 2.0"  # Allows any version from 2.0 to latest
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 0.0.0"  # Effectively no constraint
    }
  }
}

# DANGEROUS: Ignoring lock file
# .gitignore
.terraform.lock.hcl  # Don't ignore this!
```

**Why**: Unpinned providers can introduce breaking changes, security vulnerabilities, or malicious code. Provider updates may change resource behavior unexpectedly. The lock file ensures reproducible builds and prevents supply chain attacks through compromised provider versions.

**Refs**: CWE-1104 (Use of Unmaintained Third Party Components), NIST 800-53 SA-12 (Supply Chain Protection), Checkov CKV_TF_1

---

## Rule 4: Module Source Validation

**Level**: `strict`

**When**: Using external modules from registries or git repositories

**Do**:
```hcl
# Use official verified modules from Terraform Registry
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"  # Exact version pinned

  name = "production-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = false

  tags = local.common_tags
}

# Use private registry for internal modules
module "compliance" {
  source  = "app.terraform.io/company-name/compliance/aws"
  version = "2.3.1"

  # ... configuration
}

# Git source with specific tag
module "custom_network" {
  source = "git::https://github.com/company/terraform-modules.git//network?ref=v1.2.3"

  # ... configuration
}

# Git source with specific commit (most secure)
module "security_baseline" {
  source = "git::https://github.com/company/terraform-modules.git//security?ref=abc123def456789"

  # ... configuration
}

# SSH git source (requires authentication)
module "internal" {
  source = "git::ssh://git@github.com/company/terraform-modules.git//internal?ref=v1.0.0"

  # ... configuration
}
```

**Don't**:
```hcl
# VULNERABLE: No version pinning
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  # Missing version - will use latest
}

# VULNERABLE: Using branch reference
module "custom" {
  source = "git::https://github.com/company/terraform-modules.git//module?ref=main"
  # Main branch can change without notice
}

# VULNERABLE: Unverified public module
module "sketchy" {
  source  = "unknown-user/unverified-module/aws"
  version = "1.0.0"
  # No verification of module authenticity
}

# VULNERABLE: HTTP without integrity check
module "unsafe" {
  source = "http://example.com/modules/network.zip"
  # No way to verify integrity
}

# VULNERABLE: Loose version constraint
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = ">= 1.0.0"  # Too loose
}
```

**Why**: Unpinned modules can change without notice, introducing vulnerabilities or breaking changes. Supply chain attacks target popular modules. Branch references allow attackers with repository access to inject malicious code. Version pinning ensures reproducible builds and allows security review before updates.

**Refs**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), NIST 800-53 SA-12 (Supply Chain Protection), Checkov CKV_TF_1

---

## Rule 5: Sensitive Variable Marking

**Level**: `strict`

**When**: Defining variables that contain secrets, passwords, keys, tokens, or sensitive data

**Do**:
```hcl
# Mark all sensitive variables
variable "database_password" {
  description = "Master password for RDS instance"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.database_password) >= 16
    error_message = "Database password must be at least 16 characters"
  }
}

variable "api_key" {
  description = "API key for external service"
  type        = string
  sensitive   = true
}

variable "ssh_private_key" {
  description = "SSH private key for EC2 instances"
  type        = string
  sensitive   = true
}

variable "tls_private_key" {
  description = "TLS private key for load balancer"
  type        = string
  sensitive   = true
}

variable "oauth_client_secret" {
  description = "OAuth client secret"
  type        = string
  sensitive   = true
}

# Mark sensitive outputs
output "database_connection_string" {
  description = "Database connection string with credentials"
  value       = "postgresql://${aws_db_instance.main.username}:${var.database_password}@${aws_db_instance.main.endpoint}/${aws_db_instance.main.db_name}"
  sensitive   = true
}

output "api_endpoint_with_key" {
  description = "API endpoint with authentication"
  value       = "https://api.example.com?key=${var.api_key}"
  sensitive   = true
}

# Mark sensitive locals
locals {
  # This won't prevent state storage but documents intent
  connection_string = sensitive("postgresql://${aws_db_instance.main.username}:${var.database_password}@${aws_db_instance.main.endpoint}")
}
```

**Don't**:
```hcl
# VULNERABLE: Unmarked sensitive variable
variable "database_password" {
  description = "Master password for RDS instance"
  type        = string
  # Missing: sensitive = true
}

variable "api_key" {
  description = "API key for external service"
  type        = string
  # Missing: sensitive = true
}

# VULNERABLE: Exposing sensitive data in output
output "database_password" {
  description = "Database password"
  value       = var.database_password
  # Missing: sensitive = true - will show in plaintext
}

output "full_connection_string" {
  value = "postgresql://admin:${var.database_password}@${aws_db_instance.main.endpoint}/mydb"
  # Contains password but not marked sensitive
}
```

**Why**: Unmarked sensitive values appear in plan output, state files, and logs in plaintext. This exposes secrets in CI/CD logs, shared terminals, and audit trails. Terraform 0.14+ masks sensitive values in output but they still exist in state. Marking values as sensitive provides defense in depth.

**Refs**: CWE-532 (Insertion of Sensitive Information into Log File), CWE-200 (Exposure of Sensitive Information), NIST 800-53 AU-3 (Content of Audit Records)

---

## Rule 6: Remote State Data Source Security

**Level**: `warning`

**When**: Using terraform_remote_state data source to access state from other configurations

**Do**:
```hcl
# Use outputs instead of direct state access when possible
data "terraform_remote_state" "network" {
  backend = "s3"

  config = {
    bucket         = "company-terraform-state"
    key            = "network/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"

    # Use role assumption for cross-account access
    role_arn = "arn:aws:iam::${var.network_account_id}:role/TerraformStateReader"
  }
}

# Access only non-sensitive outputs
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t3.micro"

  # Use specific outputs, not entire state
  subnet_id              = data.terraform_remote_state.network.outputs.private_subnet_ids[0]
  vpc_security_group_ids = [data.terraform_remote_state.network.outputs.app_security_group_id]
}
```

```hcl
# Better: Use data sources instead of remote state
data "aws_vpc" "main" {
  tags = {
    Environment = var.environment
    Name        = "main-vpc"
  }
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }

  tags = {
    Tier = "private"
  }
}

resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  subnet_id     = data.aws_subnets.private.ids[0]
}
```

```hcl
# Use Terraform Cloud/Enterprise workspaces with controlled outputs
data "tfe_outputs" "network" {
  organization = "company"
  workspace    = "network-production"
}

resource "aws_instance" "app" {
  subnet_id = data.tfe_outputs.network.values.private_subnet_id
}
```

**Don't**:
```hcl
# VULNERABLE: Accessing state with embedded secrets
data "terraform_remote_state" "database" {
  backend = "s3"

  config = {
    bucket = "terraform-state"
    key    = "database/terraform.tfstate"
    region = "us-east-1"
  }
}

# This exposes database password to this configuration's state
locals {
  db_password = data.terraform_remote_state.database.outputs.master_password
}

# VULNERABLE: No encryption or access control
data "terraform_remote_state" "shared" {
  backend = "s3"

  config = {
    bucket = "terraform-state"
    key    = "shared.tfstate"
    region = "us-east-1"
    # Missing: encrypt, role_arn, proper access controls
  }
}

# VULNERABLE: Accessing internal state details
resource "aws_instance" "app" {
  # Directly accessing resources instead of outputs
  subnet_id = data.terraform_remote_state.network.outputs.aws_subnet.private[0].id
}
```

**Why**: Remote state contains all resources and potentially sensitive outputs. Accessing another configuration's state creates tight coupling and potential secret exposure. Using specific outputs limits exposure. Data sources are preferred because they don't copy secrets between states.

**Refs**: CWE-200 (Exposure of Sensitive Information), NIST 800-53 AC-4 (Information Flow Enforcement)

---

## Rule 7: IAM Least Privilege for Provisioned Resources

**Level**: `strict`

**When**: Creating IAM roles, policies, users, or any resource with permissions

**Do**:
```hcl
# Specific actions and resources
resource "aws_iam_policy" "app_s3_access" {
  name        = "app-s3-access"
  description = "Allow application to access specific S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadWriteAppBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.app_data.arn,
          "${aws_s3_bucket.app_data.arn}/*"
        ]
      }
    ]
  })
}

# Use conditions to further restrict
resource "aws_iam_policy" "restricted_access" {
  name = "restricted-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowWithConditions"
        Effect = "Allow"
        Action = [
          "ec2:StartInstances",
          "ec2:StopInstances"
        ]
        Resource = "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = var.environment
          }
        }
      }
    ]
  })
}

# Separate policies for different functions
resource "aws_iam_role" "lambda_function" {
  name = "lambda-processor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Only CloudWatch Logs permissions needed
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_function.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Specific SQS permissions
resource "aws_iam_role_policy" "lambda_sqs" {
  name = "lambda-sqs-access"
  role = aws_iam_role.lambda_function.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.processor.arn
      }
    ]
  })
}
```

**Don't**:
```hcl
# VULNERABLE: Wildcard actions
resource "aws_iam_policy" "admin" {
  name = "app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# VULNERABLE: Overly broad S3 permissions
resource "aws_iam_policy" "s3_full" {
  name = "s3-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      }
    ]
  })
}

# VULNERABLE: Using AWS managed admin policies
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# VULNERABLE: Broad EC2 permissions without conditions
resource "aws_iam_policy" "ec2_access" {
  name = "ec2-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ec2:*"
        Resource = "*"
        # No conditions to restrict by tag or region
      }
    ]
  })
}
```

**Why**: Overly permissive IAM policies violate least privilege and expand blast radius of credential compromise. Wildcard permissions allow attackers to access any resource. Specific actions and resource ARNs limit damage from compromised credentials. Conditions provide additional access controls.

**Refs**: CWE-250 (Execution with Unnecessary Privileges), CWE-732 (Incorrect Permission Assignment), NIST 800-53 AC-6 (Least Privilege), CIS AWS 1.16, Checkov CKV_AWS_62

---

## Rule 8: Resource Tagging for Compliance

**Level**: `warning`

**When**: Creating any infrastructure resource

**Do**:
```hcl
# Define common tags in locals
locals {
  common_tags = {
    Environment        = var.environment
    Project            = var.project_name
    ManagedBy          = "terraform"
    Repository         = var.repository_url
    CostCenter         = var.cost_center
    Owner              = var.team_email
    DataClassification = var.data_classification
    ComplianceScope    = var.compliance_scope
  }
}

# Use default_tags in provider
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

# Add resource-specific tags
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t3.micro"

  tags = {
    Name     = "app-server-${var.environment}"
    Function = "application"
    # Common tags applied automatically via default_tags
  }
}

# Enforce tagging with IAM policy
resource "aws_organizations_policy" "require_tags" {
  name        = "require-tags"
  description = "Require specific tags on resource creation"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RequireEnvironmentTag"
        Effect    = "Deny"
        Action    = ["ec2:RunInstances"]
        Resource  = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          Null = {
            "aws:RequestTag/Environment" = "true"
          }
        }
      },
      {
        Sid       = "RequireManagedByTag"
        Effect    = "Deny"
        Action    = ["ec2:RunInstances", "rds:CreateDBInstance", "s3:CreateBucket"]
        Resource  = "*"
        Condition = {
          Null = {
            "aws:RequestTag/ManagedBy" = "true"
          }
        }
      }
    ]
  })
}

# Validate tags in CI
# checkov --check CKV_AWS_153  # Ensure tags are present
```

**Don't**:
```hcl
# VULNERABLE: No tags
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  # No tags - can't identify owner, environment, or compliance scope
}

# VULNERABLE: Incomplete tagging
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t3.micro"

  tags = {
    Name = "my-instance"
    # Missing: Environment, ManagedBy, Owner, etc.
  }
}

# VULNERABLE: Inconsistent tagging
resource "aws_instance" "app1" {
  tags = {
    env = "prod"  # Inconsistent key
  }
}

resource "aws_instance" "app2" {
  tags = {
    Environment = "production"  # Different value format
  }
}
```

**Why**: Tags enable cost allocation, access control, compliance reporting, and incident response. Missing tags make it impossible to identify resource owners during security incidents. Consistent tagging allows policy enforcement and automated compliance checks. Organizations often require specific tags for audit purposes.

**Refs**: CIS AWS 1.22, NIST 800-53 AU-3 (Content of Audit Records), AWS Tagging Best Practices

---

## Rule 9: Lifecycle prevent_destroy for Critical Resources

**Level**: `warning`

**When**: Managing critical infrastructure that should not be accidentally deleted

**Do**:
```hcl
# Protect production databases
resource "aws_db_instance" "production" {
  identifier     = "production-database"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.r6g.large"

  deletion_protection = true
  skip_final_snapshot = false
  # Use a static identifier — timestamp() evaluated at plan time produces a perpetual
  # diff on every plan. prevent_destroy is the durable protection; the static name
  # is sufficient to identify the final snapshot.
  final_snapshot_identifier = "${var.db_name}-final-snapshot"

  lifecycle {
    prevent_destroy = true
  }

  tags = local.common_tags
}

# Protect state storage
resource "aws_s3_bucket" "terraform_state" {
  bucket = "company-terraform-state"

  lifecycle {
    prevent_destroy = true
  }
}

# Protect production load balancer
resource "aws_lb" "production" {
  name               = "production-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = true

  lifecycle {
    prevent_destroy = true
  }
}

# Protect KMS keys
resource "aws_kms_key" "database" {
  description             = "KMS key for database encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  lifecycle {
    prevent_destroy = true
  }
}

# Protect VPCs with production workloads
resource "aws_vpc" "production" {
  cidr_block = "10.0.0.0/16"

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "production-vpc"
  })
}
```

**Don't**:
```hcl
# RISKY: No protection for critical resources
resource "aws_db_instance" "production" {
  identifier     = "production-database"
  engine         = "postgres"
  instance_class = "db.r6g.large"

  # Missing: deletion_protection = true
  # Missing: lifecycle { prevent_destroy = true }
  skip_final_snapshot = true  # No backup before deletion
}

# RISKY: Terraform state bucket without protection
resource "aws_s3_bucket" "terraform_state" {
  bucket = "terraform-state"
  # Missing: lifecycle { prevent_destroy = true }
}

# RISKY: Using prevent_destroy on all resources
resource "aws_instance" "web" {
  # ...
  lifecycle {
    prevent_destroy = true  # Makes scaling/updates difficult
  }
}
```

**Why**: Accidental deletion of critical resources causes outages, data loss, and extended recovery time. prevent_destroy catches accidental terraform destroy commands. deletion_protection prevents API-level deletion. Combined with snapshots, these provide defense in depth against data loss.

**Refs**: NIST 800-53 CP-9 (System Backup), CIS AWS 2.1.5

---

## Rule 10: Workspace Isolation

**Level**: `warning`

**When**: Managing multiple environments or tenants with Terraform

**Do**:
```hcl
# Use workspaces for environment isolation
terraform {
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state"
    dynamodb_table = "terraform-state-lock"

    # Workspace-specific state paths
    workspace_key_prefix = "env"
  }
}

# Environment-specific configuration
locals {
  environment = terraform.workspace

  environment_config = {
    development = {
      instance_type    = "t3.small"
      min_size         = 1
      max_size         = 2
      deletion_protect = false
    }
    staging = {
      instance_type    = "t3.medium"
      min_size         = 2
      max_size         = 4
      deletion_protect = false
    }
    production = {
      instance_type    = "t3.large"
      min_size         = 3
      max_size         = 10
      deletion_protect = true
    }
  }

  config = local.environment_config[local.environment]
}

# Apply workspace-specific settings
resource "aws_autoscaling_group" "app" {
  name                = "app-${local.environment}"
  min_size            = local.config.min_size
  max_size            = local.config.max_size
  vpc_zone_identifier = var.subnet_ids

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
}
```

```hcl
# Alternative: Separate state files per environment
# IMPORTANT: Terraform backend blocks do NOT support variable references — using
# ${var.environment} inside a backend block causes "terraform init" to fail with
# "Variables not allowed." Set the key via the -backend-config CLI flag instead.
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    # key is set via -backend-config flag at init time:
    #   terraform init -backend-config="key=dev/infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
    kms_key_id     = "alias/terraform-state"
  }
}
```

```bash
# Per-environment Terraform init pattern
terraform init -backend-config="key=${ENVIRONMENT}/infrastructure/terraform.tfstate"
# Where ENVIRONMENT is set in the calling shell or CI/CD pipeline.
```

```hcl
# With separate directories
# environments/
#   development/
#     main.tf
#     terraform.tfvars
#   staging/
#     main.tf
#     terraform.tfvars
#   production/
#     main.tf
#     terraform.tfvars
```

**Don't**:
```hcl
# DANGEROUS: Single state for all environments
terraform {
  backend "s3" {
    bucket = "terraform-state"
    key    = "all-environments.tfstate"  # Everything in one state
  }
}

# DANGEROUS: Hardcoded environment
locals {
  environment = "production"  # Can't safely manage other environments
}

# DANGEROUS: No environment differentiation
resource "aws_instance" "app" {
  instance_type = "t3.large"  # Same for all environments
  # No way to have different settings per environment
}

# RISKY: Using default workspace for production
# terraform workspace list
# * default  <- Production in default workspace
#   staging
```

**Why**: Environment isolation prevents accidental production changes when working on staging. Separate states limit the blast radius of mistakes. Workspace-specific configurations ensure appropriate resource sizing and security controls per environment. Production should never be in the default workspace.

**Refs**: NIST 800-53 SC-32 (Information System Partitioning)

---

## Rule 11: Plan Output Review Before Apply

**Level**: `strict`

**When**: Applying infrastructure changes

**Do**:
```bash
# Always plan before apply
terraform plan -out=plan.tfplan

# Review the plan thoroughly
terraform show plan.tfplan

# Check for unexpected changes
terraform show -json plan.tfplan | jq '.resource_changes[] | select(.change.actions[] != "no-op") | {address, actions: .change.actions}'

# Apply the reviewed plan
terraform apply plan.tfplan
```

```yaml
# CI/CD pipeline with plan review
name: Terraform
on:
  pull_request:
    paths:
      - '**.tf'
      - '**.tfvars'
  push:
    branches: [main]

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        run: terraform init

      - name: Terraform Plan
        id: plan
        run: terraform plan -out=plan.tfplan -no-color
        continue-on-error: true

      - name: Comment PR with Plan
        uses: actions/github-script@v7
        if: github.event_name == 'pull_request'
        with:
          script: |
            const output = `#### Terraform Plan 📖
            \`\`\`
            ${{ steps.plan.outputs.stdout }}
            \`\`\`
            `;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output
            })

      - name: Upload Plan
        uses: actions/upload-artifact@v4
        with:
          name: terraform-plan
          path: plan.tfplan

  apply:
    runs-on: ubuntu-latest
    needs: plan
    if: github.ref == 'refs/heads/main'
    environment: production  # Requires manual approval
    steps:
      - uses: actions/checkout@v4

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

# DANGEROUS: Piping plan directly to apply
terraform plan | terraform apply

# RISKY: Auto-approve in CI without manual gate
- name: Apply
  run: terraform apply -auto-approve
  # No approval required for production changes
```

**Why**: The plan shows exactly what will change. Applying without review can delete critical resources, expose sensitive data, or create security vulnerabilities. Saved plan files ensure what was reviewed is what gets applied. Manual approval gates prevent unauthorized production changes.

**Refs**: NIST 800-53 CM-3 (Configuration Change Control), NIST 800-53 CM-5 (Access Restrictions for Change)

---

## Rule 12: Checkov and tfsec Integration

**Level**: `warning`

**When**: Setting up CI/CD pipelines or running security scans

**Do**:
```yaml
# GitHub Actions with comprehensive scanning
name: Terraform Security
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

      - name: Run Trivy (IaC scan)
        # aquasecurity/tfsec-action archived 2023; Trivy supersedes it.
        # Pin to a SHA before merge: replace <SHA> with the current commit hash
        # from https://github.com/aquasecurity/trivy-action/releases
        uses: aquasecurity/trivy-action@<SHA>  # v0.x - update to current SHA before merge
        with:
          scan-type: config
          hide-progress: false
          format: sarif
          output: trivy-results.sarif
          exit-code: "1"

      - name: Run Checkov
        # Pin to a SHA before merge: replace <SHA> with the current commit hash
        # from https://github.com/bridgecrewio/checkov-action/releases
        uses: bridgecrewio/checkov-action@<SHA>  # v12.x - update to current SHA before merge
        with:
          directory: .
          framework: terraform
          output_format: sarif
          output_file_path: checkov-results.sarif
          soft_fail: false
          skip_check: CKV_AWS_999  # Document any skips with reason
          # Uncomment for compliance frameworks
          # check: CKV_AWS,CIS_AWS

      - name: Upload tfsec SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tfsec-results.sarif
          category: tfsec

      - name: Upload Checkov SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: checkov-results.sarif
          category: checkov
```

```hcl
# Document security findings suppressions
# Suppression with documented reason
# checkov:skip=CKV_AWS_144:Cross-region replication handled by separate DR process
resource "aws_s3_bucket" "logs" {
  bucket = "application-logs"
}

# tfsec:ignore:aws-s3-enable-versioning
# Reason: Log bucket with lifecycle policy, versioning not required
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Disabled"
  }
}
```

```yaml
# Pre-commit hooks for local scanning
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.83.5
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_tfsec
        args:
          - --args=--soft-fail  # Local development only
      - id: terraform_checkov
        args:
          - --args=--framework terraform
```

```bash
# Local development scanning
# Install tools
brew install tfsec
pip install checkov

# Run scans
tfsec .
checkov -d .

# Scan specific checks
checkov -d . --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_21

# Generate baseline (for existing projects)
checkov -d . --create-baseline
```

**Don't**:
```yaml
# DANGEROUS: No security scanning
name: Terraform
jobs:
  apply:
    steps:
      - uses: actions/checkout@v4
      - run: terraform apply -auto-approve
      # No security checks before apply

# VULNERABLE: Unpinned branch ref + soft fail on all checks
- name: Run Checkov
  uses: bridgecrewio/checkov-action@<SHA>  # v12.x - update to current SHA before merge
  with:
    soft_fail: true  # All failures ignored

# POOR: Unpinned branch ref + skipping checks without documentation
- name: Run Checkov
  uses: bridgecrewio/checkov-action@<SHA>  # v12.x - update to current SHA before merge
  with:
    skip_check: CKV_AWS_18,CKV_AWS_19,CKV_AWS_21,CKV_AWS_23,CKV_AWS_144
    # No documentation why these are skipped
```

```hcl
# POOR: Suppressing without reason
# checkov:skip=CKV_AWS_144
# tfsec:ignore:aws-s3-enable-versioning
resource "aws_s3_bucket" "data" {
  # No explanation for suppressions
}
```

**Why**: Security scanning catches misconfigurations before deployment. Automated checks are consistent and don't miss issues that manual review would. SARIF integration provides visibility in GitHub Security tab. Pre-commit hooks catch issues before they enter version control. Documented suppressions enable audit and review.

**Refs**: NIST 800-53 SA-11 (Developer Security Testing), CIS DevSecOps Benchmark, Checkov Policies, tfsec Rules

---

## Additional Security Best Practices

### Use Secure Defaults

```hcl
# Enable encryption by default for all S3 buckets
resource "aws_s3_bucket_server_side_encryption_configuration" "default" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.key_id
    }
    bucket_key_enabled = true
  }
}

# Block public access by default
resource "aws_s3_bucket_public_access_block" "default" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Implement Network Security

```hcl
# Restrict security group ingress
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  # Specific CIDR for ingress
  ingress {
    description = "HTTPS from load balancer"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.lb.id]
  }

  # Restrict egress to required destinations
  egress {
    description = "HTTPS to required services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_egress_cidrs
  }
}

# Never use 0.0.0.0/0 for sensitive resources
# checkov:skip=CKV_AWS_260 is required for this, document why
```

### Enable Logging and Monitoring

```hcl
# Enable CloudTrail for all regions
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

# Enable VPC flow logs
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}
```

---

## Summary

These 12 Terraform security rules provide comprehensive coverage:

1. **Backend State Encryption** - Protect sensitive state data
2. **No Hardcoded Credentials** - Use secret management
3. **Provider Version Pinning** - Prevent supply chain attacks
4. **Module Source Validation** - Verify module integrity
5. **Sensitive Variable Marking** - Prevent secret exposure in logs
6. **Remote State Security** - Control cross-configuration access
7. **IAM Least Privilege** - Minimize permission scope
8. **Resource Tagging** - Enable compliance and cost tracking
9. **Lifecycle Protection** - Prevent accidental deletion
10. **Workspace Isolation** - Separate environments
11. **Plan Review** - Verify changes before apply
12. **Security Scanning** - Automated vulnerability detection

Implementing these rules ensures Terraform code follows security best practices and compliance requirements.
