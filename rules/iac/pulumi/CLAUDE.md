# Pulumi Security Rules

This document provides Pulumi-specific security rules for Claude Code. These rules ensure Pulumi infrastructure code follows security best practices across supported languages (TypeScript, Python, Go, C#, Java, YAML).

---

## Rule 1: Stack Secrets Encryption

**Level**: `strict`

**When**: Configuring Pulumi stack secrets and state backend

**Do**:
```typescript
// TypeScript - Use Pulumi Cloud with encryption
// Pulumi.yaml
name: my-infrastructure
runtime: nodejs
backend:
  url: https://api.pulumi.com

// Stack configuration with secrets
// Pulumi.production.yaml
config:
  aws:region: us-east-1
  my-infrastructure:dbPassword:
    secure: AAABADQXFlU0mxA...  // Encrypted by default with Pulumi Cloud
```

```yaml
# Pulumi.yaml - Use AWS KMS for encryption
name: my-infrastructure
runtime: python
backend:
  url: s3://company-pulumi-state?region=us-east-1
secretsprovider: awskms://alias/pulumi-secrets?region=us-east-1
```

```yaml
# Pulumi.yaml - Use Azure Key Vault
name: my-infrastructure
runtime: go
backend:
  url: azblob://pulumistate
secretsprovider: azurekeyvault://mykeyvault.vault.azure.net/keys/pulumi-key
```

```yaml
# Pulumi.yaml - Use GCP KMS
name: my-infrastructure
runtime: python
backend:
  url: gs://company-pulumi-state
secretsprovider: gcpkms://projects/my-project/locations/us/keyRings/pulumi/cryptoKeys/state
```

```yaml
# Pulumi.yaml - Use HashiCorp Vault
name: my-infrastructure
runtime: typescript
backend:
  url: s3://pulumi-state
secretsprovider: hashivault://transit/keys/pulumi
```

```typescript
// Configure S3 backend bucket with encryption
import * as aws from "@pulumi/aws";

const stateBucket = new aws.s3.Bucket("pulumi-state", {
    bucket: "company-pulumi-state",
    versioning: {
        enabled: true,
    },
    serverSideEncryptionConfiguration: {
        rule: {
            applyServerSideEncryptionByDefault: {
                sseAlgorithm: "aws:kms",
                kmsMasterKeyId: kmsKey.id,
            },
            bucketKeyEnabled: true,
        },
    },
    lifecycleRules: [{
        enabled: true,
        noncurrentVersionExpiration: {
            days: 90,
        },
    }],
});

// Block public access
const stateBucketPublicAccessBlock = new aws.s3.BucketPublicAccessBlock("pulumi-state-pab", {
    bucket: stateBucket.id,
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});
```

**Don't**:
```yaml
# VULNERABLE: Passphrase-based encryption (not for production)
name: my-infrastructure
runtime: python
backend:
  url: s3://pulumi-state
secretsprovider: passphrase
# Passphrase stored in PULUMI_CONFIG_PASSPHRASE - not suitable for teams

# VULNERABLE: No secrets provider specified
name: my-infrastructure
runtime: python
backend:
  url: file://~/.pulumi
# Uses default passphrase encryption without key management
```

```typescript
// VULNERABLE: Storing state locally
// pulumi login --local
// State files stored unencrypted in ~/.pulumi
```

**Why**: Pulumi state contains sensitive information including resource outputs, connection strings, and secrets. Without proper encryption, anyone with storage access can read secrets in plaintext. Cloud KMS provides key rotation, audit trails, and access control. Passphrase encryption lacks these enterprise features.

**Refs**: CWE-311 (Missing Encryption of Sensitive Data), NIST 800-53 SC-28 (Protection of Information at Rest), NIST 800-53 SC-12 (Cryptographic Key Management)

---

## Rule 2: Config.requireSecret for Sensitive Values

**Level**: `strict`

**When**: Accessing sensitive configuration values in Pulumi programs

**Do**:
```typescript
// TypeScript - Use requireSecret for sensitive values
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const config = new pulumi.Config();

// Retrieve secrets - these are automatically marked as secret outputs
const dbPassword = config.requireSecret("dbPassword");
const apiKey = config.requireSecret("apiKey");
const sshPrivateKey = config.requireSecret("sshPrivateKey");

// Create RDS instance with secret password
const database = new aws.rds.Instance("production-db", {
    engine: "postgres",
    engineVersion: "15.4",
    instanceClass: "db.t3.medium",
    allocatedStorage: 20,
    username: "admin",
    password: dbPassword,  // Automatically treated as secret
    skipFinalSnapshot: false,
    finalSnapshotIdentifier: pulumi.interpolate`production-db-final-${Date.now()}`,
    storageEncrypted: true,
    kmsKeyId: kmsKey.arn,
});

// Export as secret output
export const connectionString = pulumi.secret(
    pulumi.interpolate`postgresql://admin:${dbPassword}@${database.endpoint}/${database.dbName}`
);
```

```python
# Python - Use require_secret for sensitive values
import pulumi
from pulumi_aws import rds, kms

config = pulumi.Config()

# Retrieve secrets
db_password = config.require_secret("dbPassword")
api_key = config.require_secret("apiKey")

# Create database with secret password
database = rds.Instance("production-db",
    engine="postgres",
    engine_version="15.4",
    instance_class="db.t3.medium",
    allocated_storage=20,
    username="admin",
    password=db_password,  # Automatically treated as secret
    storage_encrypted=True,
    kms_key_id=kms_key.arn,
)

# Export as secret
pulumi.export("connectionString", pulumi.Output.secret(
    pulumi.Output.concat(
        "postgresql://admin:", db_password, "@", database.endpoint, "/", database.db_name
    )
))
```

```go
// Go - Use RequireSecret for sensitive values
package main

import (
    "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/rds"
    "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
    "github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func main() {
    pulumi.Run(func(ctx *pulumi.Context) error {
        cfg := config.New(ctx, "")

        // Retrieve secrets
        dbPassword := cfg.RequireSecret("dbPassword")

        // Create database
        database, err := rds.NewInstance(ctx, "production-db", &rds.InstanceArgs{
            Engine:           pulumi.String("postgres"),
            EngineVersion:    pulumi.String("15.4"),
            InstanceClass:    pulumi.String("db.t3.medium"),
            AllocatedStorage: pulumi.Int(20),
            Username:         pulumi.String("admin"),
            Password:         dbPassword,  // Automatically treated as secret
            StorageEncrypted: pulumi.Bool(true),
        })
        if err != nil {
            return err
        }

        // Export as secret
        ctx.Export("connectionString", pulumi.ToSecret(
            pulumi.Sprintf("postgresql://admin:%s@%s/%s",
                dbPassword, database.Endpoint, database.DbName),
        ))

        return nil
    })
}
```

```bash
# Set secrets via CLI
pulumi config set --secret dbPassword 'MySecurePassword123!'
pulumi config set --secret apiKey 'sk-1234567890abcdef'
```

**Don't**:
```typescript
// VULNERABLE: Using require instead of requireSecret
const config = new pulumi.Config();
const dbPassword = config.require("dbPassword");  // Not encrypted in config
const apiKey = config.get("apiKey");  // Also not encrypted

// VULNERABLE: Hardcoded secrets
const database = new aws.rds.Instance("db", {
    username: "admin",
    password: "SuperSecretPassword123!",  // Never do this
});

// VULNERABLE: Not marking output as secret
export const connectionString = pulumi.interpolate`postgresql://admin:${dbPassword}@${database.endpoint}`;
// Password visible in stack output
```

```python
# VULNERABLE: Using require instead of require_secret
config = pulumi.Config()
db_password = config.require("dbPassword")  # Stored in plaintext in config

# VULNERABLE: Not marking output as secret
pulumi.export("password", db_password)  # Visible in plaintext
```

```bash
# VULNERABLE: Setting config without --secret flag
pulumi config set dbPassword 'MyPassword123!'  # Stored in plaintext
```

**Why**: Config values set without `--secret` are stored in plaintext in stack configuration files. Using `require()` instead of `requireSecret()` doesn't mark the value as sensitive, causing it to appear in logs and previews. Secret outputs are masked in the Pulumi console and CLI output.

**Refs**: CWE-532 (Insertion of Sensitive Information into Log File), CWE-312 (Cleartext Storage of Sensitive Information), NIST 800-53 IA-5 (Authenticator Management)

---

## Rule 3: CrossGuard Policy Packs

**Level**: `warning`

**When**: Enforcing security and compliance policies across Pulumi deployments

**Do**:
```typescript
// policy-pack/index.ts - Create security policy pack
import * as policy from "@pulumi/policy";
import * as aws from "@pulumi/aws";

new policy.PolicyPack("security-policies", {
    policies: [
        // Require S3 bucket encryption
        {
            name: "s3-bucket-encryption-required",
            description: "S3 buckets must have server-side encryption enabled",
            enforcementLevel: "mandatory",
            validateResource: policy.validateResourceOfType(aws.s3.Bucket, (bucket, args, reportViolation) => {
                if (!bucket.serverSideEncryptionConfiguration) {
                    reportViolation("S3 bucket must have server-side encryption enabled");
                }
            }),
        },

        // Require S3 bucket versioning
        {
            name: "s3-bucket-versioning-required",
            description: "S3 buckets must have versioning enabled",
            enforcementLevel: "mandatory",
            validateResource: policy.validateResourceOfType(aws.s3.BucketVersioningV2, (versioning, args, reportViolation) => {
                if (versioning.versioningConfiguration?.status !== "Enabled") {
                    reportViolation("S3 bucket versioning must be enabled");
                }
            }),
        },

        // Block public S3 buckets
        {
            name: "s3-no-public-access",
            description: "S3 buckets must block public access",
            enforcementLevel: "mandatory",
            validateResource: policy.validateResourceOfType(aws.s3.BucketPublicAccessBlock, (block, args, reportViolation) => {
                if (!block.blockPublicAcls || !block.blockPublicPolicy ||
                    !block.ignorePublicAcls || !block.restrictPublicBuckets) {
                    reportViolation("S3 bucket must block all public access");
                }
            }),
        },

        // Require RDS encryption
        {
            name: "rds-encryption-required",
            description: "RDS instances must have storage encryption enabled",
            enforcementLevel: "mandatory",
            validateResource: policy.validateResourceOfType(aws.rds.Instance, (instance, args, reportViolation) => {
                if (!instance.storageEncrypted) {
                    reportViolation("RDS instance must have storage encryption enabled");
                }
            }),
        },

        // Prohibit 0.0.0.0/0 in security group ingress
        {
            name: "no-public-ingress",
            description: "Security groups must not allow ingress from 0.0.0.0/0",
            enforcementLevel: "mandatory",
            validateResource: policy.validateResourceOfType(aws.ec2.SecurityGroup, (sg, args, reportViolation) => {
                const ingress = sg.ingress || [];
                for (const rule of ingress) {
                    const cidrs = rule.cidrBlocks || [];
                    if (cidrs.includes("0.0.0.0/0")) {
                        reportViolation(`Security group allows ingress from 0.0.0.0/0 on port ${rule.fromPort}`);
                    }
                }
            }),
        },

        // Require tagging
        {
            name: "require-tags",
            description: "All resources must have required tags",
            enforcementLevel: "mandatory",
            validateResource: (args, reportViolation) => {
                const requiredTags = ["Environment", "Owner", "ManagedBy"];
                if (args.props.tags) {
                    for (const tag of requiredTags) {
                        if (!args.props.tags[tag]) {
                            reportViolation(`Resource must have '${tag}' tag`);
                        }
                    }
                }
            },
        },

        // Require cost center tagging
        {
            name: "require-cost-center",
            description: "Resources must have CostCenter tag",
            enforcementLevel: "advisory",
            validateResource: (args, reportViolation) => {
                if (args.props.tags && !args.props.tags.CostCenter) {
                    reportViolation("Resource should have 'CostCenter' tag for cost allocation");
                }
            },
        },
    ],
});
```

```python
# Python policy pack
from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ResourceValidationPolicy,
    ResourceValidationArgs,
)

def s3_encryption_validator(args: ResourceValidationArgs, report_violation):
    if args.resource_type == "aws:s3/bucket:Bucket":
        if not args.props.get("serverSideEncryptionConfiguration"):
            report_violation("S3 bucket must have encryption enabled")

def no_public_ingress_validator(args: ResourceValidationArgs, report_violation):
    if args.resource_type == "aws:ec2/securityGroup:SecurityGroup":
        for rule in args.props.get("ingress", []):
            if "0.0.0.0/0" in rule.get("cidrBlocks", []):
                report_violation(f"Security group allows public ingress on port {rule.get('fromPort')}")

PolicyPack(
    name="security-policies",
    policies=[
        ResourceValidationPolicy(
            name="s3-encryption-required",
            description="S3 buckets must have encryption enabled",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=s3_encryption_validator,
        ),
        ResourceValidationPolicy(
            name="no-public-ingress",
            description="Security groups must not allow 0.0.0.0/0",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=no_public_ingress_validator,
        ),
    ],
)
```

```bash
# Apply policy pack
pulumi preview --policy-pack ./policy-pack

# Publish to Pulumi Cloud for org-wide enforcement
cd policy-pack
pulumi policy publish company-org

# Enable for all stacks
pulumi policy enable company-org/security-policies latest
```

**Don't**:
```typescript
// POOR: No policy enforcement
// Running deployments without any policy checks

// POOR: Advisory-only for critical controls
{
    name: "s3-encryption-required",
    enforcementLevel: "advisory",  // Should be mandatory for encryption
    // ...
}

// POOR: Overly broad exception
{
    name: "no-public-ingress",
    enforcementLevel: "mandatory",
    validateResource: (args, reportViolation) => {
        // Skip validation for "special" resources
        if (args.name.includes("public")) return;  // Dangerous exception
        // ...
    },
}
```

**Why**: CrossGuard policies enforce security and compliance requirements automatically. Without policy enforcement, misconfigurations can reach production. Mandatory enforcement prevents deployments that violate security requirements. Organization-wide policies ensure consistent security across all teams.

**Refs**: NIST 800-53 SA-15 (Development Process), CIS AWS Foundations Benchmark, Pulumi CrossGuard Documentation

---

## Rule 4: Automation API Security

**Level**: `strict`

**When**: Using Pulumi Automation API for programmatic infrastructure management

**Do**:
```typescript
// TypeScript - Secure Automation API usage
import * as pulumi from "@pulumi/pulumi";
import { LocalWorkspace } from "@pulumi/pulumi/automation";
import * as aws from "@pulumi/aws";

async function deployInfrastructure() {
    // Use environment variables for secrets
    const awsRegion = process.env.AWS_REGION || "us-east-1";

    // Define the Pulumi program inline
    const program = async () => {
        const bucket = new aws.s3.Bucket("my-bucket", {
            serverSideEncryptionConfiguration: {
                rule: {
                    applyServerSideEncryptionByDefault: {
                        sseAlgorithm: "aws:kms",
                    },
                },
            },
        });

        return { bucketName: bucket.id };
    };

    // Create or select stack
    const stack = await LocalWorkspace.createOrSelectStack({
        stackName: "production",
        projectName: "my-infrastructure",
        program,
    }, {
        // Use proper secrets provider
        secretsProvider: "awskms://alias/pulumi-secrets",
        // Configure project settings
        projectSettings: {
            name: "my-infrastructure",
            runtime: "nodejs",
            backend: {
                url: "s3://company-pulumi-state",
            },
        },
    });

    // Set configuration securely
    await stack.setConfig("aws:region", { value: awsRegion });

    // Set secrets using secret flag
    const dbPassword = process.env.DB_PASSWORD;
    if (dbPassword) {
        await stack.setConfig("dbPassword", {
            value: dbPassword,
            secret: true
        });
    }

    // Preview changes first
    const previewResult = await stack.preview({ onOutput: console.log });
    console.log("Preview completed:", previewResult.changeSummary);

    // Apply with approval (in production, require human approval)
    if (process.env.AUTO_APPROVE === "true") {
        const upResult = await stack.up({ onOutput: console.log });
        console.log("Deployment completed:", upResult.summary);

        // Access outputs
        const outputs = await stack.outputs();
        console.log("Bucket name:", outputs.bucketName.value);
    }
}

// Handle errors securely
deployInfrastructure().catch(err => {
    // Don't log sensitive information
    console.error("Deployment failed:", err.message);
    process.exit(1);
});
```

```python
# Python - Secure Automation API usage
import os
import pulumi
from pulumi import automation as auto
from pulumi_aws import s3

def pulumi_program():
    bucket = s3.Bucket("my-bucket",
        server_side_encryption_configuration=s3.BucketServerSideEncryptionConfigurationArgs(
            rule=s3.BucketServerSideEncryptionConfigurationRuleArgs(
                apply_server_side_encryption_by_default=s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                    sse_algorithm="aws:kms",
                ),
            ),
        ),
    )
    pulumi.export("bucket_name", bucket.id)

def deploy():
    stack_name = "production"
    project_name = "my-infrastructure"

    # Create or select stack with secure settings
    stack = auto.create_or_select_stack(
        stack_name=stack_name,
        project_name=project_name,
        program=pulumi_program,
        opts=auto.LocalWorkspaceOptions(
            secrets_provider="awskms://alias/pulumi-secrets",
            project_settings=auto.ProjectSettings(
                name=project_name,
                runtime="python",
                backend=auto.ProjectBackend(
                    url="s3://company-pulumi-state"
                ),
            ),
        ),
    )

    # Set configuration from environment
    stack.set_config("aws:region", auto.ConfigValue(value=os.environ.get("AWS_REGION", "us-east-1")))

    # Set secrets from environment
    db_password = os.environ.get("DB_PASSWORD")
    if db_password:
        stack.set_config("dbPassword", auto.ConfigValue(value=db_password, secret=True))

    # Preview first
    preview_result = stack.preview(on_output=print)
    print(f"Preview: {preview_result.change_summary}")

    # Deploy with approval check
    if os.environ.get("AUTO_APPROVE") == "true":
        up_result = stack.up(on_output=print)
        print(f"Deployment: {up_result.summary}")

if __name__ == "__main__":
    try:
        deploy()
    except Exception as e:
        print(f"Deployment failed: {e}")
        exit(1)
```

**Don't**:
```typescript
// VULNERABLE: Hardcoded secrets in Automation API
const stack = await pulumi.LocalWorkspace.createOrSelectStack({
    stackName: "production",
    projectName: "my-app",
    program: async () => {
        const db = new aws.rds.Instance("db", {
            password: "HardcodedPassword123!",  // Never do this
        });
    },
});

// Set secret as plaintext
await stack.setConfig("dbPassword", {
    value: "MyPassword123!",
    secret: false  // Should be true
});

// VULNERABLE: No secrets provider
const stack = await pulumi.LocalWorkspace.createOrSelectStack({
    // Missing secretsProvider
    // Uses default passphrase
});

// VULNERABLE: Logging sensitive outputs
const outputs = await stack.outputs();
console.log("All outputs:", JSON.stringify(outputs));  // May contain secrets

// VULNERABLE: Auto-approve without review
const upResult = await stack.up({ onOutput: console.log });
// No preview, no approval gate
```

**Why**: Automation API enables programmatic infrastructure management, but secrets must still be protected. Hardcoded secrets are exposed in code repositories. Using `secret: false` stores config in plaintext. Missing secrets providers use weak encryption. Auto-approval without review bypasses security checks.

**Refs**: CWE-798 (Hardcoded Credentials), NIST 800-53 CM-3 (Configuration Change Control)

---

## Rule 5: State Backend Security

**Level**: `strict`

**When**: Configuring Pulumi state storage backend

**Do**:
```yaml
# Pulumi.yaml - AWS S3 with proper security
name: my-infrastructure
runtime: nodejs
backend:
  url: s3://company-pulumi-state?region=us-east-1&awssdk=v2
secretsprovider: awskms://alias/pulumi-secrets?region=us-east-1
```

```typescript
// Create secure S3 backend bucket
import * as aws from "@pulumi/aws";

// KMS key for state encryption
const stateKey = new aws.kms.Key("pulumi-state-key", {
    description: "KMS key for Pulumi state encryption",
    deletionWindowInDays: 30,
    enableKeyRotation: true,
    policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Sid: "Enable IAM User Permissions",
                Effect: "Allow",
                Principal: {
                    AWS: `arn:aws:iam::${accountId}:root`,
                },
                Action: "kms:*",
                Resource: "*",
            },
            {
                Sid: "Allow Pulumi Role",
                Effect: "Allow",
                Principal: {
                    AWS: pulumiRoleArn,
                },
                Action: [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey",
                ],
                Resource: "*",
            },
        ],
    }),
});

// S3 bucket for state
const stateBucket = new aws.s3.Bucket("pulumi-state", {
    bucket: "company-pulumi-state",
    versioning: {
        enabled: true,
    },
    serverSideEncryptionConfiguration: {
        rule: {
            applyServerSideEncryptionByDefault: {
                sseAlgorithm: "aws:kms",
                kmsMasterKeyId: stateKey.id,
            },
            bucketKeyEnabled: true,
        },
    },
    lifecycleRules: [{
        enabled: true,
        noncurrentVersionExpiration: {
            days: 90,
        },
    }],
    loggings: [{
        targetBucket: accessLogsBucket.id,
        targetPrefix: "pulumi-state/",
    }],
});

// Block public access
const publicAccessBlock = new aws.s3.BucketPublicAccessBlock("pulumi-state-pab", {
    bucket: stateBucket.id,
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});

// Bucket policy restricting access
const bucketPolicy = new aws.s3.BucketPolicy("pulumi-state-policy", {
    bucket: stateBucket.id,
    policy: pulumi.interpolate`{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "${stateBucket.arn}",
                    "${stateBucket.arn}/*"
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            },
            {
                "Sid": "RestrictToRole",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "${stateBucket.arn}",
                    "${stateBucket.arn}/*"
                ],
                "Condition": {
                    "StringNotEquals": {
                        "aws:PrincipalArn": "${pulumiRoleArn}"
                    }
                }
            }
        ]
    }`,
});
```

```yaml
# Azure Blob Storage backend
name: my-infrastructure
runtime: python
backend:
  url: azblob://pulumistate?storage_account=companystate
secretsprovider: azurekeyvault://company-vault.vault.azure.net/keys/pulumi
```

```yaml
# GCS backend
name: my-infrastructure
runtime: go
backend:
  url: gs://company-pulumi-state
secretsprovider: gcpkms://projects/my-project/locations/us/keyRings/pulumi/cryptoKeys/state
```

**Don't**:
```yaml
# VULNERABLE: Local file backend (no encryption, no access control)
name: my-infrastructure
runtime: nodejs
backend:
  url: file://~/.pulumi
# State stored locally without encryption

# VULNERABLE: S3 without encryption or versioning
name: my-infrastructure
runtime: python
backend:
  url: s3://my-bucket
# Missing: KMS encryption, versioning, access controls
```

```typescript
// VULNERABLE: Bucket without security controls
const stateBucket = new aws.s3.Bucket("pulumi-state", {
    bucket: "pulumi-state",
    // Missing: versioning
    // Missing: encryption
    // Missing: public access block
    // Missing: bucket policy
});
```

**Why**: Pulumi state contains sensitive outputs, resource IDs, and potentially secrets. Local backends have no encryption or access control. S3/Azure/GCS backends need encryption, versioning, and access restrictions. Versioning enables recovery from accidental deletion or corruption.

**Refs**: CWE-311 (Missing Encryption), CWE-732 (Incorrect Permission Assignment), NIST 800-53 SC-28 (Protection at Rest), CIS AWS 2.1.1

---

## Rule 6: Provider Configuration Security

**Level**: `strict`

**When**: Configuring cloud provider authentication for Pulumi

**Do**:
```typescript
// TypeScript - Use IAM roles and environment variables
import * as aws from "@pulumi/aws";

// Default provider uses environment variables
// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
// Or IAM role when running on EC2/ECS/Lambda

// Explicit provider with role assumption
const prodProvider = new aws.Provider("prod", {
    region: "us-east-1",
    assumeRole: {
        roleArn: "arn:aws:iam::123456789012:role/PulumiRole",
        sessionName: "pulumi-deployment",
        externalId: config.requireSecret("externalId"),
    },
});

// Use provider for resources
const bucket = new aws.s3.Bucket("my-bucket", {
    // ... configuration
}, { provider: prodProvider });
```

```python
# Python - Use environment variables and role assumption
import pulumi
from pulumi_aws import Provider, ProviderAssumeRoleArgs, s3

config = pulumi.Config()

# Provider with role assumption
prod_provider = Provider("prod",
    region="us-east-1",
    assume_role=ProviderAssumeRoleArgs(
        role_arn="arn:aws:iam::123456789012:role/PulumiRole",
        session_name="pulumi-deployment",
        external_id=config.require_secret("externalId"),
    ),
)

bucket = s3.Bucket("my-bucket",
    opts=pulumi.ResourceOptions(provider=prod_provider),
)
```

```yaml
# OIDC authentication for CI/CD (GitHub Actions)
# .github/workflows/pulumi.yml
jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      - name: Pulumi Deploy
        uses: pulumi/actions@v4
        with:
          command: up
          stack-name: production
```

```go
// Go - Environment-based authentication
package main

import (
    "github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
    "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
    "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
    pulumi.Run(func(ctx *pulumi.Context) error {
        // Provider uses AWS_* environment variables
        provider, err := aws.NewProvider(ctx, "prod", &aws.ProviderArgs{
            Region: pulumi.String("us-east-1"),
            AssumeRole: &aws.ProviderAssumeRoleArgs{
                RoleArn:     pulumi.String("arn:aws:iam::123456789012:role/PulumiRole"),
                SessionName: pulumi.String("pulumi-deployment"),
            },
        })
        if err != nil {
            return err
        }

        // Use provider
        _, err = s3.NewBucket(ctx, "my-bucket", &s3.BucketArgs{},
            pulumi.Provider(provider),
        )
        return err
    })
}
```

**Don't**:
```typescript
// VULNERABLE: Hardcoded credentials
const provider = new aws.Provider("aws", {
    region: "us-east-1",
    accessKey: "AKIAIOSFODNN7EXAMPLE",
    secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
});

// VULNERABLE: Credentials in config (even if encrypted)
const config = new pulumi.Config();
const provider = new aws.Provider("aws", {
    region: "us-east-1",
    accessKey: config.require("awsAccessKey"),  // Don't store long-term creds
    secretKey: config.requireSecret("awsSecretKey"),
});
```

```python
# VULNERABLE: Hardcoded credentials
provider = Provider("aws",
    region="us-east-1",
    access_key="AKIAIOSFODNN7EXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)
```

**Why**: Hardcoded credentials are exposed in code repositories and have unlimited lifetime. Static credentials can be stolen and used indefinitely. IAM roles and OIDC provide short-lived credentials with automatic rotation. Role assumption provides audit trails of who performed actions.

**Refs**: CWE-798 (Hardcoded Credentials), NIST 800-53 IA-5 (Authenticator Management), CIS AWS 1.16

---

## Rule 7: Resource Options (protect, retainOnDelete)

**Level**: `warning`

**When**: Managing critical infrastructure resources that should be protected from deletion

**Do**:
```typescript
// TypeScript - Protect critical resources
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

// Protect production database from deletion
const database = new aws.rds.Instance("production-db", {
    identifier: "production-database",
    engine: "postgres",
    engineVersion: "15.4",
    instanceClass: "db.r6g.large",
    allocatedStorage: 100,
    username: "admin",
    password: config.requireSecret("dbPassword"),
    deletionProtection: true,  // AWS-level protection
    skipFinalSnapshot: false,
    finalSnapshotIdentifier: "production-db-final",
    storageEncrypted: true,
}, {
    protect: true,  // Pulumi-level protection
});

// Protect state storage
const stateBucket = new aws.s3.Bucket("terraform-state", {
    bucket: "company-terraform-state",
    versioning: {
        enabled: true,
    },
}, {
    protect: true,
});

// Retain VPC on delete (for disaster recovery)
const vpc = new aws.ec2.Vpc("production-vpc", {
    cidrBlock: "10.0.0.0/16",
}, {
    retainOnDelete: true,  // Keep resource even if removed from Pulumi
});

// Protect KMS keys
const kmsKey = new aws.kms.Key("data-key", {
    description: "KMS key for data encryption",
    deletionWindowInDays: 30,
    enableKeyRotation: true,
}, {
    protect: true,
});

// Apply protection to multiple resources
const protectedOpts = { protect: true };

const certificate = new aws.acm.Certificate("main-cert", {
    domainName: "example.com",
    validationMethod: "DNS",
}, protectedOpts);
```

```python
# Python - Protect critical resources
import pulumi
import pulumi_aws as aws
from pulumi_aws import rds, s3, kms

config = pulumi.Config()

# Protect production database
database = rds.Instance("production-db",
    identifier="production-database",
    engine="postgres",
    engine_version="15.4",
    instance_class="db.r6g.large",
    allocated_storage=100,
    username="admin",
    password=config.require_secret("dbPassword"),
    deletion_protection=True,
    skip_final_snapshot=False,
    storage_encrypted=True,
    opts=pulumi.ResourceOptions(protect=True),
)

# Retain on delete
vpc = aws.ec2.Vpc("production-vpc",
    cidr_block="10.0.0.0/16",
    opts=pulumi.ResourceOptions(retain_on_delete=True),
)
```

```go
// Go - Protect critical resources
database, err := rds.NewInstance(ctx, "production-db", &rds.InstanceArgs{
    Identifier:         pulumi.String("production-database"),
    Engine:             pulumi.String("postgres"),
    EngineVersion:      pulumi.String("15.4"),
    InstanceClass:      pulumi.String("db.r6g.large"),
    DeletionProtection: pulumi.Bool(true),
    StorageEncrypted:   pulumi.Bool(true),
}, pulumi.Protect(true))
```

**Don't**:
```typescript
// RISKY: No protection for critical resources
const database = new aws.rds.Instance("production-db", {
    identifier: "production-database",
    engine: "postgres",
    instanceClass: "db.r6g.large",
    // Missing: deletionProtection = true
    // Missing: protect = true
    skipFinalSnapshot: true,  // No backup before deletion
});

// RISKY: Protecting everything (makes operations difficult)
const tempBucket = new aws.s3.Bucket("temp-bucket", {
    bucket: "temporary-processing",
}, {
    protect: true,  // Unnecessary for temporary resources
});

// RISKY: Using retainOnDelete without cleanup plan
const ephemeralResource = new aws.ec2.Instance("test", {
    // ...
}, {
    retainOnDelete: true,  // Will be orphaned without tracking
});
```

**Why**: Critical resources need protection from accidental deletion. `protect: true` prevents Pulumi from deleting resources. `deletionProtection` prevents API-level deletion. `retainOnDelete` keeps resources when removed from Pulumi (useful for migration). Without protection, a simple `pulumi destroy` can delete production databases.

**Refs**: NIST 800-53 CP-9 (System Backup), CIS AWS 2.1.5

---

## Rule 8: Stack References Security

**Level**: `warning`

**When**: Using StackReference to access outputs from other stacks

**Do**:
```typescript
// TypeScript - Secure stack references
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

// Reference another stack's outputs
const networkStack = new pulumi.StackReference("company/network/production");

// Access specific outputs (not entire state)
const vpcId = networkStack.getOutput("vpcId");
const privateSubnetIds = networkStack.getOutput("privateSubnetIds");
const securityGroupId = networkStack.getOutput("appSecurityGroupId");

// Use outputs in resources
const instance = new aws.ec2.Instance("app", {
    ami: "ami-12345678",
    instanceType: "t3.micro",
    subnetId: privateSubnetIds.apply(ids => ids[0]),
    vpcSecurityGroupIds: [securityGroupId],
});

// Handle secret outputs properly
const dbPassword = networkStack.getOutput("dbPassword");  // Marked as secret in source
const connectionString = pulumi.secret(
    pulumi.interpolate`postgresql://admin:${dbPassword}@${dbEndpoint}/mydb`
);

// Use requireOutput for mandatory values
const requiredVpcId = networkStack.requireOutput("vpcId");
```

```typescript
// Source stack - Export secure outputs
export const vpcId = vpc.id;
export const privateSubnetIds = privateSubnets.map(s => s.id);
export const appSecurityGroupId = appSg.id;

// Mark sensitive outputs as secrets
export const dbPassword = pulumi.secret(database.password);
export const connectionString = pulumi.secret(
    pulumi.interpolate`postgresql://...`
);
```

```python
# Python - Secure stack references
import pulumi
from pulumi_aws import ec2

# Reference another stack
network_stack = pulumi.StackReference("company/network/production")

# Access specific outputs
vpc_id = network_stack.get_output("vpcId")
private_subnet_ids = network_stack.get_output("privateSubnetIds")

# Use in resources
instance = ec2.Instance("app",
    ami="ami-12345678",
    instance_type="t3.micro",
    subnet_id=private_subnet_ids.apply(lambda ids: ids[0]),
)

# Require mandatory outputs
required_vpc_id = network_stack.require_output("vpcId")
```

**Don't**:
```typescript
// VULNERABLE: Accessing sensitive outputs insecurely
const networkStack = new pulumi.StackReference("company/network/production");

// Don't export secrets without marking them
const dbPassword = networkStack.getOutput("dbPassword");
export const password = dbPassword;  // Not marked as secret

// VULNERABLE: Trusting arbitrary stack references
const untrustedStack = new pulumi.StackReference("unknown-org/stack/prod");
const vpcId = untrustedStack.getOutput("vpcId");
// No validation of the referenced stack

// POOR: Using stack references for secrets that should be in secret manager
const apiKey = networkStack.getOutput("apiKey");
// Better to use Secrets Manager or Vault
```

```python
# VULNERABLE: Exposing secrets through stack reference
network_stack = pulumi.StackReference("company/network/production")
db_password = network_stack.get_output("dbPassword")
pulumi.export("password", db_password)  # Exposed in plaintext
```

**Why**: Stack references share state between Pulumi programs. Secrets must remain marked as secrets when accessed through references. Exporting secrets without proper marking exposes them in plaintext. Only reference stacks from trusted sources within your organization.

**Refs**: CWE-200 (Exposure of Sensitive Information), NIST 800-53 AC-4 (Information Flow Enforcement)

---

## Rule 9: Dynamic Providers Validation

**Level**: `warning`

**When**: Creating custom dynamic providers for resources not supported by existing providers

**Do**:
```typescript
// TypeScript - Secure dynamic provider
import * as pulumi from "@pulumi/pulumi";

// Define types for inputs/outputs
interface CustomResourceInputs {
    name: string;
    config: string;
}

interface CustomResourceOutputs {
    id: string;
    name: string;
    createdAt: string;
}

// Implement secure dynamic provider
const customResourceProvider: pulumi.dynamic.ResourceProvider = {
    async create(inputs: CustomResourceInputs): Promise<pulumi.dynamic.CreateResult> {
        // Validate inputs
        if (!inputs.name || inputs.name.length < 3) {
            throw new Error("Name must be at least 3 characters");
        }

        // Sanitize inputs to prevent injection
        const sanitizedName = inputs.name.replace(/[^a-zA-Z0-9-_]/g, "");

        // Use secure API calls
        const response = await fetch("https://api.example.com/resources", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${process.env.API_TOKEN}`,  // From environment
            },
            body: JSON.stringify({
                name: sanitizedName,
                config: inputs.config,
            }),
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        return {
            id: result.id,
            outs: {
                name: result.name,
                createdAt: result.createdAt,
            },
        };
    },

    async read(id: string, props: CustomResourceOutputs): Promise<pulumi.dynamic.ReadResult> {
        // Implement read for refresh
        const response = await fetch(`https://api.example.com/resources/${id}`, {
            headers: {
                "Authorization": `Bearer ${process.env.API_TOKEN}`,
            },
        });

        if (!response.ok) {
            if (response.status === 404) {
                // Resource doesn't exist
                return { id: "", props: {} };
            }
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();
        return {
            id: result.id,
            props: {
                name: result.name,
                createdAt: result.createdAt,
            },
        };
    },

    async update(id: string, olds: CustomResourceOutputs, news: CustomResourceInputs): Promise<pulumi.dynamic.UpdateResult> {
        // Validate and update
        const sanitizedName = news.name.replace(/[^a-zA-Z0-9-_]/g, "");

        const response = await fetch(`https://api.example.com/resources/${id}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${process.env.API_TOKEN}`,
            },
            body: JSON.stringify({
                name: sanitizedName,
                config: news.config,
            }),
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();
        return {
            outs: {
                name: result.name,
                createdAt: result.createdAt,
            },
        };
    },

    async delete(id: string, props: CustomResourceOutputs): Promise<void> {
        const response = await fetch(`https://api.example.com/resources/${id}`, {
            method: "DELETE",
            headers: {
                "Authorization": `Bearer ${process.env.API_TOKEN}`,
            },
        });

        if (!response.ok && response.status !== 404) {
            throw new Error(`API error: ${response.status}`);
        }
    },
};

// Create resource class
class CustomResource extends pulumi.dynamic.Resource {
    public readonly name!: pulumi.Output<string>;
    public readonly createdAt!: pulumi.Output<string>;

    constructor(name: string, args: CustomResourceInputs, opts?: pulumi.CustomResourceOptions) {
        super(customResourceProvider, name, { ...args, name: undefined, createdAt: undefined }, opts);
    }
}

// Use the dynamic resource
const resource = new CustomResource("my-resource", {
    name: "test-resource",
    config: "some-config",
});
```

**Don't**:
```typescript
// VULNERABLE: No input validation
const unsafeProvider: pulumi.dynamic.ResourceProvider = {
    async create(inputs: any): Promise<pulumi.dynamic.CreateResult> {
        // No validation of inputs
        const response = await fetch("https://api.example.com/resources", {
            method: "POST",
            body: JSON.stringify(inputs),  // Directly passing untrusted input
        });
        // ...
    },
};

// VULNERABLE: Hardcoded credentials
const unsafeProvider: pulumi.dynamic.ResourceProvider = {
    async create(inputs: any): Promise<pulumi.dynamic.CreateResult> {
        const response = await fetch("https://api.example.com/resources", {
            headers: {
                "Authorization": "Bearer hardcoded-api-key",  // Never do this
            },
        });
        // ...
    },
};

// VULNERABLE: Command injection
const unsafeProvider: pulumi.dynamic.ResourceProvider = {
    async create(inputs: any): Promise<pulumi.dynamic.CreateResult> {
        const { exec } = require("child_process");
        exec(`curl -X POST https://api.example.com/${inputs.name}`);  // Injection risk
        // ...
    },
};

// POOR: Missing CRUD methods
const incompleteProvider: pulumi.dynamic.ResourceProvider = {
    async create(inputs: any): Promise<pulumi.dynamic.CreateResult> {
        // Only create, no read/update/delete
        return { id: "123", outs: {} };
    },
    // Missing: read, update, delete
};
```

**Why**: Dynamic providers execute arbitrary code during deployments. Without input validation, they're vulnerable to injection attacks. Hardcoded credentials are exposed in code. Missing CRUD methods cause refresh and update failures. Proper validation and authentication are essential for security.

**Refs**: CWE-20 (Improper Input Validation), CWE-78 (OS Command Injection), CWE-798 (Hardcoded Credentials)

---

## Rule 10: ESC (Environments, Secrets, Configuration) Security

**Level**: `warning`

**When**: Using Pulumi ESC for centralized secrets and configuration management

**Do**:
```yaml
# Pulumi ESC environment definition
# environments/production.yaml
values:
  # Static configuration
  aws:
    region: us-east-1

  # Pull secrets from external providers
  secrets:
    fn::open::aws-secrets:
      region: us-east-1
      get:
        dbPassword:
          secretId: prod/database/password
        apiKey:
          secretId: prod/api/key

  # Pull from Vault
  vault:
    fn::open::vault-secrets:
      address: https://vault.company.com
      jwt:
        role: pulumi-production
      secrets:
        tls:
          path: secret/data/tls
          field: private_key

  # Environment variables for providers
  environmentVariables:
    AWS_REGION: ${aws.region}

  # Pulumi configuration
  pulumiConfig:
    aws:region: ${aws.region}
    app:dbPassword:
      fn::secret: ${secrets.dbPassword}
    app:apiKey:
      fn::secret: ${secrets.apiKey}
```

```yaml
# Stack configuration using ESC
# Pulumi.production.yaml
environment:
  - production  # Reference ESC environment

config:
  # Override or extend ESC values
  app:instanceCount: 3
```

```typescript
// TypeScript - Access ESC configuration
import * as pulumi from "@pulumi/pulumi";

const config = new pulumi.Config("app");

// Access secrets from ESC (automatically marked as secret)
const dbPassword = config.requireSecret("dbPassword");
const apiKey = config.requireSecret("apiKey");

// Use in resources
const database = new aws.rds.Instance("db", {
    password: dbPassword,
});
```

```bash
# ESC CLI commands
# List environments
esc env ls company-org

# Open environment (pulls secrets)
esc env open company-org/production

# Run command with environment
esc run company-org/production -- pulumi up

# Check environment configuration
esc env get company-org/production
```

```yaml
# Team access control in Pulumi Cloud
# environments/production.yaml
imports:
  - base  # Import from base environment

# Define who can access
# In Pulumi Cloud UI or API:
# - Admin: full access
# - Developer: read config, no secrets
# - CI/CD: read all
```

**Don't**:
```yaml
# VULNERABLE: Hardcoded secrets in ESC
values:
  secrets:
    dbPassword: "HardcodedPassword123!"  # Never do this
    apiKey: "sk-1234567890"

# VULNERABLE: Overly permissive access
# Giving all team members access to production secrets

# POOR: Not using secret providers
values:
  # Just static values, not pulling from secure stores
  database:
    password: "password123"

# POOR: Not marking values as secrets
values:
  pulumiConfig:
    app:dbPassword: ${secrets.dbPassword}  # Missing fn::secret
```

```typescript
// VULNERABLE: Accessing ESC values insecurely
const config = new pulumi.Config("app");
const dbPassword = config.require("dbPassword");  // Not requireSecret
pulumi.export("password", dbPassword);  // Exposing in plaintext
```

**Why**: ESC centralizes configuration and secrets management across environments. Hardcoding secrets defeats the purpose. Not using secret providers (AWS Secrets Manager, Vault) means no audit trails or rotation. Access control prevents unauthorized secret access. `fn::secret` ensures values are encrypted in state.

**Refs**: CWE-312 (Cleartext Storage of Sensitive Information), NIST 800-53 SC-12 (Cryptographic Key Management), Pulumi ESC Documentation

---

## Additional Security Best Practices

### Use Transformations for Global Policies

```typescript
// Apply security settings to all resources
pulumi.runtime.registerStackTransformation((args) => {
    // Add tags to all resources
    if (args.props.tags !== undefined) {
        args.props.tags = {
            ...args.props.tags,
            Environment: pulumi.getStack(),
            ManagedBy: "pulumi",
            Project: pulumi.getProject(),
        };
    }

    // Ensure S3 buckets have encryption
    if (args.type === "aws:s3/bucket:Bucket") {
        if (!args.props.serverSideEncryptionConfiguration) {
            // Add default encryption
            args.props.serverSideEncryptionConfiguration = {
                rule: {
                    applyServerSideEncryptionByDefault: {
                        sseAlgorithm: "aws:kms",
                    },
                },
            };
        }
    }

    return { props: args.props, opts: args.opts };
});
```

### Implement Audit Logging

```typescript
// Export deployment information for audit
export const deployment = {
    timestamp: new Date().toISOString(),
    stack: pulumi.getStack(),
    project: pulumi.getProject(),
    organization: pulumi.getOrganization(),
};

// Use Pulumi Cloud audit logs for compliance
// Available in Pulumi Cloud Enterprise
```

### Secure CI/CD Integration

```yaml
# GitHub Actions with Pulumi
name: Pulumi
on:
  pull_request:
  push:
    branches: [main]

jobs:
  preview:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Pulumi Preview
        uses: pulumi/actions@v4
        with:
          command: preview
          stack-name: org/project/production
          comment-on-pr: true
        env:
          PULUMI_ACCESS_TOKEN: ${{ secrets.PULUMI_ACCESS_TOKEN }}

  deploy:
    runs-on: ubuntu-latest
    needs: preview
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Pulumi Deploy
        uses: pulumi/actions@v4
        with:
          command: up
          stack-name: org/project/production
        env:
          PULUMI_ACCESS_TOKEN: ${{ secrets.PULUMI_ACCESS_TOKEN }}
```

### Network Security Defaults

```typescript
// Secure VPC configuration
const vpc = new aws.ec2.Vpc("main", {
    cidrBlock: "10.0.0.0/16",
    enableDnsHostnames: true,
    enableDnsSupport: true,
    tags: {
        Name: "production-vpc",
    },
});

// Enable VPC Flow Logs
const flowLog = new aws.ec2.FlowLog("vpc-flow-log", {
    vpcId: vpc.id,
    trafficType: "ALL",
    iamRoleArn: flowLogRole.arn,
    logDestination: flowLogGroup.arn,
});

// Restrictive default security group
const defaultSg = new aws.ec2.DefaultSecurityGroup("default", {
    vpcId: vpc.id,
    // No ingress or egress rules - effectively disabled
});
```

---

## Summary

These 10 Pulumi security rules provide comprehensive coverage:

1. **Stack Secrets Encryption** - Use KMS/Vault for state encryption
2. **Config.requireSecret** - Properly handle sensitive configuration
3. **CrossGuard Policy Packs** - Automated policy enforcement
4. **Automation API Security** - Secure programmatic deployments
5. **State Backend Security** - Protect state storage
6. **Provider Configuration** - Use IAM roles and OIDC
7. **Resource Options** - Protect critical resources
8. **Stack References** - Secure cross-stack communication
9. **Dynamic Providers** - Validate inputs, secure credentials
10. **ESC Security** - Centralized secrets management

Implementing these rules ensures Pulumi infrastructure code follows security best practices across all supported languages (TypeScript, Python, Go, C#, Java, YAML).
