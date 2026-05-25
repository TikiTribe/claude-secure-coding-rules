# GitLab CI/CD Security Rules

This document provides security rules specific to GitLab CI/CD pipelines. These rules address variable protection, runner security, include security, Vault integration, security scanning, and compliance pipelines.

---

## Rule: Protected Variables - Mask and Protect Secrets

**Level**: `strict`

**When**: Storing secrets or sensitive configuration in GitLab CI/CD variables.

**Do**: Configure variables with protection, masking, and appropriate scopes.

```yaml
# Variable configuration in GitLab UI or API
# Settings > CI/CD > Variables

# Production database credentials
# - Protected: Yes (only available on protected branches/tags)
# - Masked: Yes (hidden in job logs)
# - Expand variable reference: No

# API keys
# - Protected: Yes
# - Masked: Yes
# - Environment scope: production

# Using protected variables in .gitlab-ci.yml
deploy_production:
  stage: deploy
  environment:
    name: production
    url: https://app.example.com
  script:
    - echo "Deploying to production"
    # Variables are automatically available if job runs on protected branch
    - ./deploy.sh
  variables:
    # Reference protected variables
    DATABASE_URL: $PROD_DATABASE_URL
    API_KEY: $PROD_API_KEY
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'  # Protected branch
```

```yaml
# Using CI/CD variables with proper scoping
variables:
  # Global non-sensitive variables
  NODE_VERSION: "20"
  BUILD_ENV: "production"

stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - echo "Building with Node $NODE_VERSION"
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/

deploy_staging:
  stage: deploy
  environment:
    name: staging
  variables:
    # Staging-scoped variables from UI
    DATABASE_URL: $STAGING_DATABASE_URL
  script:
    - ./deploy.sh staging
  rules:
    - if: '$CI_COMMIT_BRANCH == "develop"'

deploy_production:
  stage: deploy
  environment:
    name: production
  variables:
    # Production-scoped variables from UI (protected)
    DATABASE_URL: $PROD_DATABASE_URL
  script:
    - ./deploy.sh production
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual
```

**Don't**: Store secrets unprotected or visible in logs.

```yaml
# VULNERABLE: Unprotected secrets
variables:
  # Hardcoded in .gitlab-ci.yml (visible in repo)
  DATABASE_URL: "postgresql://admin:password@db.example.com:5432/app"
  API_KEY: "sk-live-1234567890abcdef"

deploy:
  script:
    # Prints secrets to log
    - echo "Database: $DATABASE_URL"
    - echo "API Key: $API_KEY"

    # Environment dump exposes all variables
    - env | sort
```

```yaml
# VULNERABLE: Unprotected variable accessible on all branches
# Any branch (including attacker's) can access production secrets
deploy:
  script:
    - echo $PROD_DATABASE_URL  # Available on all branches
    - ./deploy.sh
```

**Why**: Unprotected variables can be accessed by any pipeline, including those from merge requests or feature branches. Attackers can create branches that exfiltrate protected secrets. Masked variables prevent accidental exposure in logs. Protected variables ensure secrets are only available in authorized contexts.

**Refs**:
- CWE-798: Use of Hard-coded Credentials
- CWE-532: Information Exposure Through Log Files
- OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene
- GitLab Docs: CI/CD variable security

---

## Rule: Runner Security - Tags and Isolation

**Level**: `strict`

**When**: Configuring GitLab Runners for pipeline execution.

**Do**: Use runner tags to enforce execution isolation and security boundaries.

```yaml
# Runner registration with security tags
# gitlab-runner register \
#   --tag-list "production,secure,docker" \
#   --locked \
#   --run-untagged=false

# .gitlab-ci.yml with runner isolation
stages:
  - build
  - test
  - deploy

# General jobs on shared runners
build:
  stage: build
  tags:
    - docker
    - shared
  script:
    - npm ci
    - npm run build

test:
  stage: test
  tags:
    - docker
    - shared
  script:
    - npm test

# Security scanning on isolated runner
security_scan:
  stage: test
  tags:
    - security
    - isolated
  script:
    - trivy fs --severity HIGH,CRITICAL .
    - semgrep --config auto .

# Production deployment on dedicated secure runner
deploy_production:
  stage: deploy
  tags:
    - production
    - secure
  environment:
    name: production
  script:
    - ./deploy.sh
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual
```

```yaml
# Kubernetes runner with pod security
# values.yaml for GitLab Runner Helm chart
runners:
  config: |
    [[runners]]
      [runners.kubernetes]
        namespace = "gitlab-runners"

        # Pod security context
        [runners.kubernetes.pod_security_context]
          run_as_non_root = true
          run_as_user = 1000
          fs_group = 1000

        # Container security context
        [runners.kubernetes.container_security_context]
          allow_privilege_escalation = false
          read_only_root_filesystem = true
          capabilities = { drop = ["ALL"] }

        # Ephemeral pods
        [runners.kubernetes.affinity]

        # Network policy applied via namespace
```

```yaml
# Runner configuration for different trust levels
# config.toml

# Shared runners for untrusted jobs
[[runners]]
  name = "shared-runner"
  url = "https://gitlab.example.com"
  token = "xxx"
  executor = "docker"
  [runners.docker]
    image = "alpine:latest"
    privileged = false
    disable_entrypoint_overwrite = true
    volumes = ["/cache"]
    shm_size = 0

# Secure runners for production
[[runners]]
  name = "production-runner"
  url = "https://gitlab.example.com"
  token = "yyy"
  executor = "docker"
  locked = true  # Only this project
  [runners.docker]
    image = "alpine:latest"
    privileged = false
    allowed_images = ["alpine:*", "node:*-alpine"]
    allowed_services = []  # No services
    pull_policy = "always"
```

**Don't**: Use shared runners for production deployments or sensitive operations.

```yaml
# VULNERABLE: No runner isolation
deploy_production:
  stage: deploy
  # No tags - runs on any available runner
  # Same runner may execute untrusted code from other projects
  script:
    - ./deploy.sh production
```

```yaml
# VULNERABLE: Privileged runners for all jobs
# config.toml
[[runners]]
  [runners.docker]
    privileged = true  # Can escape container
    volumes = ["/var/run/docker.sock:/var/run/docker.sock"]  # Docker socket access
```

**Why**: Shared runners may process jobs from multiple projects, including untrusted ones. Without isolation, secrets cached on runners or network access could be exploited. Tagged runners ensure sensitive jobs run only on appropriately secured infrastructure. Privileged runners can be used for container escapes.

**Refs**:
- CWE-250: Execution with Unnecessary Privileges
- CWE-269: Improper Privilege Management
- OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution
- GitLab Docs: Configuring runners

---

## Rule: Include Security - Trusted Sources Only

**Level**: `strict`

**When**: Using `include` to import external CI/CD configuration.

**Do**: Only include configurations from trusted, version-controlled sources.

```yaml
# Include from trusted internal projects
include:
  # From specific project and ref
  - project: 'security/ci-templates'
    ref: 'v2.1.0'  # Pinned tag
    file: '/templates/security-scanning.yml'

  # From compliance templates (organization-controlled)
  - project: 'platform/base-pipelines'
    ref: 'main'  # Protected branch
    file:
      - '/templates/build.yml'
      - '/templates/test.yml'

  # Local includes (same repo)
  - local: '/.gitlab/ci/deploy.yml'

stages:
  - build
  - test
  - security
  - deploy

# Override or extend included jobs
build:
  extends: .base-build
  variables:
    BUILD_TARGET: production
```

```yaml
# Secure template in security/ci-templates project
# File: /templates/security-scanning.yml

.security-base:
  stage: security
  allow_failure: false

sast:
  extends: .security-base
  script:
    - semgrep --config auto --error .
  artifacts:
    reports:
      sast: gl-sast-report.json

dependency_scanning:
  extends: .security-base
  script:
    - trivy fs --format json --output trivy-report.json .
  artifacts:
    reports:
      dependency_scanning: trivy-report.json

secret_detection:
  extends: .security-base
  script:
    - gitleaks detect --source . --report-format json --report-path gitleaks-report.json
  artifacts:
    reports:
      secret_detection: gitleaks-report.json
```

**Don't**: Include configurations from untrusted or unversioned sources.

```yaml
# VULNERABLE: Remote URL include
include:
  - remote: 'https://external-site.com/ci-template.yml'
  # Content can change at any time
  # No version control or audit trail
  # Potential for malicious code injection

# VULNERABLE: Unpinned project reference
include:
  - project: 'other-team/templates'
    file: '/template.yml'
    # No ref specified - uses default branch
    # Content can change unexpectedly
```

```yaml
# ADVISORY: Built-in GitLab templates
include:
  - template: 'Auto-DevOps.gitlab-ci.yml'
  # GitLab-maintained templates are hosted in the GitLab instance itself —
  # they are not fetched from an untrusted external URL. However, Auto-DevOps
  # enables many jobs by default (including deployment). Review what the
  # template enables before including it in a production pipeline and disable
  # any stages you do not need via DISABLE_* variables or overrides.
```

**Why**: Included configurations execute with the same permissions as the including pipeline. Malicious includes can exfiltrate secrets, modify artifacts, or inject backdoors. Unpinned references can be modified without the including project's knowledge. Only trusted, versioned sources should be included.

**Refs**:
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- CWE-94: Improper Control of Generation of Code
- OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse
- GitLab Docs: Include configuration

---

## Rule: Vault Integration - Dynamic Secrets

**Level**: `warning`

**When**: Accessing secrets for CI/CD pipelines.

**Do**: Use HashiCorp Vault with JWT authentication for dynamic secrets.

```yaml
# GitLab CI with Vault JWT authentication
variables:
  VAULT_ADDR: https://vault.example.com
  VAULT_AUTH_PATH: gitlab
  VAULT_AUTH_ROLE: myproject-production

stages:
  - build
  - deploy

deploy_production:
  stage: deploy
  environment:
    name: production
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com
  secrets:
    # Database credentials from Vault
    DATABASE_URL:
      vault: production/database/url@secrets
    DATABASE_PASSWORD:
      vault: production/database/password@secrets
    # API keys from Vault
    API_KEY:
      vault: production/api/key@secrets
  script:
    # Secrets are automatically injected
    - echo "Deploying with Vault secrets"
    - ./deploy.sh
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual
```

```hcl
# Vault configuration for GitLab JWT auth
# Enable JWT auth method
path "auth/gitlab" {
  type = "jwt"
}

# Configure JWT auth for GitLab
resource "vault_jwt_auth_backend" "gitlab" {
  path         = "gitlab"
  oidc_discovery_url = "https://gitlab.example.com"
  bound_issuer       = "https://gitlab.example.com"
}

# Role for production deployments
resource "vault_jwt_auth_backend_role" "production" {
  backend         = vault_jwt_auth_backend.gitlab.path
  role_name       = "myproject-production"
  token_policies  = ["production-deploy"]

  bound_claims = {
    project_id = "123"
    ref        = "main"
    ref_type   = "branch"
  }

  user_claim = "user_email"
  role_type  = "jwt"
}

# Policy for production secrets
resource "vault_policy" "production_deploy" {
  name   = "production-deploy"
  policy = <<-EOT
    path "secrets/data/production/*" {
      capabilities = ["read"]
    }
  EOT
}
```

```yaml
# Alternative: Using Vault CLI in scripts
deploy_with_vault:
  stage: deploy
  image: hashicorp/vault:latest
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com
  script:
    # Authenticate with JWT
    - export VAULT_TOKEN=$(vault write -field=token auth/gitlab/login role=myproject-production jwt=$VAULT_ID_TOKEN)

    # Get dynamic database credentials
    - export DATABASE_CREDS=$(vault read -format=json database/creds/myapp)
    - export DATABASE_USER=$(echo $DATABASE_CREDS | jq -r .data.username)
    - export DATABASE_PASS=$(echo $DATABASE_CREDS | jq -r .data.password)

    # WARNING: Values fetched from Vault at job-runtime cannot be auto-masked by
    # GitLab. The "Mask variable" flag only applies to pre-configured CI/CD
    # variables. If you fetch a secret from Vault inside a job, that secret will
    # appear in logs unless you explicitly avoid echoing it.
    # Best practice: pre-configure rotation-resistant credentials as masked
    # GitLab variables (Settings > CI/CD > Variables, "Mask variable" enabled),
    # or use GitLab's native Vault integration (id_tokens + vault: keyword)
    # which handles masking automatically. Do NOT echo $DATABASE_PASS.

    # Use credentials
    - ./deploy.sh
```

**Don't**: Store static Vault tokens or use insecure authentication.

```yaml
# VULNERABLE: Static Vault token
variables:
  VAULT_TOKEN: "s.abcdef1234567890"  # Never expires, can be stolen

deploy:
  script:
    - vault read secret/production/database

# VULNERABLE: AppRole with static secret
variables:
  VAULT_ROLE_ID: "xxx"
  VAULT_SECRET_ID: "yyy"  # Static, long-lived

deploy:
  script:
    - vault write auth/approle/login role_id=$VAULT_ROLE_ID secret_id=$VAULT_SECRET_ID
```

**Why**: Static Vault tokens or AppRole secrets are long-lived credentials that can be exfiltrated and used outside GitLab. JWT authentication provides short-lived tokens bound to specific pipelines, projects, and branches. If a token is stolen, it expires quickly and cannot be used for unauthorized access.

**Refs**:
- CWE-798: Use of Hard-coded Credentials
- OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene
- GitLab Docs: Using external secrets in CI
- Vault Docs: GitLab CI/CD integration

---

## Rule: Security Scanning - SAST/DAST/Container

**Level**: `strict`

**When**: Building and deploying applications.

**Do**: Implement comprehensive security scanning in all pipelines.

```yaml
# Complete security scanning pipeline
include:
  # GitLab security scanning templates
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/DAST.gitlab-ci.yml
  - template: Security/License-Scanning.gitlab-ci.yml

variables:
  # SAST configuration
  SAST_EXCLUDED_PATHS: "spec, test, tests, node_modules"
  SAST_EXCLUDED_ANALYZERS: ""

  # Dependency scanning
  DS_EXCLUDED_ANALYZERS: ""

  # Container scanning
  CS_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  CS_SEVERITY_THRESHOLD: "HIGH"

  # DAST
  DAST_WEBSITE: https://staging.example.com
  DAST_FULL_SCAN_ENABLED: "true"

stages:
  - build
  - test
  - security
  - deploy

build:
  stage: build
  script:
    - docker build -t $CS_IMAGE .
    - docker push $CS_IMAGE

# Custom security checks in addition to templates
custom_security_scan:
  stage: security
  script:
    # Trivy for comprehensive scanning
    - trivy image --exit-code 1 --severity HIGH,CRITICAL $CS_IMAGE

    # Semgrep with custom rules
    - semgrep --config auto --config p/security-audit --error .

    # Check for secrets
    - gitleaks detect --source . --verbose

    # SBOM generation
    - syft packages $CS_IMAGE -o spdx-json > sbom.json
  artifacts:
    paths:
      - sbom.json
    reports:
      container_scanning: trivy-report.json

# Block deployment if security issues found
deploy_staging:
  stage: deploy
  needs:
    - job: sast
      artifacts: false
    - job: secret_detection
      artifacts: false
    - job: dependency_scanning
      artifacts: false
    - job: container_scanning
      artifacts: false
  script:
    - ./deploy.sh staging
  environment:
    name: staging
```

```yaml
# API security testing
api_security:
  stage: security
  image: zaproxy/zap-stable
  script:
    # OpenAPI/Swagger scanning
    - zap-api-scan.py -t https://staging.example.com/api/openapi.json -f openapi -r api-scan-report.html

    # GraphQL scanning
    - zap-api-scan.py -t https://staging.example.com/graphql -f graphql -r graphql-scan-report.html
  artifacts:
    paths:
      - "*-report.html"
    when: always
```

**Don't**: Skip security scanning or ignore results.

```yaml
# VULNERABLE: No security scanning
build:
  script:
    - npm install
    - npm run build
    - docker build -t myapp .
    - docker push myapp
    # No SAST, DAST, dependency scanning, or container scanning

# VULNERABLE: Ignoring scan results
sast:
  allow_failure: true  # Always passes even with findings

dependency_scanning:
  script:
    - npm audit || true  # Ignores all vulnerabilities
```

**Why**: Security scanning identifies vulnerabilities before deployment. Without scanning, vulnerable dependencies, insecure code patterns, exposed secrets, and container vulnerabilities reach production. Comprehensive scanning (SAST, DAST, SCA, container) provides defense in depth against different vulnerability types.

**Refs**:
- CWE-1035: Using Components with Known Vulnerabilities
- OWASP A06:2021: Vulnerable and Outdated Components
- OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse
- GitLab Docs: Security scanning

---

## Rule: Merge Request Approvals - Required Reviews

**Level**: `strict`

**When**: Changes to code, configuration, or infrastructure.

**Do**: Configure merge request approvals with appropriate rules.

```yaml
# CODEOWNERS file for automatic review assignment
# File: CODEOWNERS

# Security team must approve security-related changes
.gitlab-ci.yml @security-team
/security/ @security-team
**/auth/** @security-team
**/crypto/** @security-team

# DevOps team must approve infrastructure
/terraform/ @devops-team
/kubernetes/ @devops-team
/docker/ @devops-team

# Platform team for shared configurations
/config/ @platform-team
/.gitlab/ @platform-team
```

```yaml
# Merge request approval settings
# Settings > Merge requests > Merge request approvals

# Rules:
# 1. Security team approval for:
#    - .gitlab-ci.yml
#    - /security/**
#    - Changes to dependencies
#    - Minimum: 1 approval

# 2. Code owner approval:
#    - CODEOWNERS approval required
#    - Cannot self-approve

# 3. All merge requests:
#    - Minimum 2 approvals
#    - Reset approvals on new commits
#    - Only users who can merge
```

```yaml
# .gitlab-ci.yml with approval verification
deploy_production:
  stage: deploy
  environment:
    name: production
  script:
    - ./deploy.sh
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  # Environment protection ensures approval before deploy
  # Settings > Environments > production > Protected Environments

# Compliance job to verify approvals
verify_approvals:
  stage: .pre
  script:
    - |
      # Check merge request approvals
      APPROVALS=$(curl -s "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/approval_state" \
        -H "PRIVATE-TOKEN: $GITLAB_TOKEN" | jq '.rules[] | select(.approved == false)')

      if [ -n "$APPROVALS" ]; then
        echo "Missing required approvals"
        exit 1
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

**Don't**: Allow merges without required approvals.

```yaml
# VULNERABLE: No approval requirements
# Anyone with write access can merge
# No CODEOWNERS
# No security team review for sensitive changes
# Self-approval allowed
```

**Why**: Code review catches security vulnerabilities, malicious code, and configuration errors before they reach production. Without required approvals, attackers with write access can directly introduce backdoors. CODEOWNERS ensures domain experts review changes in their areas.

**Refs**:
- OWASP CI/CD Top 10: CICD-SEC-1 Insufficient Flow Control Mechanisms
- SLSA v1.1 Build L3: Hardened build platform (highest SLSA level as of v1.1)
- NIST SSDF PO.5: Implement and Maintain Secure Environments for Software Development
- SOC 2 CC8.1: Changes Are Authorized
- GitLab Docs: Merge request approvals

---

## Rule: Protected Branches and Tags - Access Control

**Level**: `strict`

**When**: Configuring repository branches and release tags.

**Do**: Configure protection rules for critical branches and tags.

```yaml
# Protected branch settings
# Settings > Repository > Protected branches

# main branch:
# - Allowed to push: No one (only merge requests)
# - Allowed to merge: Maintainers
# - Allowed to force push: No
# - Code owner approval required: Yes

# develop branch:
# - Allowed to push: Developers
# - Allowed to merge: Developers
# - Allowed to force push: No

# release/* branches:
# - Allowed to push: No one
# - Allowed to merge: Maintainers
# - Require approval from code owners
```

```yaml
# Protected tag settings
# Settings > Repository > Protected tags

# v* tags:
# - Allowed to create: Maintainers
# - Only signed tags allowed: Yes

# Pipeline that verifies branch protection
verify_protection:
  stage: .pre
  script:
    - |
      # Verify running on protected branch for deployments
      if [[ "$CI_COMMIT_BRANCH" == "main" && "$CI_COMMIT_REF_PROTECTED" != "true" ]]; then
        echo "ERROR: main branch must be protected"
        exit 1
      fi
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

```yaml
# Tag-based releases with protection
release:
  stage: deploy
  script:
    # Only runs on protected tags
    - echo "Creating release for $CI_COMMIT_TAG"
    - ./create-release.sh
  rules:
    - if: '$CI_COMMIT_TAG =~ /^v\d+\.\d+\.\d+$/'
```

**Don't**: Leave production branches unprotected.

```yaml
# VULNERABLE: Unprotected main branch
# Anyone can:
# - Push directly to main
# - Force push to rewrite history
# - Delete the branch
# - Bypass all review requirements
```

**Why**: Protected branches prevent direct pushes, force pushes, and deletions that could introduce malicious code or remove audit trails. Protection ensures all changes go through merge requests with required approvals. Protected tags prevent tampering with release artifacts.

**Refs**:
- CWE-284: Improper Access Control
- OWASP CI/CD Top 10: CICD-SEC-1 Insufficient Flow Control Mechanisms
- NIST SSDF PS.1: Protect All Forms of Code
- GitLab Docs: Protected branches

---

## Rule: Artifact Security - Expiration and Signing

**Level**: `warning`

**When**: Generating and storing pipeline artifacts.

**Do**: Configure artifact expiration and implement signing for release artifacts.

```yaml
# Artifact configuration with security best practices
stages:
  - build
  - test
  - security
  - release

build:
  stage: build
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/
    expire_in: 1 week  # Short retention for build artifacts

test:
  stage: test
  script:
    - npm test
  artifacts:
    reports:
      junit: junit.xml
    expire_in: 30 days  # Longer retention for test results

# Signed release artifacts
release:
  stage: release
  script:
    # Generate checksums
    - sha256sum dist/* > dist/SHA256SUMS

    # Sign with GPG
    - gpg --import $GPG_PRIVATE_KEY
    - gpg --armor --detach-sign dist/SHA256SUMS

    # Sign container
    - cosign sign --key $COSIGN_PRIVATE_KEY $CI_REGISTRY_IMAGE:$CI_COMMIT_TAG

    # Generate SBOM
    - syft packages dir:./dist -o spdx-json > dist/sbom.spdx.json
  artifacts:
    paths:
      - dist/
    expire_in: never  # Release artifacts kept indefinitely
  rules:
    - if: '$CI_COMMIT_TAG'
```

```yaml
# Container signing and verification
build_container:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

    # Sign the container
    - cosign sign --yes $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore

deploy:
  stage: deploy
  script:
    # Verify signature before deployment
    - cosign verify $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

    # Deploy only if verified
    - kubectl set image deployment/app app=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

**Don't**: Keep artifacts indefinitely or publish unsigned releases.

```yaml
# VULNERABLE: No expiration
build:
  artifacts:
    paths:
      - dist/
    # No expire_in - kept forever
    # Consumes storage
    # Old artifacts may have vulnerabilities

# VULNERABLE: Unsigned releases
release:
  script:
    - ./build-release.sh
    - aws s3 cp dist/ s3://releases/
    # No signatures
    # No checksums
    # Consumers cannot verify integrity
```

**Why**: Artifact expiration manages storage and ensures old, potentially vulnerable artifacts don't accumulate. Signed artifacts provide integrity verification and provenance. Without signatures, artifacts can be tampered with in storage or transit without detection.

**Refs**:
- CWE-494: Download of Code Without Integrity Check
- SLSA Level 2: Signed Provenance
- NIST SSDF PS.3: Maintain Provenance Data
- GitLab Docs: Job artifacts

---

## Rule: Environment-Specific Variables - Scoped Secrets

**Level**: `strict`

**When**: Managing variables for multiple deployment environments.

**Do**: Use environment-scoped variables to prevent cross-environment access.

```yaml
# Variable configuration in GitLab UI
# Settings > CI/CD > Variables

# Staging environment variables
# DATABASE_URL
# - Value: postgresql://staging-db.example.com/app
# - Protected: No (staging may not be protected branch)
# - Masked: Yes
# - Environment scope: staging

# Production environment variables
# DATABASE_URL
# - Value: postgresql://prod-db.example.com/app
# - Protected: Yes
# - Masked: Yes
# - Environment scope: production

# .gitlab-ci.yml using scoped variables
stages:
  - build
  - deploy

build:
  stage: build
  script:
    - npm run build

deploy_staging:
  stage: deploy
  environment:
    name: staging
    url: https://staging.example.com
  variables:
    # These variables are automatically scoped to staging
    DEPLOY_ENV: staging
  script:
    # $DATABASE_URL is staging database
    - ./deploy.sh
  rules:
    - if: '$CI_COMMIT_BRANCH == "develop"'

deploy_production:
  stage: deploy
  environment:
    name: production
    url: https://app.example.com
  variables:
    DEPLOY_ENV: production
  script:
    # $DATABASE_URL is production database
    - ./deploy.sh
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual
```

```yaml
# Environment-specific configurations
variables:
  # Default values (can be overridden per environment)
  LOG_LEVEL: info
  CACHE_TTL: 3600

.deploy_template:
  script:
    - echo "Deploying to $CI_ENVIRONMENT_NAME"
    - echo "Database: $DATABASE_URL"  # Scoped per environment
    - ./deploy.sh

deploy_development:
  extends: .deploy_template
  environment:
    name: development
  variables:
    LOG_LEVEL: debug  # More verbose for development

deploy_staging:
  extends: .deploy_template
  environment:
    name: staging

deploy_production:
  extends: .deploy_template
  environment:
    name: production
  variables:
    CACHE_TTL: 7200  # Longer cache for production
  when: manual
```

**Don't**: Use single variables for all environments.

```yaml
# VULNERABLE: Same variables for all environments
variables:
  # Production credentials accessible in all jobs
  DATABASE_URL: $PROD_DATABASE_URL

deploy_staging:
  environment:
    name: staging
  script:
    # Using production database in staging!
    - ./deploy.sh

deploy_production:
  environment:
    name: production
  script:
    - ./deploy.sh
```

**Why**: Environment-scoped variables ensure staging jobs cannot access production credentials and vice versa. This prevents accidental data corruption, enforces separation of concerns, and limits the blast radius if staging is compromised.

**Refs**:
- CWE-269: Improper Privilege Management
- OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene
- SOC 2 CC6.1: Logical and Physical Access Controls
- GitLab Docs: Environment-specific variables

---

## Rule: Pipeline Security - Prevent Override

**Level**: `strict`

**When**: Configuring pipeline security settings and job controls.

**Do**: Prevent variable overrides and job property changes.

```yaml
# Pipeline configuration to prevent overrides
variables:
  # Cannot be overridden by pipeline trigger or child pipeline
  SECURE_ANALYZERS_PREFIX:
    value: "registry.gitlab.com/gitlab-org/security-products/analyzers"
    description: "Security scanner images"
    # Protected from override

# Job with non-overridable properties
security_scan:
  stage: security
  image: $SECURE_ANALYZERS_PREFIX/semgrep:latest
  script:
    - semgrep --config auto --error .
  # These cannot be overridden:
  allow_failure: false
  interruptible: false
  rules:
    - when: always  # Always runs

# Compliance job that validates pipeline
compliance_check:
  stage: .pre
  script:
    - |
      # Verify required jobs exist in pipeline
      JOBS=$(cat .gitlab-ci.yml | yq '.security_scan')
      if [ -z "$JOBS" ]; then
        echo "ERROR: security_scan job is required"
        exit 1
      fi
  rules:
    - when: always
```

```yaml
# Using compliance framework to enforce jobs
# Admin > Compliance > Compliance frameworks
# Create framework with required pipeline configuration

# compliance-pipeline.yml (cannot be bypassed)
stages:
  - .pre
  - compliance
  - build
  - test
  - security
  - deploy
  - .post

compliance_check:
  stage: compliance
  script:
    - echo "Running compliance checks"
    - ./compliance-check.sh
  allow_failure: false

security_gate:
  stage: .post
  script:
    - echo "Verifying security scan results"
    - |
      if [ -f gl-sast-report.json ]; then
        HIGH_VULNS=$(jq '[.vulnerabilities[] | select(.severity == "High")] | length' gl-sast-report.json)
        if [ "$HIGH_VULNS" -gt 0 ]; then
          echo "Found $HIGH_VULNS high severity vulnerabilities"
          exit 1
        fi
      fi
  allow_failure: false
```

**Don't**: Allow variables and job properties to be overridden.

```yaml
# VULNERABLE: Overridable security settings
variables:
  SKIP_SECURITY: "false"

security_scan:
  script:
    - |
      if [ "$SKIP_SECURITY" == "true" ]; then
        echo "Skipping security scan"
        exit 0
      fi
      # Run scan
  # Can be overridden via pipeline trigger:
  # curl --request POST --form "variables[SKIP_SECURITY]=true" ...
```

```yaml
# VULNERABLE: Skippable required jobs
security_scan:
  script:
    - ./security-scan.sh
  allow_failure: true  # Can be bypassed
  rules:
    - when: manual  # Can be skipped
```

**Why**: If security jobs can be overridden or skipped, attackers can bypass them to introduce vulnerabilities. Compliance frameworks and non-overridable settings ensure critical security checks always run and their results are respected.

**Refs**:
- OWASP CI/CD Top 10: CICD-SEC-7 Insecure System Configuration
- NIST SSDF PW.9: Configure Build Processes
- SOC 2 CC8.1: Changes Are Authorized
- GitLab Docs: Compliance pipelines

---

## Rule: Secure Files - Sensitive File Storage

**Level**: `warning`

**When**: Need to store files (certificates, keys, configurations) for CI/CD.

**Do**: Use GitLab Secure Files feature for sensitive file storage.

```yaml
# Secure Files configuration
# Settings > CI/CD > Secure Files
# Upload files through UI or API (not in repository)

# Files are:
# - Encrypted at rest
# - Access controlled
# - Audit logged
# - Available via $CI_PROJECT_DIR/.secure_files

# .gitlab-ci.yml using secure files
deploy:
  stage: deploy
  script:
    # Secure files are automatically downloaded to .secure_files
    - ls -la $CI_PROJECT_DIR/.secure_files

    # Use certificate for deployment
    - kubectl --certificate-authority=$CI_PROJECT_DIR/.secure_files/ca.crt apply -f deployment.yaml

    # Use SSH key for server access
    - chmod 600 $CI_PROJECT_DIR/.secure_files/deploy_key
    - ssh -i $CI_PROJECT_DIR/.secure_files/deploy_key user@server ./deploy.sh

    # Use configuration file
    - cp $CI_PROJECT_DIR/.secure_files/config.yaml ./config.yaml
    - ./app --config config.yaml
```

```yaml
# Alternative: Generate certificates in pipeline
generate_certs:
  stage: build
  script:
    # Generate ephemeral certificates
    - openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=pipeline"

    # Use immediately
    - curl --cert cert.pem --key key.pem https://internal-api.example.com

  # Don't artifact sensitive files
  artifacts:
    paths:
      - output/  # Only non-sensitive outputs
```

**Don't**: Store sensitive files in the repository.

```yaml
# VULNERABLE: Certificates in repository
deploy:
  script:
    # Certificate checked into git
    - kubectl --certificate-authority=./certs/ca.crt apply -f deployment.yaml

# VULNERABLE: Keys in repository
deploy:
  script:
    # Private key in repository
    - ssh -i ./keys/deploy_key user@server

# VULNERABLE: Configuration with secrets in repository
deploy:
  script:
    # Config file with embedded secrets
    - ./app --config ./config/production.yaml
```

**Why**: Sensitive files in repositories are accessible to all users with read access and persist in git history. Secure Files provides encrypted, access-controlled storage with audit logging. Files are automatically downloaded to jobs that need them without exposing them in repository.

**Refs**:
- CWE-798: Use of Hard-coded Credentials
- CWE-312: Cleartext Storage of Sensitive Information
- OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene
- GitLab Docs: Secure files

---

## Rule: Compliance Pipelines - Enforced Security Jobs

**Level**: `strict`

**When**: Ensuring security controls are applied to all projects.

**Do**: Use compliance frameworks to enforce security pipelines.

```yaml
# Compliance framework pipeline
# Admin > Compliance > Frameworks > Create framework
# Attach compliance pipeline that cannot be bypassed

# compliance-framework/.gitlab-ci.yml
# This pipeline is merged with project pipelines

stages:
  - .compliance
  - build
  - test
  - security
  - deploy

# Always runs first
compliance_header:
  stage: .compliance
  script:
    - echo "Compliance pipeline active"
    - echo "Project: $CI_PROJECT_PATH"
    - echo "Pipeline: $CI_PIPELINE_ID"
  rules:
    - when: always

# Required security scans
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml

# Override templates to make non-skippable
sast:
  allow_failure: false
  rules:
    - when: always

secret_detection:
  allow_failure: false
  rules:
    - when: always

dependency_scanning:
  allow_failure: false
  rules:
    - when: always

# Compliance gate before deployment
compliance_gate:
  stage: security
  script:
    - |
      # Check for high/critical vulnerabilities
      for report in gl-sast-report.json gl-dependency-scanning-report.json; do
        if [ -f "$report" ]; then
          CRITICAL=$(jq '[.vulnerabilities[] | select(.severity == "Critical")] | length' "$report")
          if [ "$CRITICAL" -gt 0 ]; then
            echo "BLOCKED: Found $CRITICAL critical vulnerabilities in $report"
            exit 1
          fi
        fi
      done
    - echo "Compliance gate passed"
  allow_failure: false
  rules:
    - when: always
```

```yaml
# Project .gitlab-ci.yml (merged with compliance pipeline)
# Projects cannot remove or override compliance jobs

stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - npm ci
    - npm run build

test:
  stage: test
  script:
    - npm test

# This would normally be added, but compliance pipeline
# already includes security scanning

deploy:
  stage: deploy
  needs:
    - build
    - test
    # Implicit: compliance_gate from compliance pipeline
  script:
    - ./deploy.sh
```

**Don't**: Rely on projects to implement their own security scanning.

```yaml
# VULNERABLE: Optional security scanning
# Each project must implement its own scanning
# Projects can skip or misconfigure scanning
# No central enforcement

# project/.gitlab-ci.yml
build:
  script:
    - npm run build

deploy:
  script:
    - ./deploy.sh
# No security scanning
```

**Why**: Without enforcement, projects may skip security scanning due to time pressure, lack of awareness, or intentional bypass. Compliance pipelines ensure security jobs always run, cannot be modified, and block deployment if issues are found. This provides consistent security across all projects.

**Refs**:
- OWASP CI/CD Top 10: CICD-SEC-1 Insufficient Flow Control Mechanisms
- SOC 2 CC8.1: Changes Are Authorized
- NIST SSDF PO.3: Implement Supporting Toolchains
- GitLab Docs: Compliance frameworks

---

## Summary

These GitLab CI/CD security rules address critical risks in pipeline configuration:

1. **Protect variables** - Mask and protect secrets with appropriate scopes
2. **Isolate runners** - Use tags to separate trusted and untrusted workloads
3. **Verify includes** - Only include configurations from trusted sources
4. **Use Vault integration** - Dynamic secrets with JWT authentication
5. **Implement security scanning** - SAST, DAST, dependency, and container scanning
6. **Require approvals** - Merge request approvals with CODEOWNERS
7. **Protect branches/tags** - Prevent direct pushes and force pushes
8. **Sign artifacts** - Expiration and signatures for release artifacts
9. **Scope variables** - Environment-specific secrets
10. **Prevent overrides** - Non-bypassable security jobs
11. **Use secure files** - Encrypted storage for sensitive files
12. **Enforce compliance** - Compliance frameworks for all projects

Apply these rules to all GitLab CI/CD pipelines for comprehensive security protection.
