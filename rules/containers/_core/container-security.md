# Container Security Core Rules

These foundational container security rules apply to all containerized environments. They establish baseline security principles that must be followed regardless of the specific container runtime or orchestration platform.

---

## Rule: Minimal Base Images

**Level**: `strict`

**When**: Creating container images for any application

**Do**: Use minimal base images that contain only essential components
```dockerfile
# Best: Distroless for compiled applications
FROM gcr.io/distroless/static-debian13:nonroot AS runtime
COPY --from=builder /app/binary /app/binary
USER nonroot:nonroot
ENTRYPOINT ["/app/binary"]

# Good: Alpine for interpreted languages
FROM python:3.13-alpine AS runtime
RUN apk add --no-cache \
    ca-certificates \
    && rm -rf /var/cache/apk/*
COPY --from=builder /app /app
USER nobody:nobody

# Good: Scratch for static binaries
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/binary /binary
USER 65534:65534
ENTRYPOINT ["/binary"]
```

**Don't**: Use full OS images or images with unnecessary components
```dockerfile
# Vulnerable: Full Ubuntu with package manager and shell
FROM ubuntu:latest
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    vim \
    net-tools \
    telnet
COPY app.py /app/
CMD ["python3", "/app/app.py"]
# Risk: 500+ packages, shells, package managers increase attack surface
```

**Why**: Minimal images reduce attack surface by eliminating unnecessary packages, shells, and utilities that attackers could exploit. A typical Ubuntu image contains 100+ binaries that can be used for privilege escalation, lateral movement, or data exfiltration. Distroless images contain only the application and its runtime dependencies, dramatically reducing vulnerability count.

**Refs**: CWE-250, CIS Docker Benchmark 4.1, NIST SP 800-190 Section 3.1

---

## Rule: Non-Root Container Execution

**Level**: `strict`

**When**: Running any container in production

**Do**: Configure containers to run as non-root users
```dockerfile
# Create dedicated user with specific UID/GID
FROM node:22-alpine

# Create non-root user with specific UID for consistency
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup

# Set ownership and switch to non-root user
WORKDIR /app
COPY --chown=appuser:appgroup . .
RUN npm ci --only=production

USER appuser:appgroup

EXPOSE 3000
CMD ["node", "server.js"]
```

```yaml
# Kubernetes: Enforce non-root at pod level
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

**Don't**: Run containers as root or without explicit user specification
```dockerfile
# Vulnerable: Running as root (default)
FROM node:22
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["node", "server.js"]
# Risk: Container escape gives attacker root on host
```

**Why**: Container escape vulnerabilities allow attackers to break out of the container and access the host system. If the container runs as root (UID 0), a successful escape grants root privileges on the host. Running as non-root limits the blast radius of container escapes and prevents modification of system files within the container.

**Refs**: CWE-250, CWE-269, CIS Docker Benchmark 4.1, NIST SP 800-190 Section 4.3

---

## Rule: Image Vulnerability Scanning

**Level**: `strict`

**When**: Building or deploying container images

**Do**: Integrate vulnerability scanning into CI/CD pipelines
```yaml
# GitHub Actions with Trivy
name: Container Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@a20de5420d57c4102486cdd9349b532415f8050e # v0.30.0
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'  # Fail on critical/high vulnerabilities

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
```

```bash
# Local scanning with Grype
grype myapp:latest --fail-on critical

# Scanning with Trivy including secrets detection
trivy image --severity CRITICAL,HIGH \
  --scanners vuln,secret,config \
  --exit-code 1 \
  myapp:latest

# Scanning Dockerfile for misconfigurations
trivy config --severity CRITICAL,HIGH Dockerfile
```

**Don't**: Deploy images without vulnerability scanning
```yaml
# Vulnerable: No security scanning
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t myapp:latest .
      - run: docker push myapp:latest
      # Risk: Unknown vulnerabilities deployed to production
```

**Why**: Container images frequently contain vulnerabilities in base images, libraries, and dependencies. Without scanning, critical vulnerabilities like remote code execution flaws may be deployed to production. Automated scanning catches known CVEs before deployment and enforces security policies through CI/CD gates.

**Refs**: CWE-1104, NIST SP 800-190 Section 3.2, CIS Docker Benchmark 4.4

---

## Rule: Image Signing and Verification

**Level**: `warning`

**When**: Distributing or consuming container images

**Do**: Sign images and verify signatures before deployment
```bash
# Sign images with Cosign
cosign generate-key-pair

# Sign the image
cosign sign --key cosign.key myregistry.io/myapp:v1.0.0

# Verify signature before pulling
cosign verify --key cosign.pub myregistry.io/myapp:v1.0.0

# Sign with keyless OIDC identity in CI (cosign v2+)
# OIDC token is auto-detected from the GitHub Actions environment
# The --oidc-issuer flag was removed in cosign v2.0 (June 2023)
cosign sign --yes myregistry.io/myapp@sha256:<digest>
```

```yaml
# Kubernetes: Enforce signature verification with Kyverno
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "myregistry.io/*"
      attestors:
      - count: 1
        entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
              -----END PUBLIC KEY-----
```

**Don't**: Pull and run unsigned images without verification
```bash
# Vulnerable: No verification of image authenticity
docker pull untrusted-registry.io/someapp:latest
docker run untrusted-registry.io/someapp:latest
# Risk: Image may be tampered with or from malicious source
```

**Why**: Without image signing, attackers can replace legitimate images with malicious versions through registry compromise, man-in-the-middle attacks, or typosquatting. Signed images provide cryptographic proof of origin and integrity, ensuring the image hasn't been modified since it was built by a trusted party.

**Refs**: CWE-494, NIST SP 800-190 Section 3.5, SLSA Build L2 (SLSA v1.1)

---

## Rule: No Secrets in Container Images

**Level**: `strict`

**When**: Building container images or configuring runtime secrets

**Do**: Use runtime secret injection mechanisms
```dockerfile
# Dockerfile: No secrets in image
FROM python:3.13-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

USER nobody:nobody

# Secrets injected at runtime, not build time
CMD ["python", "app.py"]
```

```yaml
# Kubernetes: Inject secrets at runtime
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp:latest
    env:
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-credentials
          key: password
    volumeMounts:
    - name: tls-certs
      mountPath: /etc/tls
      readOnly: true
  volumes:
  - name: tls-certs
    secret:
      secretName: app-tls
      defaultMode: 0400
```

```bash
# Docker: Mount secrets at runtime
docker run -e DATABASE_URL \
  --secret source=db_password,target=/run/secrets/db_password \
  myapp:latest

# Docker Compose: Use secrets
services:
  app:
    image: myapp:latest
    secrets:
      - db_password
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
secrets:
  db_password:
    external: true
```

**Don't**: Embed secrets in images during build
```dockerfile
# Vulnerable: Secrets in build arguments
FROM python:3.13-alpine
ARG DATABASE_PASSWORD
ENV DATABASE_PASSWORD=${DATABASE_PASSWORD}
# Risk: Secret visible in image layers and history

# Vulnerable: Copying secret files
COPY .env /app/.env
COPY credentials.json /app/credentials.json
# Risk: Secrets extracted from image layers
```

**Why**: Secrets embedded in container images are stored in image layers and can be extracted by anyone with access to the image. Build arguments are visible in image history. Even if secrets are deleted in later layers, they remain accessible in earlier layers. This exposes credentials to unauthorized access and makes rotation difficult.

**Refs**: CWE-798, CWE-522, CIS Docker Benchmark 4.10, NIST SP 800-190 Section 4.3

---

## Rule: Read-Only Root Filesystem

**Level**: `warning`

**When**: Running containers in production

**Do**: Configure containers with read-only root filesystems
```dockerfile
FROM python:3.13-alpine

WORKDIR /app
COPY --chown=nobody:nobody . .
RUN pip install --no-cache-dir -r requirements.txt && \
    mkdir -p /app/tmp /app/logs && \
    chown -R nobody:nobody /app/tmp /app/logs

USER nobody:nobody

# Application configured to write only to specific directories
ENV TMPDIR=/app/tmp
CMD ["python", "app.py"]
```

```yaml
# Kubernetes: Read-only with explicit writable mounts
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: app-logs
      mountPath: /app/logs
    - name: cache
      mountPath: /app/.cache
  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: 100Mi
  - name: app-logs
    emptyDir:
      sizeLimit: 500Mi
  - name: cache
    emptyDir:
      sizeLimit: 200Mi
```

```bash
# Docker: Read-only with tmpfs for writable directories
docker run --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --tmpfs /app/logs:rw,noexec,nosuid,size=500m \
  myapp:latest
```

**Don't**: Allow unrestricted filesystem writes
```yaml
# Vulnerable: No read-only restriction
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    # No securityContext defined
    # Risk: Attacker can write malware, modify binaries
```

**Why**: A writable root filesystem allows attackers to modify application binaries, install backdoors, write malware, or modify configuration files. Read-only filesystems prevent persistent modifications and limit the impact of application compromise. Specific writable directories can be mounted for legitimate application needs.

**Refs**: CWE-284, CIS Docker Benchmark 5.12, NIST SP 800-190 Section 4.3

---

## Rule: Drop All Capabilities

**Level**: `strict`

**When**: Running containers in production

**Do**: Drop all Linux capabilities and add only those required
```yaml
# Kubernetes: Minimal capabilities
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      # Add back only what's needed (rarely required)
      # capabilities:
      #   add:
      #     - NET_BIND_SERVICE  # Only if binding to ports < 1024
```

```bash
# Docker: Drop all capabilities
docker run --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  myapp:latest

# If binding to privileged port is required
docker run --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --user 1000:1000 \
  myapp:latest
```

**Don't**: Run with default or all capabilities
```bash
# Vulnerable: Running with default capabilities
docker run myapp:latest
# Risk: Containers have many capabilities by default

# Critical vulnerability: All capabilities
docker run --cap-add=ALL myapp:latest
# Risk: Near-equivalent to running as root on host
```

**Why**: Linux capabilities divide root privileges into distinct units. Default container capabilities include dangerous permissions like CAP_NET_RAW (packet crafting), CAP_SYS_CHROOT (escape attempts), and CAP_SETUID (privilege escalation). Dropping all capabilities and adding back only required ones follows least privilege and reduces attack surface.

**Refs**: CWE-250, CWE-269, CIS Docker Benchmark 5.3, NIST SP 800-190 Section 4.3

---

## Rule: Container Network Segmentation

**Level**: `warning`

**When**: Deploying containers with network connectivity

**Do**: Implement network policies to restrict container communication
```yaml
# Kubernetes: Default deny all ingress and egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Allow specific communication patterns
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend
    ports:
    - protocol: TCP
      port: 5432

---
# Allow egress only to specific services
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

```bash
# Docker: Use custom networks for segmentation
docker network create --driver bridge frontend-net
docker network create --driver bridge backend-net
docker network create --driver bridge --internal db-net

# Connect containers to appropriate networks
docker run --network frontend-net nginx:latest
docker run --network backend-net --network frontend-net app:latest
docker run --network db-net --network backend-net postgres:latest
```

**Don't**: Allow unrestricted network communication
```yaml
# Vulnerable: No network policies
# All pods can communicate with all other pods
# All pods can reach the internet
# Risk: Lateral movement, data exfiltration
```

**Why**: Without network segmentation, a compromised container can access any other container, the Kubernetes API, cloud metadata services, and external networks. Network policies implement zero-trust networking by explicitly defining allowed communication patterns, limiting lateral movement and data exfiltration.

**Refs**: CWE-284, CIS Kubernetes Benchmark 5.3, NIST SP 800-190 Section 4.3, NSA Kubernetes Hardening Guide

---

## Rule: Resource Limits

**Level**: `warning`

**When**: Running containers in shared environments

**Do**: Set memory, CPU, and storage limits for all containers
```yaml
# Kubernetes: Resource requests and limits
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    resources:
      requests:
        memory: "256Mi"
        cpu: "250m"
        ephemeral-storage: "100Mi"
      limits:
        memory: "512Mi"
        cpu: "1000m"
        ephemeral-storage: "500Mi"
```

```yaml
# Kubernetes: Namespace resource quotas
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: production
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    persistentvolumeclaims: "10"

---
# Limit ranges for defaults
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
  - default:
      memory: "512Mi"
      cpu: "500m"
    defaultRequest:
      memory: "256Mi"
      cpu: "250m"
    type: Container
```

```bash
# Docker: Set resource limits
docker run --memory="512m" \
  --memory-swap="512m" \
  --cpus="1.0" \
  --pids-limit=100 \
  --storage-opt size=1G \
  myapp:latest
```

**Don't**: Run containers without resource limits
```yaml
# Vulnerable: No resource limits
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    # No resources defined
    # Risk: Resource exhaustion, noisy neighbor, DoS
```

**Why**: Containers without resource limits can consume all available host resources, causing denial of service to other containers. Attackers can exploit this through resource exhaustion attacks (fork bombs, memory leaks, crypto mining). Resource limits ensure fair sharing, prevent noisy neighbor problems, and limit the impact of compromised containers.

**Refs**: CWE-400, CWE-770, CIS Docker Benchmark 5.10-5.14, NIST SP 800-190 Section 4.3

---

## Rule: Container Health Checks

**Level**: `advisory`

**When**: Running production containers

**Do**: Implement comprehensive health checks
```dockerfile
FROM python:3.13-alpine

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

USER nobody:nobody

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

EXPOSE 8000
CMD ["python", "app.py"]
```

```yaml
# Kubernetes: Liveness, readiness, and startup probes
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    ports:
    - containerPort: 8000
    livenessProbe:
      httpGet:
        path: /health/live
        port: 8000
      initialDelaySeconds: 60
      periodSeconds: 30
      timeoutSeconds: 10
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /health/ready
        port: 8000
      initialDelaySeconds: 10
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 3
    startupProbe:
      httpGet:
        path: /health/startup
        port: 8000
      initialDelaySeconds: 10
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 30
```

**Don't**: Run containers without health monitoring
```yaml
# Vulnerable: No health checks
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    # No probes defined
    # Risk: Failed containers continue receiving traffic
```

**Why**: Without health checks, containers that have crashed, deadlocked, or become unresponsive continue running and receiving traffic. This leads to service degradation and makes security incidents harder to detect. Health checks enable automatic recovery, load balancer integration, and can detect compromise indicators.

**Refs**: CIS Docker Benchmark 4.6, NIST SP 800-190 Section 4.4

---

## Rule: Supply Chain Security

**Level**: `warning`

**When**: Building and deploying container images

**Do**: Implement comprehensive supply chain security measures
```yaml
# Multi-stage build with pinned versions and verification
FROM golang:1.24-alpine@sha256:abc123... AS builder

# Verify dependencies
COPY go.mod go.sum ./
RUN go mod verify

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app

# Minimal runtime image
FROM gcr.io/distroless/static-debian13@sha256:def456...
COPY --from=builder /app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
```

```yaml
# SLSA provenance generation
name: Build with Provenance
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write  # For OIDC
    steps:
      - uses: actions/checkout@v4

      - name: Build and push with provenance
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
          provenance: true
          sbom: true
```

```bash
# Generate SBOM
syft myapp:latest -o spdx-json > sbom.spdx.json

# Verify image provenance
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/myorg/myrepo/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  myregistry.io/myapp:v1.0.0
```

**Don't**: Use unverified images or dependencies
```dockerfile
# Vulnerable: Unverified base image and dependencies
FROM python:latest
RUN pip install -r requirements.txt
# Risk: Compromised base image or malicious dependencies
```

**Why**: Container supply chains are targeted by attackers to distribute malware widely. Compromised base images, malicious packages, and tampered builds can affect thousands of deployments. Supply chain security measures including pinned versions, digest verification, SBOM generation, and provenance attestation provide assurance about the origin and integrity of container contents.

**Refs**: CWE-1104, CWE-494, NIST SP 800-190 Section 3.5, SLSA Framework

---

## Rule: Secure Container Registries

**Level**: `warning`

**When**: Storing and distributing container images

**Do**: Use authenticated, encrypted registry access with access controls
```yaml
# Kubernetes: ImagePullSecrets for private registries
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  imagePullSecrets:
  - name: registry-credentials
  containers:
  - name: app
    image: private-registry.io/myapp:v1.0.0
    imagePullPolicy: Always  # Always pull to get latest security fixes

---
# Create registry secret
apiVersion: v1
kind: Secret
metadata:
  name: registry-credentials
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded-docker-config>
```

```bash
# Docker: Configure registry authentication
docker login private-registry.io --username $USER --password-stdin <<< "$TOKEN"

# Use credential helpers for cloud registries
{
  "credHelpers": {
    "gcr.io": "gcr",
    "us-docker.pkg.dev": "gcloud",
    "*.dkr.ecr.*.amazonaws.com": "ecr-login"
  }
}
```

**Don't**: Use public registries for sensitive images or pull without authentication
```yaml
# Vulnerable: Pulling from public registry without verification
spec:
  containers:
  - name: app
    image: someuser/myapp:latest
    imagePullPolicy: IfNotPresent
    # Risk: Typosquatting, image replacement, no access control
```

**Why**: Public registries can host malicious images with similar names to legitimate ones (typosquatting). Without authentication, anyone can pull your private images if the registry is misconfigured. Using ImagePullPolicy: IfNotPresent means containers may run outdated, vulnerable images. Authenticated registries with access controls ensure only authorized images are deployed.

**Refs**: CWE-284, CWE-494, CIS Docker Benchmark 2.1, NIST SP 800-190 Section 3.5

---

## Rule: Runtime Security Monitoring

**Level**: `advisory`

**When**: Running containers in production

**Do**: Implement runtime security monitoring and threat detection
```yaml
# Falco lists and rules for container runtime security
# List definitions are required; Falco refuses to load rules that reference undefined lists.
# shell_binaries is a Falco built-in; define the rest explicitly.
- list: expected_processes
  items: [python3, node, java, nginx, gunicorn]

- list: expected_parent_processes
  items: [containerd-shim, runc]

- list: allowed_shell_parents
  items: [sshd, sudo]

- rule: Unexpected Process in Container
  desc: Detect unexpected processes spawned in containers
  condition: >
    spawned_process and container and
    not proc.name in (expected_processes) and
    not proc.pname in (expected_parent_processes)
  output: >
    Unexpected process spawned in container
    (user=%user.name command=%proc.cmdline container=%container.name
    image=%container.image.repository)
  priority: WARNING

- rule: Container Shell Access
  desc: Detect shell execution in container
  condition: >
    spawned_process and container and
    proc.name in (shell_binaries) and
    not proc.pname in (allowed_shell_parents)
  output: >
    Shell spawned in container
    (user=%user.name shell=%proc.name container=%container.name
    image=%container.image.repository)
  priority: CRITICAL

- rule: Sensitive File Access
  desc: Detect access to sensitive files
  condition: >
    open_read and container and
    (fd.name in (/etc/shadow, /etc/passwd) or
     fd.name startswith "/etc/kubernetes/")
  output: >
    Sensitive file read in container
    (user=%user.name file=%fd.name container=%container.name)
  priority: CRITICAL
```

```yaml
# Kubernetes: Deploy Falco for runtime monitoring
# Pin to a specific version tag; :latest violates the Image Immutability rule.
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: security
spec:
  selector:
    matchLabels:
      app: falco
  template:
    spec:
      containers:
      - name: falco
        image: falcosecurity/falco:0.38.2  # pin to a specific release
        securityContext:
          privileged: true  # Required for eBPF
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /host/boot
          readOnly: true
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
```

**Don't**: Run containers without runtime monitoring
```yaml
# Vulnerable: No runtime security monitoring
# Cannot detect:
# - Container escapes
# - Cryptocurrency mining
# - Reverse shells
# - Data exfiltration
# - Privilege escalation attempts
```

**Why**: Build-time security scanning cannot detect runtime attacks such as container escapes, cryptomining, reverse shells, or zero-day exploits. Runtime security monitoring uses system call analysis, network monitoring, and behavioral detection to identify suspicious activity. This provides defense in depth and enables rapid incident response.

**Refs**: NIST SP 800-190 Section 4.4, CIS Docker Benchmark 5.1

---

## Rule: Audit Logging

**Level**: `warning`

**When**: Running containers in production

**Do**: Enable comprehensive audit logging for containers and orchestration
```yaml
# Kubernetes: API server audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all requests to secrets at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]

  # Log all pod exec commands
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach"]

  # Log authentication failures
  - level: RequestResponse
    users: ["system:anonymous"]

  # Log metadata for other requests
  - level: Metadata
    omitStages:
    - RequestReceived
```

```bash
# Docker: Enable daemon audit logging
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  },
  "live-restore": true
}

# Enable Linux auditd rules for Docker
-w /usr/bin/docker -p rwxa -k docker
-w /var/lib/docker -p rwxa -k docker
-w /etc/docker -p rwxa -k docker
-w /lib/systemd/system/docker.service -p rwxa -k docker
-w /etc/docker/daemon.json -p rwxa -k docker
```

**Don't**: Run without audit logging
```yaml
# Vulnerable: No audit logging configured
# Cannot investigate:
# - Who accessed secrets
# - What commands were executed in pods
# - When configuration changes occurred
# - How attackers gained access
```

**Why**: Audit logs are essential for security incident investigation, compliance requirements, and detecting unauthorized access. Without audit logging, it's impossible to determine what actions were taken, by whom, and when. This hampers incident response, forensic analysis, and compliance audits.

**Refs**: CWE-778, CIS Kubernetes Benchmark 3.2, NIST SP 800-190 Section 4.4

---

## Rule: Image Immutability

**Level**: `warning`

**When**: Managing container images in production

**Do**: Use immutable image tags and prevent tag mutation
```yaml
# Use digest-based references for critical deployments
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: myregistry.io/myapp@sha256:abc123def456...

# Kyverno: Require image digests
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-digest
spec:
  validationFailureAction: Enforce
  rules:
  - name: require-digest
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Images must use digest references"
      pattern:
        spec:
          containers:
          - image: "*@sha256:*"
```

```bash
# Registry: Enable tag immutability
# AWS ECR
aws ecr put-image-tag-mutability \
  --repository-name myapp \
  --image-tag-mutability IMMUTABLE

# GCP Artifact Registry
gcloud artifacts repositories update myrepo \
  --location=us \
  --immutable-tags
```

**Don't**: Use mutable tags like `latest` in production
```yaml
# Vulnerable: Mutable tag
spec:
  containers:
  - name: app
    image: myapp:latest
    # Risk: Image contents can change without deployment
```

**Why**: Mutable tags like `latest` or version tags can be overwritten, causing unexpected behavior when images are pulled. This breaks reproducibility, makes rollbacks unreliable, and can be exploited by attackers to inject malicious code. Digest-based references ensure the exact same image is always deployed.

**Refs**: CWE-494, NIST SP 800-190 Section 3.2, SLSA v1.1 Build L3
