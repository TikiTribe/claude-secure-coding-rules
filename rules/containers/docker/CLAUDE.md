# Docker Security Rules for Claude Code

These rules guide Claude Code to generate secure Docker configurations, Dockerfiles, and container deployments. Apply these rules when creating or modifying Docker-related files.

---

## Rule: Minimal Base Images

**Level**: `strict`

**When**: Creating Dockerfiles or selecting base images

**Do**: Use minimal base images appropriate for your application
```dockerfile
# Best for compiled languages (Go, Rust, C++)
FROM scratch AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/binary /binary
USER 65534:65534
ENTRYPOINT ["/binary"]

# Best for most applications - Google's distroless
FROM gcr.io/distroless/base-debian13:nonroot AS runtime
COPY --from=builder /app /app
USER nonroot:nonroot
ENTRYPOINT ["/app/server"]

# Good for interpreted languages requiring packages
FROM python:3.13-alpine AS runtime
RUN apk add --no-cache ca-certificates tini && \
    rm -rf /var/cache/apk/* /tmp/*
USER nobody:nobody
ENTRYPOINT ["/sbin/tini", "--"]

# For Java applications
FROM gcr.io/distroless/java21-debian13:nonroot
COPY --from=builder /app/app.jar /app/app.jar
USER nonroot:nonroot
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
```

**Don't**: Use full OS images or unnecessarily large base images
```dockerfile
# Vulnerable: Full Ubuntu with unnecessary tools
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    curl wget vim nano \
    net-tools iputils-ping telnet \
    ssh-client \
    unzip tar gzip
# Problems:
# - 500+ packages with potential vulnerabilities
# - Includes shells for attackers
# - Package manager available for installing malware
# - Networking tools for reconnaissance

# Vulnerable: Using :latest tag
FROM node:latest
# Problem: Unpredictable, may change and break builds
```

**Why**: Minimal images dramatically reduce attack surface. A typical Ubuntu image contains 100+ binaries that can be used for privilege escalation (`sudo`, `su`), lateral movement (`ssh`, `curl`, `wget`), or data exfiltration (`nc`, `tar`). Distroless images contain only the application runtime, reducing CVE count by 80-90%.

**Refs**: CWE-250, CIS Docker Benchmark 4.1, NIST 800-190 Section 3.1

---

## Rule: Non-Root User Directive

**Level**: `strict`

**When**: Creating Dockerfiles

**Do**: Create and switch to a non-root user
```dockerfile
FROM node:22-alpine

# Create non-root user with specific UID for consistency across containers
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S -G appgroup -h /app -s /sbin/nologin appuser

WORKDIR /app

# Copy with correct ownership
COPY --chown=appuser:appgroup package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser:appgroup

EXPOSE 3000
CMD ["node", "server.js"]
```

```dockerfile
# For Python applications
FROM python:3.13-alpine

RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S -G appgroup -h /app -s /sbin/nologin appuser

WORKDIR /app

COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

COPY --chown=appuser:appgroup . .

USER appuser:appgroup

ENV PATH="/app/.local/bin:$PATH"
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```dockerfile
# Using numeric UID for scratch/distroless
FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app /app
# Use numeric UID (nobody = 65534)
USER 65534:65534
ENTRYPOINT ["/app"]
```

**Don't**: Run containers as root
```dockerfile
# Vulnerable: No USER directive (runs as root)
FROM node:22
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["node", "server.js"]
# Risk: Container escape = root access on host

# Vulnerable: Explicitly running as root
USER root
RUN npm install
# Never switch back to non-root
CMD ["node", "server.js"]
```

**Why**: Container escape vulnerabilities like CVE-2019-5736 (runc) and CVE-2020-15257 (containerd) allow attackers to break out of containers. If the container runs as root (UID 0), the attacker gains root on the host. Running as non-root limits impact to unprivileged user access, significantly reducing the severity of container escapes.

**Refs**: CWE-250, CWE-269, CIS Docker Benchmark 4.1, NIST 800-190 Section 4.2.1

---

## Rule: Multi-Stage Builds

**Level**: `strict`

**When**: Building application containers

**Do**: Use multi-stage builds to separate build and runtime environments
```dockerfile
# Stage 1: Build environment with all build tools
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /app/server ./cmd/server

# Stage 2: Minimal runtime
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

```dockerfile
# Node.js multi-stage build
FROM node:22-alpine AS builder
WORKDIR /build
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --production

# Runtime stage
FROM node:22-alpine AS runtime
RUN apk add --no-cache tini && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup

WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /build/dist ./dist
COPY --from=builder --chown=appuser:appgroup /build/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /build/package.json ./

USER appuser:appgroup
EXPOSE 3000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
```

```dockerfile
# Python multi-stage with virtual environment
FROM python:3.13-alpine AS builder
RUN apk add --no-cache build-base libffi-dev
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.13-alpine AS runtime
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup
COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appgroup . /app
WORKDIR /app
USER appuser:appgroup
ENV PATH="/opt/venv/bin:$PATH"
CMD ["python", "app.py"]
```

**Don't**: Include build tools in runtime images
```dockerfile
# Vulnerable: Build tools in runtime image
FROM node:22
WORKDIR /app
COPY . .
RUN npm install && npm run build
# npm, build tools, dev dependencies all in final image
EXPOSE 3000
CMD ["node", "dist/server.js"]
# Problems:
# - Includes npm (can install malware)
# - Includes dev dependencies (larger attack surface)
# - Source code visible in image
```

**Why**: Build environments contain compilers, package managers, development tools, and source code that aren't needed at runtime and increase attack surface. Attackers can use these tools to download malware, compile exploits, or exfiltrate data. Multi-stage builds produce minimal images with only runtime dependencies.

**Refs**: CIS Docker Benchmark 4.9, NIST 800-190 Section 3.1

---

## Rule: No Secrets in Build Arguments or Layers

**Level**: `strict`

**When**: Handling secrets during container build or runtime

**Do**: Use Docker BuildKit secrets or runtime injection
```dockerfile
# syntax=docker/dockerfile:1.4

FROM python:3.13-alpine AS builder

# Mount secrets during build (not stored in layers)
RUN --mount=type=secret,id=pip_token \
    pip install --no-cache-dir \
    --extra-index-url https://$(cat /run/secrets/pip_token)@pypi.example.com/simple \
    -r requirements.txt

FROM python:3.13-alpine AS runtime
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY . /app
USER nobody:nobody
CMD ["python", "/app/main.py"]
```

```bash
# Build with BuildKit secrets
DOCKER_BUILDKIT=1 docker build \
  --secret id=pip_token,src=./pip_token.txt \
  -t myapp:latest .
```

```dockerfile
# Runtime secret injection via environment (from orchestrator)
FROM python:3.13-alpine
COPY . /app
USER nobody:nobody
# Secrets injected at runtime by Docker/Kubernetes
CMD ["python", "/app/main.py"]
```

```yaml
# docker-compose.yml with secrets
services:
  app:
    build: .
    secrets:
      - db_password
      - api_key
    environment:
      - DATABASE_PASSWORD_FILE=/run/secrets/db_password
      - API_KEY_FILE=/run/secrets/api_key

secrets:
  db_password:
    external: true
  api_key:
    external: true
```

**Don't**: Embed secrets in images
```dockerfile
# Vulnerable: Secrets in ARG (visible in history)
ARG DATABASE_PASSWORD
ENV DATABASE_PASSWORD=${DATABASE_PASSWORD}
# docker history shows the value

# Vulnerable: Secrets in ENV
ENV API_KEY=sk-1234567890abcdef
# Plaintext in image configuration

# Vulnerable: Copying secret files
COPY credentials.json /app/
COPY .env /app/
# Secrets extractable from image layers

# Vulnerable: Secrets in RUN commands
RUN curl -H "Authorization: Bearer sk-secret123" https://api.example.com
# Visible in layer history
```

**Why**: Docker image layers are immutable and can be inspected. Secrets in ARG values appear in `docker history`. Secrets in ENV are stored in image config. Secrets in COPY persist in layers even if deleted later. Anyone with image access can extract these secrets. This violates secret management principles and makes rotation impossible.

**Refs**: CWE-798, CWE-522, CIS Docker Benchmark 4.10, NIST 800-190 Section 4.2.3

---

## Rule: Image Vulnerability Scanning

**Level**: `strict`

**When**: Building and deploying Docker images

**Do**: Integrate vulnerability scanning in CI/CD pipelines
```yaml
# GitHub Actions with Trivy
name: Build and Scan
on: [push, pull_request]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan for vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true

      - name: Scan for secrets
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          scanners: 'secret'
          exit-code: '1'

      - name: Scan Dockerfile
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
```

```bash
# Local scanning with Trivy
trivy image --severity CRITICAL,HIGH --exit-code 1 myapp:latest

# Scan with vulnerability database update
trivy image --download-db-only
trivy image --skip-db-update myapp:latest

# Scan for secrets and misconfigurations
trivy image --scanners vuln,secret,config myapp:latest

# Generate SBOM
trivy image --format cyclonedx --output sbom.json myapp:latest

# Scan with Grype
grype myapp:latest --fail-on high

# Scan with Docker Scout
docker scout cves myapp:latest --exit-code --only-severity critical,high
```

```dockerfile
# Dockerfile best practices scanner
# hadolint Dockerfile
FROM python:3.13-alpine
# hadolint will flag issues like:
# - Using :latest tag
# - Missing USER directive
# - Curl/wget without verification
```

**Don't**: Deploy without vulnerability scanning
```yaml
# Vulnerable: No security scanning
jobs:
  deploy:
    steps:
      - run: docker build -t myapp:latest .
      - run: docker push myapp:latest
      - run: kubectl set image deployment/app app=myapp:latest
# Risk: Critical CVEs deployed to production
```

**Why**: Container images contain vulnerabilities in base images, system packages, and application dependencies. Average images contain 50-200 vulnerabilities. Without scanning, critical vulnerabilities like remote code execution can be deployed. Automated scanning catches known CVEs before deployment and generates SBOMs for compliance.

**Refs**: CWE-1104, NIST 800-190 Section 3.2, CIS Docker Benchmark 4.4

---

## Rule: Content Trust and Image Signing

**Level**: `warning`

**When**: Distributing or consuming Docker images

**Do**: Sign images and enable content trust
```bash
# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1
export DOCKER_CONTENT_TRUST_SERVER=https://notary.example.com

# Push will automatically sign
docker push myregistry.io/myapp:v1.0.0

# Pull will verify signature
docker pull myregistry.io/myapp:v1.0.0

# Sign with Cosign (recommended)
cosign generate-key-pair

# Sign image
cosign sign --key cosign.key myregistry.io/myapp:v1.0.0

# Verify signature
cosign verify --key cosign.pub myregistry.io/myapp:v1.0.0

# Keyless signing with OIDC (GitHub Actions)
cosign sign --oidc-issuer=https://token.actions.githubusercontent.com \
  myregistry.io/myapp:v1.0.0
```

```yaml
# GitHub Actions: Keyless signing with Cosign
- name: Sign image with Cosign
  run: |
    cosign sign --yes \
      --oidc-issuer=https://token.actions.githubusercontent.com \
      ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
  env:
    COSIGN_EXPERIMENTAL: "true"
```

**Don't**: Use unsigned images without verification
```bash
# Vulnerable: No signature verification
docker pull someregistry.io/app:latest
docker run someregistry.io/app:latest
# Risk: Image may be tampered or from malicious source

# Vulnerable: Disabled content trust
export DOCKER_CONTENT_TRUST=0
docker pull myregistry.io/myapp:latest
```

**Why**: Without signing, attackers can replace legitimate images through registry compromise, man-in-the-middle attacks, or typosquatting (e.g., `myap` vs `myapp`). Image signing provides cryptographic proof of origin and integrity. Content trust prevents pulling unsigned or tampered images.

**Refs**: CWE-494, CIS Docker Benchmark 4.5, NIST 800-190 Section 3.3

---

## Rule: Read-Only Root Filesystem

**Level**: `warning`

**When**: Running Docker containers

**Do**: Mount root filesystem as read-only with explicit writable directories
```bash
# Run with read-only root filesystem
docker run --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --tmpfs /var/run:rw,noexec,nosuid,size=10m \
  -v app-logs:/var/log/app:rw \
  myapp:latest

# Docker Compose
services:
  app:
    image: myapp:latest
    read_only: true
    tmpfs:
      - /tmp:size=100m,mode=1777
      - /var/run:size=10m
    volumes:
      - app-logs:/var/log/app:rw
      - app-data:/app/data:rw
```

```dockerfile
# Prepare application for read-only filesystem
FROM python:3.13-alpine

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt && \
    mkdir -p /app/tmp /app/logs /app/.cache && \
    chown -R nobody:nobody /app

USER nobody:nobody

# Configure app to use specific writable directories
ENV TMPDIR=/app/tmp
ENV CACHE_DIR=/app/.cache
CMD ["python", "app.py"]
```

**Don't**: Allow unrestricted filesystem writes
```bash
# Vulnerable: Writable filesystem
docker run myapp:latest
# Attacker can:
# - Modify application binaries
# - Install backdoors
# - Write malware
# - Modify configuration files
```

**Why**: A writable root filesystem allows attackers to modify application binaries, install backdoors, write malware, or tamper with configuration. Read-only filesystems prevent persistent modifications and limit the impact of application compromise. tmpfs mounts provide necessary writable space without persistence.

**Refs**: CWE-284, CIS Docker Benchmark 5.12, NIST 800-190 Section 4.2.2

---

## Rule: Drop All Capabilities

**Level**: `strict`

**When**: Running Docker containers

**Do**: Drop all Linux capabilities and add only required ones
```bash
# Drop all capabilities
docker run --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  myapp:latest

# Add back specific capability if absolutely required
docker run --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --user 1000:1000 \
  --security-opt=no-new-privileges:true \
  myapp:latest
```

```yaml
# Docker Compose
services:
  app:
    image: myapp:latest
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    # Only if binding to port < 1024
    # cap_add:
    #   - NET_BIND_SERVICE
```

**Common capabilities and their risks**:
```bash
# Dangerous capabilities to never add:
# CAP_SYS_ADMIN   - Mount filesystems, load kernel modules
# CAP_SYS_PTRACE  - Debug processes, bypass security
# CAP_SYS_RAWIO   - Direct I/O access
# CAP_NET_ADMIN   - Network configuration changes
# CAP_DAC_OVERRIDE - Bypass file permission checks

# Rarely needed capabilities:
# CAP_NET_BIND_SERVICE - Bind to ports < 1024
# CAP_CHOWN           - Change file ownership
# CAP_SETUID          - Change UID (dangerous!)
```

**Don't**: Run with default or elevated capabilities
```bash
# Vulnerable: Default capabilities (13 capabilities)
docker run myapp:latest

# Critical: All capabilities
docker run --cap-add=ALL myapp:latest
# Equivalent to root on host

# Vulnerable: Dangerous capabilities
docker run --cap-add=SYS_ADMIN myapp:latest
docker run --cap-add=SYS_PTRACE myapp:latest
```

**Why**: Linux capabilities divide root privileges into distinct units. Docker containers have 13 capabilities by default, including dangerous ones like CAP_NET_RAW (ARP spoofing, packet sniffing) and CAP_SETFCAP (setting file capabilities). Dropping all capabilities and adding only required ones follows least privilege and significantly reduces attack surface.

**Refs**: CWE-250, CWE-269, CIS Docker Benchmark 5.3-5.4, NIST 800-190 Section 4.2.1

---

## Rule: No Privileged Containers

**Level**: `strict`

**When**: Running Docker containers

**Do**: Run containers with restricted privileges
```bash
# Secure container runtime
docker run \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --security-opt=seccomp=default.json \
  --read-only \
  --user 10001:10001 \
  myapp:latest
```

```yaml
# Docker Compose with security options
services:
  app:
    image: myapp:latest
    user: "10001:10001"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp-profile.json
    read_only: true
    tmpfs:
      - /tmp
```

**Don't**: Run privileged containers
```bash
# Critical vulnerability: Privileged mode
docker run --privileged myapp:latest
# Gives full host access:
# - All capabilities
# - Access to all devices
# - Can mount host filesystem
# - Can load kernel modules
# - Effectively root on host

# Vulnerable: Elevated privileges
docker run --cap-add=SYS_ADMIN myapp:latest
docker run --device=/dev/sda myapp:latest
docker run -v /:/host myapp:latest
```

**Why**: Privileged containers have full access to the host system, effectively negating container isolation. An attacker who compromises a privileged container has root access to the host and can escape the container trivially. This is the most severe container security misconfiguration.

**Refs**: CWE-250, CWE-269, CIS Docker Benchmark 5.4, NIST 800-190 Section 4.2.1

---

## Rule: Container Health Checks

**Level**: `advisory`

**When**: Creating production Dockerfiles

**Do**: Implement comprehensive health checks
```dockerfile
FROM python:3.13-alpine

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

USER nobody:nobody

# Health check with appropriate intervals
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```dockerfile
# For containers without wget/curl
FROM gcr.io/distroless/base-debian13:nonroot

COPY --from=builder /app/server /server
COPY --from=builder /app/healthcheck /healthcheck

USER nonroot:nonroot

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/healthcheck"]

ENTRYPOINT ["/server"]
```

```dockerfile
# Multiple health check approaches
# HTTP endpoint
HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1

# TCP port check
HEALTHCHECK CMD nc -z localhost 5432 || exit 1

# Custom script
HEALTHCHECK CMD /app/healthcheck.sh || exit 1

# PostgreSQL
HEALTHCHECK CMD pg_isready -U postgres || exit 1

# Redis
HEALTHCHECK CMD redis-cli ping || exit 1
```

**Don't**: Skip health checks in production
```dockerfile
# Vulnerable: No health check
FROM python:3.13-alpine
COPY . /app
CMD ["python", "/app/main.py"]
# Problems:
# - No automatic restart on failure
# - No readiness detection
# - Harder to detect compromised containers
```

**Why**: Without health checks, containers that crash, deadlock, or become unresponsive continue running. Orchestrators can't automatically restart failed containers or route traffic away from unhealthy instances. Health checks enable automatic recovery and can detect anomalies that may indicate compromise.

**Refs**: CIS Docker Benchmark 4.6, NIST 800-190 Section 4.4.1

---

## Rule: Resource Limits

**Level**: `warning`

**When**: Running Docker containers in production

**Do**: Set memory, CPU, and PID limits
```bash
# Run with resource limits
docker run \
  --memory="512m" \
  --memory-swap="512m" \
  --memory-reservation="256m" \
  --cpus="1.0" \
  --cpu-shares=1024 \
  --pids-limit=100 \
  --ulimit nofile=1024:1024 \
  --ulimit nproc=64:64 \
  myapp:latest
```

```yaml
# Docker Compose resource limits
services:
  app:
    image: myapp:latest
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
          pids: 100
        reservations:
          cpus: '0.5'
          memory: 256M
    ulimits:
      nofile:
        soft: 1024
        hard: 1024
      nproc:
        soft: 64
        hard: 64
```

```bash
# System-wide Docker daemon defaults
# /etc/docker/daemon.json
{
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 1024,
      "Soft": 1024
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 64,
      "Soft": 64
    }
  }
}
```

**Don't**: Run containers without resource limits
```bash
# Vulnerable: No limits
docker run myapp:latest
# Risks:
# - Fork bombs can exhaust PIDs
# - Memory leaks can OOM host
# - CPU mining can starve other containers
# - File descriptor exhaustion
```

**Why**: Containers without resource limits can consume all host resources, causing denial of service to other containers and the host system. Attackers exploit this through fork bombs (--pids-limit prevents), memory exhaustion (--memory prevents), and CPU abuse (--cpus prevents). Limits ensure fair resource sharing and contain compromise impact.

**Refs**: CWE-400, CWE-770, CIS Docker Benchmark 5.10-5.14, NIST 800-190 Section 4.2.4

---

## Rule: Secure .dockerignore

**Level**: `warning`

**When**: Building Docker images

**Do**: Create comprehensive .dockerignore to exclude sensitive files
```gitignore
# .dockerignore

# Version control
.git
.gitignore
.svn

# Secrets and credentials
.env
.env.*
*.pem
*.key
*.crt
**/secrets/
credentials.json
service-account.json
*.secret

# Build artifacts and dependencies
node_modules
__pycache__
*.pyc
.pytest_cache
.coverage
coverage/
dist/
build/
target/

# IDE and editor files
.vscode
.idea
*.swp
*.swo
*~

# Documentation and tests (usually not needed in runtime)
docs/
*.md
README*
CHANGELOG*
test/
tests/
*_test.go
*.test.js

# Docker files
Dockerfile*
docker-compose*.yml
.dockerignore

# CI/CD
.github/
.gitlab-ci.yml
.travis.yml
Jenkinsfile

# OS files
.DS_Store
Thumbs.db

# Log files
*.log
logs/
```

**Don't**: Build images without .dockerignore
```bash
# Vulnerable: No .dockerignore
# The following get copied into the image:
# - .git directory (full history including deleted secrets)
# - .env files with credentials
# - Private keys and certificates
# - IDE settings with personal info
# - Test files and coverage reports
# - node_modules (may differ from npm ci)
```

**Why**: Without .dockerignore, COPY and ADD instructions include all files in the build context, including sensitive data like .git directories (containing full history), environment files with credentials, private keys, and IDE configurations. These become extractable from image layers and may be exposed if the image is published.

**Refs**: CWE-200, CWE-522, CIS Docker Benchmark 4.10

---

## Additional Security Configurations

### Seccomp Profile

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "stat", "fstat",
        "lstat", "poll", "lseek", "mmap", "mprotect", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "ioctl",
        "access", "pipe", "select", "sched_yield", "mremap",
        "msync", "mincore", "madvise", "shmget", "shmat",
        "exit", "exit_group", "wait4", "kill", "uname",
        "fcntl", "flock", "fsync", "fdatasync", "truncate",
        "ftruncate", "getdents", "getcwd", "chdir", "fchdir",
        "rename", "mkdir", "rmdir", "link", "unlink", "symlink",
        "readlink", "chmod", "fchmod", "chown", "fchown",
        "lchown", "umask", "gettimeofday", "getuid", "getgid",
        "geteuid", "getegid", "getpgid", "getppid", "getpgrp",
        "setsid", "setpgid", "getgroups", "setresuid", "setresgid",
        "getresuid", "getresgid", "sigaltstack", "rt_sigreturn",
        "clock_gettime", "clock_getres", "clock_nanosleep",
        "futex", "sched_getaffinity", "epoll_create", "epoll_ctl",
        "epoll_wait", "epoll_pwait", "epoll_create1", "dup",
        "dup2", "dup3", "socket", "connect", "accept", "accept4",
        "sendto", "recvfrom", "sendmsg", "recvmsg", "bind",
        "listen", "getsockname", "getpeername", "socketpair",
        "setsockopt", "getsockopt", "clone", "execve", "arch_prctl",
        "prctl", "pread64", "pwrite64", "readv", "writev",
        "getrandom", "memfd_create", "openat", "fstatat", "unlinkat",
        "renameat", "faccessat", "fchmodat", "fchownat", "newfstatat"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### AppArmor Profile

```bash
# /etc/apparmor.d/docker-myapp
#include <tunables/global>

profile docker-myapp flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network inet tcp,
  network inet udp,
  network inet icmp,

  deny @{PROC}/* w,
  deny @{PROC}/sys/** w,
  deny /sys/** w,

  /app/** r,
  /app/logs/** rw,
  /tmp/** rw,

  deny /etc/shadow r,
  deny /etc/passwd r,
}
```

### Docker Daemon Security Configuration

```json
{
  "icc": false,
  "userns-remap": "default",
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp-profile.json",
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65535,
      "Soft": 65535
    }
  }
}
```

**Refs**: CIS Docker Benchmark Section 2, NIST 800-190 Section 4

---

## Rule: Secure Dependency Files

**Level**: `strict`

**When**: Creating or updating `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`, or any container dependency file

**Do**: Pin all dependencies to exact versions with hash verification, and scan for known vulnerabilities

### Python — `requirements.txt` (hash-pinned)

```text
# requirements.txt generated by pip-compile with --generate-hashes
# pip-compile --generate-hashes --output-file=requirements.txt requirements.in

fastapi==0.115.12 \
    --hash=sha256:e5f9db7b9b01d4156cd7f7e6f8d3773a5b52bc21b1b7b8a8c72f34b2b2d1e8a1 \
    --hash=sha256:b2f2a8e1c3d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a
uvicorn[standard]==0.34.2 \
    --hash=sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 \
    --hash=sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4
pydantic==2.11.4 \
    --hash=sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5 \
    --hash=sha256:f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

```dockerfile
# Dockerfile: install with hash verification
FROM python:3.13-alpine AS builder
RUN apk add --no-cache build-base libffi-dev

WORKDIR /build
COPY requirements.txt .
# --require-hashes enforces all packages have hashes; fails on mismatch
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

FROM python:3.13-alpine AS runtime
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup -s /sbin/nologin

COPY --from=builder /usr/local/lib/python3.13 /usr/local/lib/python3.13
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --chown=appuser:appgroup . /app
WORKDIR /app
USER appuser:appgroup
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
# Generate locked requirements with hashes (use pip-tools)
pip install pip-tools
pip-compile --generate-hashes --strip-extras requirements.in

# Audit for known CVEs
pip install pip-audit
pip-audit -r requirements.txt --desc

# Upgrade and re-lock
pip-compile --upgrade --generate-hashes requirements.in
```

### Python — `pyproject.toml` (uv / Poetry)

```toml
# pyproject.toml — managed by uv (fast, secure resolver)
[project]
name = "my-app"
version = "1.0.0"
requires-python = ">=3.13"
dependencies = [
    "fastapi==0.115.0",
    "uvicorn[standard]==0.34.0",
    "pydantic==2.11.0",
]

[dependency-groups]
dev = [
    "pip-audit==2.8.0",
    "ruff==0.9.0",
    "pytest==8.3.0",
]

[tool.uv]
# Pin the Python version used inside the container build
python-version = "3.13"
```

```dockerfile
# Dockerfile with uv for fast, reproducible installs
FROM python:3.13-alpine AS builder
RUN pip install --no-cache-dir uv==0.6.14

WORKDIR /build
COPY pyproject.toml uv.lock ./
# --frozen ensures uv.lock is not regenerated (reproducible)
RUN uv sync --frozen --no-dev --compile-bytecode

FROM python:3.13-alpine AS runtime
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup -s /sbin/nologin
COPY --from=builder /build/.venv /app/.venv
COPY --chown=appuser:appgroup . /app
WORKDIR /app
USER appuser:appgroup
ENV PATH="/app/.venv/bin:$PATH"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
# Lock dependencies
uv lock
# Audit with pip-audit via uv
uv run pip-audit
# Check for outdated packages
uv tree --outdated
```

### Node.js — `package.json` + lockfile

```json
{
  "name": "my-app",
  "version": "1.0.0",
  "engines": {
    "node": ">=22.0.0",
    "npm": ">=10.0.0"
  },
  "dependencies": {
    "express": "4.21.2",
    "helmet": "8.0.0",
    "express-rate-limit": "7.5.0"
  },
  "devDependencies": {
    "@types/node": "22.15.3",
    "typescript": "5.8.3"
  },
  "scripts": {
    "audit": "npm audit --audit-level=high",
    "audit:fix": "npm audit fix"
  }
}
```

```dockerfile
# Dockerfile: reproducible Node.js install
FROM node:22-alpine AS builder
WORKDIR /build
COPY package.json package-lock.json ./
# npm ci: clean install from lockfile only, fails on lockfile mismatch
RUN npm ci --ignore-scripts && npm audit --audit-level=high
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine AS runtime
RUN apk add --no-cache tini && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup -s /sbin/nologin

WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /build/dist ./dist
COPY --from=builder --chown=appuser:appgroup /build/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /build/package.json ./

USER appuser:appgroup
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
```

```bash
# Audit dependencies
npm audit --audit-level=high

# Continuous monitoring with socket.dev or snyk
npx snyk test
# Or use socket
npx socket scan

# Generate SBOM
npm sbom --sbom-format cyclonedx
```

### Go — `go.mod` + `go.sum`

```go
// go.mod — module with explicit Go version
module github.com/example/myapp

go 1.24

require (
    github.com/gin-gonic/gin v1.10.0
    github.com/golang-jwt/jwt/v5 v5.2.2
)
```

```dockerfile
# Dockerfile: Go build with module verification
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build
COPY go.mod go.sum ./
# Verify module checksums against sum database (sum.golang.org)
RUN go mod download && go mod verify

COPY . .
# -trimpath removes local path info; -ldflags strips debug symbols
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /app/server ./cmd/server

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

```bash
# Scan for known vulnerabilities in Go modules
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Check for outdated modules
go list -u -m all

# Tidy and verify
go mod tidy && go mod verify
```

**Don't**: Use unpinned, unverified, or unscanned dependencies

```text
# Vulnerable requirements.txt — unpinned
fastapi
uvicorn
pydantic
# Problems:
# - Any version (including ones with CVEs) may be installed
# - No reproducibility between builds
# - No integrity verification
```

```json
// Vulnerable package.json — floating ranges
{
  "dependencies": {
    "express": "^4.0.0",
    "some-lib": "*"
  }
}
// ^ and * allow installing any new major/minor versions
// A compromised package publish can inject malware
```

```dockerfile
# Vulnerable: dependencies not scanned
FROM python:3.13-alpine
COPY requirements.txt .
RUN pip install -r requirements.txt
# No --require-hashes, no pip-audit
# A dependency with a known CVE ships silently to production
```

**Why**: Supply-chain attacks (OWASP A06:2021 — Vulnerable and Outdated Components) increasingly target dependency ecosystems. Unpinned packages allow silent upgrades to compromised versions (e.g., `event-stream`, `ua-parser-js` incidents). Hash verification (`--require-hashes`, `npm ci`, `go mod verify`) ensures installed packages match what was tested. Automated auditing (`pip-audit`, `npm audit`, `govulncheck`) catches CVEs before they reach production.

**Refs**: CWE-1104, OWASP A06:2021, NIST SP 800-161 (Supply Chain Risk), CIS Docker Benchmark 4.9, SLSA Supply Chain Levels
