# Kubernetes Security Rules for Claude Code

These rules guide Claude Code to generate secure Kubernetes configurations, manifests, and deployments. Apply these rules when creating or modifying Kubernetes resources.

---

## Rule: Pod Security Standards (Restricted Profile)

**Level**: `strict`

**When**: Creating Pod specifications or deployments

**Do**: Apply restricted Pod Security Standards
```yaml
# Namespace-level enforcement
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted

---
# Pod meeting restricted profile requirements
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abc123...
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "512Mi"
        cpu: "1000m"
      requests:
        memory: "256Mi"
        cpu: "250m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: 100Mi
```

```yaml
# Deployment with restricted profile
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: myregistry.io/myapp:v1.0.0@sha256:abc123...
        ports:
        - containerPort: 8080
          protocol: TCP
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/.cache
      volumes:
      - name: tmp
        emptyDir:
          sizeLimit: 100Mi
      - name: cache
        emptyDir:
          sizeLimit: 200Mi
```

**Don't**: Create pods without security context or with privileged settings
```yaml
# Vulnerable: No security context
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
# Runs as root, all capabilities, writable filesystem

# Vulnerable: Privileged container
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
# Complete host access, container escape trivial
```

**Why**: Pod Security Standards define three profiles (privileged, baseline, restricted) that enforce security settings at the namespace level. The restricted profile prevents container escapes, privilege escalation, and limits blast radius of compromised containers. Without enforcement, containers run with dangerous defaults including root user, all capabilities, and writable filesystem.

**Refs**: CWE-250, CIS Kubernetes Benchmark 5.2, NSA Kubernetes Hardening Guide, Pod Security Standards

---

## Rule: RBAC Least Privilege

**Level**: `strict`

**When**: Creating ServiceAccounts, Roles, or RoleBindings

**Do**: Follow least privilege principle with scoped RBAC
```yaml
# Dedicated ServiceAccount (not default)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production
automountServiceAccountToken: false  # Disabled by default

---
# Role with minimal permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
# Only allow reading specific ConfigMaps
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]  # Specific resources only
  verbs: ["get"]
# Only allow reading specific Secrets
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["app-credentials"]
  verbs: ["get"]

---
# RoleBinding (not ClusterRoleBinding)
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-role-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-service-account
  namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# Pod using dedicated service account
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: production
spec:
  serviceAccountName: app-service-account
  automountServiceAccountToken: true  # Only if needed
  # If token needed, mount read-only
  containers:
  - name: app
    image: myapp:latest
```

**Don't**: Use overly permissive RBAC
```yaml
# Vulnerable: Wildcard permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-everything
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
# Grants full cluster admin access

# Vulnerable: Read all secrets
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
# Can read all secrets in all namespaces

# Vulnerable: Using default service account
apiVersion: v1
kind: Pod
spec:
  # Uses default service account
  containers:
  - name: app
    image: myapp:latest
```

**Why**: RBAC controls who can perform what actions in Kubernetes. Overly permissive roles allow attackers to escalate privileges, read secrets, modify deployments, or take over the cluster. Using wildcard permissions or ClusterRoles when namespace-scoped Roles suffice violates least privilege. The default service account often has unnecessary permissions.

**Refs**: CWE-269, CWE-284, CIS Kubernetes Benchmark 5.1, NSA Kubernetes Hardening Guide

---

## Rule: Network Policies (Default Deny)

**Level**: `strict`

**When**: Deploying workloads in Kubernetes

**Do**: Implement default deny with explicit allow rules
```yaml
# Default deny all ingress and egress
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
# Allow app to receive traffic from ingress controller
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-app
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
      podSelector:
        matchLabels:
          app.kubernetes.io/name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080

---
# Allow backend to communicate with database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-to-database
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
# Allow backend egress to database and DNS only
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
  # Allow DNS resolution
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow database access
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

```yaml
# Deny access to cloud metadata service
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-service
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32  # Block metadata service
```

**Don't**: Allow unrestricted network traffic
```yaml
# Vulnerable: No network policies
# All pods can:
# - Communicate with all other pods
# - Access Kubernetes API server
# - Reach cloud metadata service
# - Connect to the internet
# Risk: Lateral movement, credential theft, data exfiltration
```

**Why**: By default, all pods can communicate with each other and external networks. This allows attackers to move laterally between pods, access the Kubernetes API, query cloud metadata services for credentials, and exfiltrate data. Network policies implement zero-trust networking by explicitly defining allowed communication patterns.

**Refs**: CWE-284, CIS Kubernetes Benchmark 5.3, NSA Kubernetes Hardening Guide, NIST 800-190 Section 4.3.2

---

## Rule: SecurityContext Configuration

**Level**: `strict`

**When**: Defining container security settings

**Do**: Configure comprehensive SecurityContext
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: production
spec:
  # Pod-level security context
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    fsGroupChangePolicy: "OnRootMismatch"
    seccompProfile:
      type: RuntimeDefault
    supplementalGroups: [10001]

  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abc123...

    # Container-level security context
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 10001
      runAsGroup: 10001
      capabilities:
        drop:
          - ALL
        # Add back only if absolutely required:
        # add:
        #   - NET_BIND_SERVICE
      seccompProfile:
        type: RuntimeDefault
      # Optional: Enable SELinux
      # seLinuxOptions:
      #   level: "s0:c123,c456"

    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/.cache
    - name: secrets
      mountPath: /etc/secrets
      readOnly: true

  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: 100Mi
  - name: cache
    emptyDir:
      sizeLimit: 200Mi
  - name: secrets
    secret:
      secretName: app-secrets
      defaultMode: 0400
```

**Don't**: Omit SecurityContext or use insecure settings
```yaml
# Vulnerable: Missing security context
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
# Defaults:
# - Runs as root (UID 0)
# - All capabilities enabled
# - Writable filesystem
# - Privilege escalation allowed

# Vulnerable: Insecure security context
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
      runAsUser: 0
      allowPrivilegeEscalation: true
```

**Why**: SecurityContext controls the security settings applied to pods and containers. Without it, containers run with dangerous defaults that allow privilege escalation, container escapes, and host system access. Properly configured SecurityContext ensures defense in depth by enforcing non-root users, dropping capabilities, and enabling seccomp profiles.

**Refs**: CWE-250, CWE-269, CIS Kubernetes Benchmark 5.2, NSA Kubernetes Hardening Guide

---

## Rule: No Host Namespace Sharing

**Level**: `strict`

**When**: Creating Pod specifications

**Do**: Keep pods isolated from host namespaces
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: isolated-pod
spec:
  # All host namespace sharing explicitly disabled
  hostNetwork: false
  hostPID: false
  hostIPC: false

  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
```

**Don't**: Share host namespaces with containers
```yaml
# Vulnerable: Host network namespace
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: myapp:latest
# Risks:
# - Access all host network interfaces
# - Sniff network traffic
# - Bind to any port
# - Bypass network policies

# Vulnerable: Host PID namespace
apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
  - name: app
    image: myapp:latest
# Risks:
# - See all host processes
# - Send signals to host processes
# - Access /proc of host processes
# - Read environment variables of other containers

# Vulnerable: Host IPC namespace
apiVersion: v1
kind: Pod
spec:
  hostIPC: true
  containers:
  - name: app
    image: myapp:latest
# Risks:
# - Access shared memory of host
# - Communicate with host processes
```

**Why**: Sharing host namespaces breaks container isolation. hostNetwork allows network traffic sniffing and bypasses network policies. hostPID exposes all host processes and allows sending signals to them. hostIPC allows access to host shared memory. These settings essentially give containers host-level access and should never be used for application workloads.

**Refs**: CWE-284, CIS Kubernetes Benchmark 5.2.2-5.2.4, NSA Kubernetes Hardening Guide

---

## Rule: Resource Quotas and Limits

**Level**: `warning`

**When**: Deploying workloads to Kubernetes

**Do**: Set resource requests and limits for all containers
```yaml
# Container resource limits
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

---
# Namespace ResourceQuota
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: production
spec:
  hard:
    requests.cpu: "20"
    requests.memory: 40Gi
    limits.cpu: "40"
    limits.memory: 80Gi
    pods: "100"
    persistentvolumeclaims: "20"
    secrets: "50"
    configmaps: "50"
    services: "20"
    services.loadbalancers: "2"
    services.nodeports: "0"

---
# LimitRange for defaults
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
    max:
      memory: "2Gi"
      cpu: "2"
    min:
      memory: "64Mi"
      cpu: "50m"
    type: Container
  - max:
      storage: "10Gi"
    type: PersistentVolumeClaim
```

**Don't**: Deploy without resource constraints
```yaml
# Vulnerable: No resource limits
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
# Risks:
# - Memory exhaustion can OOM node
# - CPU starvation of other pods
# - Denial of service
# - Cryptocurrency mining

# Vulnerable: No namespace quotas
# A single namespace can consume all cluster resources
```

**Why**: Containers without resource limits can consume unlimited node resources, causing denial of service to other pods and potentially crashing nodes. ResourceQuotas prevent namespace resource abuse. LimitRanges enforce defaults and boundaries. These controls prevent resource exhaustion attacks and ensure fair multi-tenant resource sharing.

**Refs**: CWE-400, CWE-770, CIS Kubernetes Benchmark 5.2.6, NIST 800-190 Section 4.2.4

---

## Rule: Secrets Management

**Level**: `strict`

**When**: Handling sensitive data in Kubernetes

**Do**: Use proper secret management with encryption and access control
```yaml
# Enable encryption at rest in API server
# /etc/kubernetes/enc/enc.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}  # Fallback for reading old secrets

---
# Secret with proper mode
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: production
type: Opaque
stringData:
  database-password: "actual-password"

---
# Mount secrets with restricted permissions
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    volumeMounts:
    - name: secrets
      mountPath: /etc/secrets
      readOnly: true
    env:
    # Individual secret keys as environment variables
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: app-secrets
          key: database-password
  volumes:
  - name: secrets
    secret:
      secretName: app-secrets
      defaultMode: 0400  # Read-only for owner only
      items:
      - key: database-password
        path: db-password
        mode: 0400
```

```yaml
# External secrets with ESO (External Secrets Operator)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-password
    remoteRef:
      key: production/database
      property: password
```

**Don't**: Mishandle secrets
```yaml
# Vulnerable: Secrets in ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DATABASE_PASSWORD: "my-password"
# ConfigMaps are not encrypted, easily viewed

# Vulnerable: Secrets in environment from manifest
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    env:
    - name: DATABASE_PASSWORD
      value: "hardcoded-password"
# Visible in pod spec

# Vulnerable: No encryption at rest
# etcd stores secrets in plaintext by default
```

**Why**: Kubernetes secrets are base64-encoded, not encrypted. Without encryption at rest, anyone with etcd access can read all secrets. Secrets in ConfigMaps or hardcoded in manifests are not protected. Improper mount permissions allow other users to read secret files. External secret management systems provide better security with rotation, audit logging, and dynamic secrets.

**Refs**: CWE-312, CWE-522, CIS Kubernetes Benchmark 5.4, NSA Kubernetes Hardening Guide

---

## Rule: Service Account Token Management

**Level**: `warning`

**When**: Creating pods or service accounts

**Do**: Disable automatic token mounting and use projected volumes when needed
```yaml
# ServiceAccount with disabled automount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production
automountServiceAccountToken: false

---
# Pod explicitly disabling token mount
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: production
spec:
  serviceAccountName: app-service-account
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:latest

---
# When API access is needed: use projected volume with expiration
apiVersion: v1
kind: Pod
metadata:
  name: app-with-api-access
spec:
  serviceAccountName: app-service-account
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:latest
    volumeMounts:
    - name: sa-token
      mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      readOnly: true
  volumes:
  - name: sa-token
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 3600  # 1 hour expiration
          audience: api
      - configMap:
          name: kube-root-ca.crt
          items:
          - key: ca.crt
            path: ca.crt
```

**Don't**: Use automatic token mounting without need
```yaml
# Vulnerable: Default token mounting
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
# Token auto-mounted at /var/run/secrets/kubernetes.io/serviceaccount
# If compromised, attacker can access Kubernetes API

# Vulnerable: Using default service account
# Default SA may have permissions from cluster defaults
```

**Why**: Service account tokens provide access to the Kubernetes API. Automatically mounted tokens in every pod expand the attack surface unnecessarily. If a pod is compromised, the attacker can use the token to interact with the API server. Disabling automount and using short-lived projected tokens when needed reduces risk and limits token validity period.

**Refs**: CWE-522, CIS Kubernetes Benchmark 5.1.5-5.1.6, NSA Kubernetes Hardening Guide

---

## Rule: Image Pull Policy and Security

**Level**: `warning`

**When**: Specifying container images

**Do**: Use secure image references and appropriate pull policies
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: production
spec:
  # Pull from private registry
  imagePullSecrets:
  - name: registry-credentials

  containers:
  - name: app
    # Use digest for immutability
    image: myregistry.io/myapp:v1.0.0@sha256:abc123def456...
    # Always pull to ensure latest security patches
    imagePullPolicy: Always

  - name: sidecar
    # If using tag, must use Always
    image: myregistry.io/sidecar:v2.0.0
    imagePullPolicy: Always

---
# Registry credentials secret
apiVersion: v1
kind: Secret
metadata:
  name: registry-credentials
  namespace: production
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded-docker-config>
```

```yaml
# Kyverno: Enforce image digest usage
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
          initContainers:
          - image: "*@sha256:*"
```

**Don't**: Use insecure image references
```yaml
# Vulnerable: Using :latest tag
spec:
  containers:
  - name: app
    image: myapp:latest
    imagePullPolicy: IfNotPresent
# Risks:
# - Image contents can change
# - IfNotPresent may use cached vulnerable image
# - No reproducibility

# Vulnerable: No imagePullSecrets for private registry
spec:
  containers:
  - name: app
    image: privateregistry.io/myapp:v1.0.0
# May fail or fall back to public registry
```

**Why**: The `:latest` tag is mutable and can change between pulls. Using `IfNotPresent` with mutable tags means nodes may run different versions. Without digest pinning, the same tag can reference different images over time. This breaks reproducibility, complicates rollbacks, and can be exploited to inject malicious images.

**Refs**: CWE-494, CIS Kubernetes Benchmark 5.5.1, NSA Kubernetes Hardening Guide

---

## Rule: Admission Controllers and Policy Enforcement

**Level**: `warning`

**When**: Enforcing security policies cluster-wide

**Do**: Use admission controllers to enforce security policies
```yaml
# Kyverno: Enforce security policies
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-security-context
spec:
  validationFailureAction: Enforce
  rules:
  - name: require-run-as-non-root
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Containers must run as non-root"
      pattern:
        spec:
          securityContext:
            runAsNonRoot: true
          containers:
          - securityContext:
              runAsNonRoot: true
              allowPrivilegeEscalation: false

---
# Kyverno: Disallow privileged containers
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: Enforce
  rules:
  - name: no-privileged-containers
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Privileged containers are not allowed"
      pattern:
        spec:
          containers:
          - securityContext:
              privileged: "!true"
          initContainers:
          - securityContext:
              privileged: "!true"

---
# Kyverno: Require resource limits
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
spec:
  validationFailureAction: Enforce
  rules:
  - name: require-limits
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Resource limits are required"
      pattern:
        spec:
          containers:
          - resources:
              limits:
                memory: "?*"
                cpu: "?*"
```

```yaml
# OPA Gatekeeper: Constraint template
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
```

**Don't**: Run without policy enforcement
```yaml
# Vulnerable: No admission controller policies
# Anyone can deploy:
# - Privileged containers
# - Containers running as root
# - Containers without resource limits
# - Images from untrusted registries
```

**Why**: Admission controllers intercept requests to the Kubernetes API before persistence. Without policy enforcement, users can deploy insecure workloads that violate security requirements. Kyverno, OPA Gatekeeper, and other policy engines automate security enforcement, ensuring compliance with organizational policies and security standards.

**Refs**: CWE-284, CIS Kubernetes Benchmark 5.6, NSA Kubernetes Hardening Guide

---

## Rule: API Server Audit Logging

**Level**: `warning`

**When**: Configuring Kubernetes API server

**Do**: Enable comprehensive audit logging
```yaml
# Audit policy configuration
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all requests to secrets at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]

  # Log pod exec and attach
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # Log all authentication failures
  - level: RequestResponse
    users: ["system:anonymous"]

  # Log RBAC changes
  - level: RequestResponse
    resources:
    - group: "rbac.authorization.k8s.io"
      resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

  # Log service account token requests
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["serviceaccounts/token"]

  # Log persistent volume operations
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["persistentvolumes", "persistentvolumeclaims"]

  # Log node operations
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["nodes"]
    verbs: ["create", "update", "patch", "delete"]

  # Log workload changes
  - level: Metadata
    resources:
    - group: "apps"
      resources: ["deployments", "daemonsets", "statefulsets", "replicasets"]
    - group: "batch"
      resources: ["jobs", "cronjobs"]

  # Log everything else at Metadata level
  - level: Metadata
    omitStages:
    - RequestReceived
```

```yaml
# API server configuration
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
apiServer:
  extraArgs:
    audit-policy-file: /etc/kubernetes/audit-policy.yaml
    audit-log-path: /var/log/kubernetes/audit/audit.log
    audit-log-maxage: "30"
    audit-log-maxbackup: "10"
    audit-log-maxsize: "100"
  extraVolumes:
  - name: audit-policy
    hostPath: /etc/kubernetes/audit-policy.yaml
    mountPath: /etc/kubernetes/audit-policy.yaml
    readOnly: true
  - name: audit-logs
    hostPath: /var/log/kubernetes/audit
    mountPath: /var/log/kubernetes/audit
```

**Don't**: Disable or skip audit logging
```yaml
# Vulnerable: No audit logging
# Cannot investigate:
# - Who accessed secrets
# - What commands were executed
# - When RBAC was modified
# - How attackers gained access
```

**Why**: Audit logs are essential for security incident investigation, compliance requirements, and detecting unauthorized access. Without audit logging, it's impossible to determine what actions were taken, by whom, and when. Audit logs should capture security-relevant events like secret access, exec commands, RBAC changes, and authentication attempts.

**Refs**: CWE-778, CIS Kubernetes Benchmark 3.2, NSA Kubernetes Hardening Guide

---

## Rule: Node Security Configuration

**Level**: `warning`

**When**: Configuring Kubernetes nodes

**Do**: Harden kubelet and node configuration
```yaml
# Kubelet configuration
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
readOnlyPort: 0  # Disable read-only port
protectKernelDefaults: true
makeIPTablesUtilChains: true
eventRecordQPS: 5
tlsCipherSuites:
  # TLS 1.2 ciphers (TLS 1.3 ciphers are always enabled and not configurable)
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
tlsMinVersion: VersionTLS12
```

```bash
# Kubelet security flags
--anonymous-auth=false
--authentication-token-webhook=true
--authorization-mode=Webhook
--read-only-port=0
--protect-kernel-defaults=true
--rotate-certificates=true
```

**Don't**: Use insecure node configurations
```yaml
# Vulnerable: Anonymous authentication enabled
authentication:
  anonymous:
    enabled: true
# Anyone can query kubelet API

# Vulnerable: Read-only port exposed
readOnlyPort: 10255
# Exposes node information without authentication
```

**Why**: Kubelet is the primary node agent that runs on each node. Insecure kubelet configuration allows unauthorized access to node information, container logs, and can enable attacks against containers. Anonymous authentication, read-only ports, and weak authorization modes expose nodes to reconnaissance and exploitation.

**Refs**: CIS Kubernetes Benchmark 4.2, NSA Kubernetes Hardening Guide

---

## Rule: Ingress TLS Configuration

**Level**: `warning`

**When**: Configuring Ingress resources

**Do**: Enforce TLS with strong configuration
```yaml
# Ingress with TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/hsts: "true"
    nginx.ingress.kubernetes.io/hsts-max-age: "31536000"
    nginx.ingress.kubernetes.io/hsts-include-subdomains: "true"
    nginx.ingress.kubernetes.io/hsts-preload: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls-secret
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 8080

---
# TLS secret with certificate
apiVersion: v1
kind: Secret
metadata:
  name: app-tls-secret
  namespace: production
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
```

```yaml
# cert-manager for automatic TLS
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app-certificate
  namespace: production
spec:
  secretName: app-tls-secret
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  commonName: app.example.com
  dnsNames:
  - app.example.com
  privateKey:
    algorithm: ECDSA
    size: 256
```

**Don't**: Expose services without TLS
```yaml
# Vulnerable: No TLS configuration
apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        backend:
          service:
            name: app-service
            port:
              number: 8080
# Traffic is unencrypted

# Vulnerable: Weak TLS configuration
annotations:
  nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2"
# TLS 1.0 and 1.1 are deprecated and vulnerable
```

**Why**: Ingress controllers terminate TLS for incoming traffic. Without TLS, traffic is transmitted in plaintext and can be intercepted. Weak TLS configurations with outdated protocols or ciphers are vulnerable to attacks like POODLE, BEAST, and downgrade attacks. HSTS prevents protocol downgrade attacks.

**Refs**: CWE-319, CIS Kubernetes Benchmark 5.5.1, NIST 800-190

---

## Rule: PodDisruptionBudgets

**Level**: `advisory`

**When**: Deploying critical workloads

**Do**: Configure PodDisruptionBudgets for availability
```yaml
# PodDisruptionBudget with minAvailable
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: app-pdb
  namespace: production
spec:
  minAvailable: 2  # At least 2 pods must be available
  selector:
    matchLabels:
      app: myapp

---
# PodDisruptionBudget with maxUnavailable
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: api-pdb
  namespace: production
spec:
  maxUnavailable: 1  # At most 1 pod can be unavailable
  selector:
    matchLabels:
      app: api
```

**Don't**: Deploy without availability protection
```yaml
# Vulnerable: No PodDisruptionBudget
# During cluster upgrades or maintenance:
# - All pods can be evicted simultaneously
# - Service outage during rolling updates
# - No protection against accidental disruption
```

**Why**: PodDisruptionBudgets protect applications from voluntary disruptions like node drains during cluster upgrades. Without PDBs, all pods can be evicted simultaneously, causing service outages. PDBs ensure a minimum number of pods remain available during maintenance operations.

**Refs**: CIS Kubernetes Benchmark 5.7, Kubernetes Documentation

---

## Rule: Namespace Isolation

**Level**: `warning`

**When**: Organizing cluster resources

**Do**: Use namespaces for isolation and apply appropriate policies
```yaml
# Production namespace with security labels
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    environment: production
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted

---
# Staging namespace with different policies
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    environment: staging
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted

---
# Network policy for namespace isolation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-from-other-namespaces
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}  # Only from same namespace
```

```yaml
# RBAC scoped to namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: staging
subjects:
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role
  apiGroup: rbac.authorization.k8s.io
# Developers can only access staging namespace
```

**Don't**: Mix environments or skip namespace isolation
```yaml
# Vulnerable: Everything in default namespace
# All workloads share:
# - Network access (no isolation)
# - RBAC policies
# - Resource quotas
# - Security policies

# Vulnerable: No cross-namespace network isolation
# Pods in staging can access production database
```

**Why**: Namespaces provide logical isolation for multi-tenant clusters. Without namespace isolation, workloads from different environments or teams can interfere with each other. Network policies, RBAC, and resource quotas should be scoped to namespaces to provide defense in depth and limit blast radius of security incidents.

**Refs**: CWE-284, CIS Kubernetes Benchmark 5.7, NSA Kubernetes Hardening Guide

---

## Additional Security Configurations

### Secure etcd Configuration

```yaml
# etcd encryption configuration
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-32-byte-key>
      - identity: {}
```

### Security Scanning with Kubescape

```bash
# Scan cluster for security issues
kubescape scan framework nsa --submit --account <account-id>

# Scan specific namespace
kubescape scan framework cis-kubernetes -n production

# Scan YAML files
kubescape scan *.yaml --format json --output results.json
```

### Falco Runtime Security Rules

```yaml
# Falco rules for Kubernetes
- rule: Unauthorized Shell in Container
  desc: Detect shell execution in containers
  condition: >
    spawned_process and container and
    shell_procs and
    not proc.pname in (allowed_shell_parents)
  output: >
    Shell executed in container
    (user=%user.name container=%container.name
    shell=%proc.name parent=%proc.pname
    cmdline=%proc.cmdline image=%container.image.repository)
  priority: CRITICAL

- rule: Kubernetes API Server Access
  desc: Detect access to Kubernetes API from containers
  condition: >
    outbound and container and
    fd.sip in (kubernetes_api_server_ips)
  output: >
    Kubernetes API access from container
    (container=%container.name image=%container.image.repository
    connection=%fd.name)
  priority: WARNING
```

**Refs**: CIS Kubernetes Benchmark, NSA Kubernetes Hardening Guide, Pod Security Standards

---

## Rule: Image Supply Chain Verification

**Level**: `strict`

**When**: Deploying container images to Kubernetes

**Do**: Enforce cryptographic image signature verification and digest pinning at admission time

```yaml
# Kyverno: Verify Cosign signatures before admission
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
  annotations:
    policies.kyverno.io/title: Verify Image Signatures
    policies.kyverno.io/description: >
      Images must be signed with Cosign using keyless OIDC signing
      before they are admitted to the cluster.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "myregistry.io/myapp:*"
      attestors:
      - count: 1
        entries:
        - keyless:
            subject: "https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/heads/main"
            issuer: "https://token.actions.githubusercontent.com"
            rekor:
              url: https://rekor.sigstore.dev
      mutateDigest: true     # Rewrite tag to digest for immutability
      verifyDigest: true
      required: true
```

```yaml
# Kyverno: Require SBOM attestation alongside signature
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sbom-attestation
spec:
  validationFailureAction: Enforce
  background: false
  rules:
  - name: check-sbom
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "myregistry.io/*:*"
      attestations:
      - type: https://cyclonedx.org/bom
        attestors:
        - entries:
          - keyless:
              subject: "https://github.com/my-org/*"
              issuer: "https://token.actions.githubusercontent.com"
```

```yaml
# Kyverno: Enforce digest-only image references (no mutable tags)
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
          kinds: [Pod]
    validate:
      message: "Images must use immutable digest references (@sha256:...)"
      foreach:
      - list: "request.object.spec.containers"
        deny:
          conditions:
            any:
            - key: "{{ element.image }}"
              operator: NotEquals
              value: "*@sha256:*"
      - list: "request.object.spec.initContainers"
        deny:
          conditions:
            any:
            - key: "{{ element.image }}"
              operator: NotEquals
              value: "*@sha256:*"
```

```bash
# CI/CD: Sign image and attach SBOM after build (GitHub Actions)
# 1. Build and push
docker build -t myregistry.io/myapp:v1.2.3 .
docker push myregistry.io/myapp:v1.2.3

# 2. Generate SBOM
syft myregistry.io/myapp:v1.2.3 -o cyclonedx-json > sbom.json

# 3. Sign image (keyless via OIDC — no key management needed)
cosign sign --yes myregistry.io/myapp:v1.2.3

# 4. Attach SBOM as attestation
cosign attest --yes --type cyclonedx \
  --predicate sbom.json \
  myregistry.io/myapp:v1.2.3

# 5. Verify before deploy
cosign verify \
  --certificate-identity-regexp="https://github.com/my-org/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  myregistry.io/myapp:v1.2.3
```

```bash
# Scan cluster for unsigned or unverified images
# Using Trivy Operator (runs inside the cluster)
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
helm install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace
kubectl get vulnerabilityreports -A
kubectl get sbomreports -A
```

**Don't**: Allow unsigned or mutable image references in production

```yaml
# Vulnerable: Mutable tag with no signature check
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myregistry.io/myapp:latest
    imagePullPolicy: IfNotPresent
# Risks:
# - Tag can be silently repointed to malicious image
# - No cryptographic proof of build provenance
# - Supply chain compromise undetectable

# Vulnerable: No admission policy — unsigned images admitted
# Any developer can push a compromised image and deploy it
```

**Why**: Supply chain attacks (OWASP A06:2021) compromise container images before they reach production — via compromised CI/CD pipelines, dependency confusion, or registry tampering. Cosign keyless signing creates an immutable, verifiable audit trail in the public Rekor transparency log, linking each image to the specific CI/CD workflow that built it. Kyverno enforces these checks at admission, blocking unverified images before they can run. Combined with digest pinning, this ensures that what was approved is exactly what runs.

**Refs**: CWE-494, OWASP A06:2021, SLSA (Supply-chain Levels for Software Artifacts) L3+, NIST SP 800-218 (SSDF), CIS Kubernetes Benchmark 5.5, Sigstore / Cosign documentation
