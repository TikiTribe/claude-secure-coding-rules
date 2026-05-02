# Helm Security Rules for Claude Code

These rules guide Claude Code to generate secure Helm charts, values files, and release configurations. Apply these rules when creating or modifying Helm-related files.

---

## Rule: No Hardcoded Secrets in Values Files

**Level**: `strict`

**When**: Creating `values.yaml`, `values-*.yaml`, or any Helm values file

**Do**: Use secret references — never inline secrets — and document required external sources

```yaml
# values.yaml — safe defaults, no actual secrets
image:
  repository: myregistry.io/myapp
  tag: "v1.2.3"
  pullPolicy: Always

# Database config — values only reference secret names/keys
database:
  host: postgres.production.svc.cluster.local
  port: 5432
  name: myapp
  # Secret name that must exist in the namespace before install
  existingSecret: myapp-db-credentials
  passwordKey: password
  usernameKey: username

# External secrets (ESO) — chart creates ExternalSecret, not Secret
externalSecrets:
  enabled: true
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  refreshInterval: 1h
```

```yaml
# templates/deployment.yaml — consume secret reference
env:
- name: DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.passwordKey }}
- name: DATABASE_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.usernameKey }}
```

```yaml
# templates/externalsecret.yaml — create ExternalSecret if enabled
{{- if .Values.externalSecrets.enabled }}
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {{ include "myapp.fullname" . }}-db-credentials
  namespace: {{ .Release.Namespace }}
spec:
  refreshInterval: {{ .Values.externalSecrets.refreshInterval }}
  secretStoreRef:
    name: {{ .Values.externalSecrets.secretStoreRef.name }}
    kind: {{ .Values.externalSecrets.secretStoreRef.kind }}
  target:
    name: {{ .Values.database.existingSecret }}
    creationPolicy: Owner
  data:
  - secretKey: password
    remoteRef:
      key: {{ .Release.Namespace }}/database
      property: password
  - secretKey: username
    remoteRef:
      key: {{ .Release.Namespace }}/database
      property: username
{{- end }}
```

```bash
# Install with secret pre-created (not stored in chart)
kubectl create secret generic myapp-db-credentials \
  --from-literal=password="$(vault kv get -field=password secret/prod/db)" \
  --from-literal=username="myapp" \
  --namespace production

helm install myapp ./myapp --namespace production
```

**Don't**: Put secrets directly in values files

```yaml
# Vulnerable: Hardcoded secrets in values.yaml
database:
  password: "supersecret123"
  apiKey: "sk-1234567890abcdef"

# Vulnerable: Secrets passed via --set (appear in shell history and Helm release secret)
# helm install myapp ./myapp --set database.password=secret123
```

**Why**: Helm stores release state — including all values — in Kubernetes Secrets (base64-encoded, not encrypted). Any secret passed via `--set` or `values.yaml` becomes readable by anyone with access to those Secrets. Values files are typically committed to version control, further exposing credentials. External secrets management keeps secrets out of Git and the Helm release store entirely.

**Refs**: CWE-312, CWE-522, OWASP A02:2021, CIS Kubernetes Benchmark 5.4

---

## Rule: Secure Container SecurityContext Defaults

**Level**: `strict`

**When**: Creating `templates/deployment.yaml`, `templates/statefulset.yaml`, or any workload template

**Do**: Set restrictive security context defaults in both chart values and templates

```yaml
# values.yaml — secure defaults
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  fsGroupChangePolicy: "OnRootMismatch"
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
```

```yaml
# templates/deployment.yaml — render security contexts from values
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        {{- toYaml .Values.podSecurityContext | nindent 8 }}
      containers:
      - name: {{ .Chart.Name }}
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        securityContext:
          {{- toYaml .Values.securityContext | nindent 12 }}
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        {{- with .Values.extraVolumeMounts }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      volumes:
      - name: tmp
        emptyDir:
          sizeLimit: 100Mi
      {{- with .Values.extraVolumes }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
```

```yaml
# templates/NOTES.txt — warn if security context is weakened
{{- if .Values.securityContext.allowPrivilegeEscalation }}
WARNING: allowPrivilegeEscalation is enabled. This is a security risk.
{{- end }}
{{- if not .Values.podSecurityContext.runAsNonRoot }}
WARNING: Pod is configured to run as root. Consider setting runAsNonRoot: true.
{{- end }}
```

**Don't**: Use insecure defaults or allow security context overrides without validation

```yaml
# Vulnerable: No security context defined
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
# Container runs as root with all capabilities

# Vulnerable: Permissive defaults that users rarely override
podSecurityContext: {}
securityContext:
  runAsUser: 0
  privileged: true
```

**Why**: Helm chart defaults become production defaults for most users who do not customize values. Insecure defaults ship insecure deployments at scale. Every chart consuming this template inherits the security posture — restrictive defaults mean secure-by-default deployments. Privilege escalation and root execution enable container escape attacks (CVE-2019-5736, CVE-2020-15257).

**Refs**: CWE-250, CWE-269, CIS Kubernetes Benchmark 5.2, NSA Kubernetes Hardening Guide

---

## Rule: Resource Requests and Limits

**Level**: `warning`

**When**: Creating any workload template

**Do**: Define resource requests and limits with sensible defaults configurable via values

```yaml
# values.yaml
resources:
  requests:
    cpu: 250m
    memory: 256Mi
    ephemeral-storage: 100Mi
  limits:
    cpu: 1000m
    memory: 512Mi
    ephemeral-storage: 500Mi
```

```yaml
# templates/deployment.yaml
containers:
- name: {{ .Chart.Name }}
  resources:
    {{- toYaml .Values.resources | nindent 12 }}
```

```yaml
# templates/_helpers.tpl — validate that limits are set
{{- define "myapp.validateResources" -}}
{{- if not .Values.resources.limits.memory }}
  {{- fail "resources.limits.memory must be set to prevent OOM conditions" }}
{{- end }}
{{- if not .Values.resources.limits.cpu }}
  {{- fail "resources.limits.cpu must be set to prevent CPU starvation" }}
{{- end }}
{{- end }}
```

**Don't**: Leave resources unconfigured or set no limits

```yaml
# Vulnerable: Empty resources (no limits)
resources: {}

# Vulnerable: Requests without limits allow unbounded growth
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  # No limits — pod can consume all node resources
```

**Why**: Containers without resource limits can consume unlimited node resources, causing denial of service to co-located workloads. Limits enforce fair resource sharing and bound the blast radius of memory leaks, runaway processes, or cryptomining workloads. Requests ensure the scheduler places pods on nodes with sufficient capacity.

**Refs**: CWE-400, CWE-770, CIS Kubernetes Benchmark 5.2.6

---

## Rule: Image Tag and Digest Pinning

**Level**: `strict`

**When**: Defining container image references in values or templates

**Do**: Default to specific version tags with digest pinning capability

```yaml
# values.yaml — explicit tag, digest field available for production pinning
image:
  repository: myregistry.io/myapp
  # Never use 'latest'. Use semver tags.
  tag: "v1.2.3"
  # For production: set digest to pin to an immutable reference
  # digest: "sha256:abc123def456..."
  pullPolicy: Always
```

```yaml
# templates/deployment.yaml — prefer digest if set, fall back to tag
containers:
- name: {{ .Chart.Name }}
  image: >-
    {{- if .Values.image.digest -}}
    {{ .Values.image.repository }}@{{ .Values.image.digest }}
    {{- else -}}
    {{ .Values.image.repository }}:{{ .Values.image.tag }}
    {{- end }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
```

```yaml
# templates/_helpers.tpl — warn if using latest tag
{{- define "myapp.validateImage" -}}
{{- if eq .Values.image.tag "latest" }}
  {{- fail "image.tag must not be 'latest'. Use an explicit semver tag." }}
{{- end }}
{{- end }}
```

```yaml
# values-production.yaml — production overrides pin to digest
image:
  repository: myregistry.io/myapp
  tag: "v1.2.3"
  digest: "sha256:abc123def456789abc123def456789abc123def456789abc123def456789abcd"
  pullPolicy: Always
```

**Don't**: Default to mutable or unversioned image references

```yaml
# Vulnerable: Latest tag
image:
  repository: myapp
  tag: latest
  pullPolicy: IfNotPresent
# 'latest' changes silently; IfNotPresent uses stale cached images

# Vulnerable: No tag (Docker defaults to latest)
image:
  repository: myapp
```

**Why**: The `:latest` tag is mutable and can reference different images over time. A compromised registry or typosquatting attack can silently replace the image. Digest references are immutable — the SHA-256 hash is computed from the image manifest, so any change produces a different digest. Combined with `imagePullPolicy: Always`, digest pinning guarantees exactly the tested image runs in production.

**Refs**: CWE-494, CIS Kubernetes Benchmark 5.5.1, NSA Kubernetes Hardening Guide

---

## Rule: Network Policy Integration

**Level**: `warning`

**When**: Creating Helm charts for network-accessible services

**Do**: Include NetworkPolicy templates with a configurable default-deny posture

```yaml
# values.yaml
networkPolicy:
  enabled: true
  # Ingress: allow from ingress-controller namespace only by default
  ingress:
    enabled: true
    fromNamespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: ingress-nginx
    fromPodSelector:
      matchLabels:
        app.kubernetes.io/name: ingress-nginx
  # Egress: restrict to DNS + named services
  egress:
    enabled: true
    allowDNS: true
    additionalRules: []
```

```yaml
# templates/networkpolicy.yaml
{{- if .Values.networkPolicy.enabled }}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "myapp.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "myapp.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "myapp.selectorLabels" . | nindent 6 }}
  policyTypes:
  - Ingress
  - Egress
  {{- if .Values.networkPolicy.ingress.enabled }}
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          {{- toYaml .Values.networkPolicy.ingress.fromNamespaceSelector.matchLabels | nindent 10 }}
      podSelector:
        matchLabels:
          {{- toYaml .Values.networkPolicy.ingress.fromPodSelector.matchLabels | nindent 10 }}
    ports:
    - port: {{ .Values.service.port }}
      protocol: TCP
  {{- end }}
  {{- if .Values.networkPolicy.egress.enabled }}
  egress:
  {{- if .Values.networkPolicy.egress.allowDNS }}
  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  {{- end }}
  {{- with .Values.networkPolicy.egress.additionalRules }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
  {{- end }}
{{- end }}
```

**Don't**: Ship charts without network policy support

```yaml
# Vulnerable: No networkPolicy template — chart is deployed with no traffic controls
# All pods can communicate with all other pods and external endpoints by default
```

**Why**: Without network policies, a compromised pod can freely communicate with any other pod, reach the Kubernetes API server, query cloud metadata services for credentials, or exfiltrate data externally. Providing a network policy template in the chart makes least-privilege networking the path of least resistance for chart consumers.

**Refs**: CWE-284, CIS Kubernetes Benchmark 5.3, NSA Kubernetes Hardening Guide

---

## Rule: RBAC and ServiceAccount Least Privilege

**Level**: `strict`

**When**: Creating ServiceAccount, Role, or RoleBinding templates

**Do**: Create a dedicated, scoped ServiceAccount with `automountServiceAccountToken: false`

```yaml
# values.yaml
serviceAccount:
  # Creates a dedicated SA (recommended)
  create: true
  name: ""
  # Never auto-mount unless the application explicitly needs API access
  automountServiceAccountToken: false
  annotations: {}

rbac:
  # Create RBAC rules scoped to this chart's resources only
  create: true
```

```yaml
# templates/serviceaccount.yaml
{{- if .Values.serviceAccount.create -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "myapp.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "myapp.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
automountServiceAccountToken: {{ .Values.serviceAccount.automountServiceAccountToken }}
{{- end }}
```

```yaml
# templates/role.yaml — scope permissions to the minimum required
{{- if .Values.rbac.create }}
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "myapp.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "myapp.labels" . | nindent 4 }}
rules:
# Only grant what the application actually needs
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["{{ include "myapp.fullname" . }}-config"]
  verbs: ["get"]
{{- end }}
```

```yaml
# templates/rolebinding.yaml
{{- if .Values.rbac.create }}
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "myapp.fullname" . }}
  namespace: {{ .Release.Namespace }}
subjects:
- kind: ServiceAccount
  name: {{ include "myapp.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
roleRef:
  kind: Role
  name: {{ include "myapp.fullname" . }}
  apiGroup: rbac.authorization.k8s.io
{{- end }}
```

**Don't**: Use the default service account or grant cluster-wide permissions

```yaml
# Vulnerable: Using default SA (may have unexpected permissions)
serviceAccount:
  create: false
  name: "default"

# Vulnerable: ClusterRole when namespace-scoped Role suffices
kind: ClusterRole
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

**Why**: The default service account often accumulates permissions from multiple applications and cluster defaults. If a pod is compromised, the attacker inherits all permissions of the service account. Dedicated service accounts with namespace-scoped Roles and disabled auto-mount limit lateral movement to only what the specific application requires.

**Refs**: CWE-269, CWE-284, CIS Kubernetes Benchmark 5.1, NSA Kubernetes Hardening Guide

---

## Rule: Ingress TLS Enforcement

**Level**: `warning`

**When**: Creating Ingress templates in a chart

**Do**: Default to TLS with cert-manager annotation support and HTTPS-only enforcement

```yaml
# values.yaml
ingress:
  enabled: false
  className: nginx
  annotations:
    # Force HTTPS redirect
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    # Disable HTTP entirely
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    # cert-manager automatic certificate provisioning
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: myapp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: myapp-tls
      hosts:
        - myapp.example.com
```

```yaml
# templates/ingress.yaml
{{- if .Values.ingress.enabled -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "myapp.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "myapp.labels" . | nindent 4 }}
  {{- with .Values.ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- if .Values.ingress.className }}
  ingressClassName: {{ .Values.ingress.className }}
  {{- end }}
  {{- if .Values.ingress.tls }}
  tls:
    {{- range .Values.ingress.tls }}
    - hosts:
        {{- range .hosts }}
        - {{ . | quote }}
        {{- end }}
      secretName: {{ .secretName }}
    {{- end }}
  {{- end }}
  rules:
    {{- range .Values.ingress.hosts }}
    - host: {{ .host | quote }}
      http:
        paths:
          {{- range .paths }}
          - path: {{ .path }}
            pathType: {{ .pathType }}
            backend:
              service:
                name: {{ include "myapp.fullname" $ }}
                port:
                  number: {{ $.Values.service.port }}
          {{- end }}
    {{- end }}
{{- end }}
```

```yaml
# templates/_helpers.tpl — warn if TLS is disabled for a public ingress
{{- define "myapp.validateIngress" -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.tls) }}
WARNING: Ingress is enabled without TLS. Traffic will be transmitted unencrypted.
{{- end }}
{{- end }}
```

**Don't**: Expose services over HTTP or skip TLS configuration

```yaml
# Vulnerable: No TLS configured
ingress:
  enabled: true
  hosts:
    - host: myapp.example.com
      paths:
        - path: /
  # No tls: block — traffic is plaintext HTTP

# Vulnerable: SSL redirect disabled
annotations:
  nginx.ingress.kubernetes.io/ssl-redirect: "false"
```

**Why**: Plaintext HTTP exposes authentication tokens, session cookies, API keys, and user data to network interception. Kubernetes Ingress resources without TLS send all traffic unencrypted across the network, including between nodes in a cluster that may span multiple data centers or cloud availability zones. cert-manager automates certificate lifecycle management, eliminating expired certificate incidents.

**Refs**: CWE-319, CWE-523, OWASP A02:2021, CIS Kubernetes Benchmark 5.4.1

---

## Rule: Chart Linting and Schema Validation

**Level**: `warning`

**When**: Creating or publishing a Helm chart

**Do**: Define a `values.schema.json` and lint the chart in CI

```json
// values.schema.json — enforces type safety and required fields
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["image", "resources"],
  "properties": {
    "image": {
      "type": "object",
      "required": ["repository", "tag"],
      "properties": {
        "repository": { "type": "string", "minLength": 1 },
        "tag": {
          "type": "string",
          "not": { "const": "latest" },
          "description": "Must not be 'latest'. Use a semver tag."
        },
        "digest": { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
        "pullPolicy": {
          "type": "string",
          "enum": ["Always", "IfNotPresent", "Never"],
          "default": "Always"
        }
      }
    },
    "resources": {
      "type": "object",
      "required": ["limits"],
      "properties": {
        "limits": {
          "type": "object",
          "required": ["memory", "cpu"],
          "properties": {
            "memory": { "type": "string", "pattern": "^[0-9]+(Mi|Gi)$" },
            "cpu":    { "type": "string", "pattern": "^[0-9]+(m|)$" }
          }
        },
        "requests": {
          "type": "object",
          "properties": {
            "memory": { "type": "string" },
            "cpu":    { "type": "string" }
          }
        }
      }
    },
    "podSecurityContext": {
      "type": "object",
      "properties": {
        "runAsNonRoot": { "type": "boolean" },
        "runAsUser":    { "type": "integer", "minimum": 1 }
      }
    },
    "replicaCount": {
      "type": "integer",
      "minimum": 1
    }
  }
}
```

```yaml
# .github/workflows/helm-lint.yml — CI linting pipeline
name: Helm Lint and Test
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Set up Helm
      uses: azure/setup-helm@v4
      with:
        version: "v3.17.0"

    - name: Lint chart
      run: helm lint charts/myapp --strict --with-subcharts

    - name: Validate schema
      run: |
        helm template charts/myapp --set image.tag=v1.0.0 > /dev/null

    - name: Run kubeconform (Kubernetes manifest validation)
      run: |
        helm template charts/myapp --set image.tag=v1.0.0 | \
          kubeconform -strict -summary -kubernetes-version 1.32.0

    - name: Run checkov (security policy scan)
      uses: bridgecrewio/checkov-action@master
      with:
        directory: charts/myapp
        framework: helm
        soft_fail: false

    - name: Run Trivy misconfiguration scan
      run: |
        trivy config charts/myapp --exit-code 1 --severity HIGH,CRITICAL
```

```bash
# Local development checks
helm lint ./myapp --strict
helm template ./myapp --set image.tag=v1.0.0 | kubectl apply --dry-run=client -f -
helm template ./myapp --set image.tag=v1.0.0 | trivy config -
helm template ./myapp --set image.tag=v1.0.0 | kubeconform -strict -
```

**Don't**: Ship charts without schema validation or linting

```yaml
# Vulnerable: No values.schema.json
# Users can set image.tag=latest or omit resource limits
# with no validation error

# Vulnerable: No CI linting
# Misconfigured templates reach production clusters unchecked
```

**Why**: Helm's `values.schema.json` enforces contract between chart and user — preventing insecure inputs like `latest` tags, missing resource limits, or wrong types that cause runtime failures. `helm lint --strict` catches template errors and deprecated API versions. `kubeconform` validates rendered manifests against the actual Kubernetes OpenAPI schema. Automated scanning in CI prevents security regressions from reaching production.

**Refs**: Helm documentation — Chart Best Practices, CIS Kubernetes Benchmark, NIST 800-190

---

## Rule: Sensitive Values Redaction and NOTES.txt

**Level**: `advisory`

**When**: Creating the `templates/NOTES.txt` file

**Do**: Show post-install guidance without exposing secrets; use `helm show values` safely

```text
# templates/NOTES.txt
{{- $fullName := include "myapp.fullname" . -}}

Thank you for installing {{ .Chart.Name }} {{ .Chart.Version }}.

Application URL:
{{- if .Values.ingress.enabled }}
  https://{{ (first .Values.ingress.hosts).host }}
{{- else if contains "NodePort" .Values.service.type }}
  export NODE_PORT=$(kubectl get --namespace {{ .Release.Namespace }} -o jsonpath="{.spec.ports[0].nodePort}" services {{ $fullName }})
  export NODE_IP=$(kubectl get nodes --namespace {{ .Release.Namespace }} -o jsonpath="{.items[0].status.addresses[0].address}")
  echo "http://$NODE_IP:$NODE_PORT"
{{- else }}
  kubectl --namespace {{ .Release.Namespace }} port-forward svc/{{ $fullName }} 8080:{{ .Values.service.port }}
  echo "http://127.0.0.1:8080"
{{- end }}

Security Notes:
- Ensure the Secret '{{ .Values.database.existingSecret }}' exists in namespace '{{ .Release.Namespace }}' before use.
- Review network policies: networkPolicy.enabled={{ .Values.networkPolicy.enabled }}
- Pod runs as non-root: {{ .Values.podSecurityContext.runAsNonRoot }}

{{- if not .Values.networkPolicy.enabled }}
WARNING: NetworkPolicy is disabled. Enable it for production deployments.
{{- end }}
{{- if not .Values.ingress.tls }}
WARNING: TLS is not configured on the Ingress. Enable TLS before production use.
{{- end }}
```

**Don't**: Print secrets or sensitive values in NOTES.txt

```text
# Vulnerable: Leaking secret values in NOTES.txt
Your database password is: {{ .Values.database.password }}
Your API key: {{ .Values.apiKey }}
# Visible to anyone who ran helm install, stored in terminal history
```

**Why**: `helm install` output and `helm get notes` are logged, stored in terminal history, and may be captured by CI/CD systems. Printing secrets here exposes them to anyone with access to those logs. NOTES.txt should guide operators to retrieve credentials securely (e.g., `kubectl get secret`) rather than displaying them directly.

**Refs**: CWE-200, CWE-312, OWASP A02:2021

---

## Rule: Dependency Management and Chart Provenance

**Level**: `warning`

**When**: Declaring chart dependencies in `Chart.yaml`

**Do**: Pin dependency versions, use `helm dependency update` with lock files, and verify chart provenance

```yaml
# Chart.yaml — pinned dependency versions
apiVersion: v2
name: myapp
description: A Helm chart for myapp
type: application
version: 1.2.3
appVersion: "v1.2.3"

dependencies:
  - name: postgresql
    version: "16.4.5"          # Exact version, not a range
    repository: "oci://registry-1.docker.io/bitnamicharts"
    condition: postgresql.enabled

  - name: redis
    version: "20.6.2"
    repository: "oci://registry-1.docker.io/bitnamicharts"
    condition: redis.enabled
```

```bash
# Lock and verify dependencies
helm dependency update ./myapp
# Generates Chart.lock — commit this file

# Verify chart provenance with Cosign (if chart registry supports OCI signing)
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  registry-1.docker.io/bitnamicharts/postgresql:16.4.5

# Scan packaged chart for vulnerabilities
helm package ./myapp -d /tmp/charts
trivy config /tmp/charts/myapp-1.2.3.tgz --exit-code 1 --severity HIGH,CRITICAL

# Use OCI registries for charts (preferred over HTTP repos — integrity built in)
helm pull oci://myregistry.io/charts/myapp --version 1.2.3 --verify
```

```yaml
# Chart.lock — commit alongside Chart.yaml
dependencies:
- name: postgresql
  repository: oci://registry-1.docker.io/bitnamicharts
  version: 16.4.5
digest: sha256:abc123def456789abc123def456789abc123def456789abc123def456789abcd
generated: "2026-05-01T00:00:00.000000000Z"
```

**Don't**: Use unpinned or unverified chart dependencies

```yaml
# Vulnerable: Version ranges allow silent upgrades
dependencies:
  - name: postgresql
    version: ">=15.0.0"       # Could install any version including breaking changes
    repository: https://charts.bitnami.com/bitnami

# Vulnerable: HTTP chart repos with no integrity check
dependencies:
  - name: some-chart
    repository: http://charts.example.com  # HTTP, no TLS
    version: "*"
```

**Why**: Chart dependencies are supply chain attack vectors. A compromised chart repository can serve malicious chart versions. Version ranges allow silent upgrades to charts containing vulnerabilities or breaking security configurations. Exact version pinning with `Chart.lock` provides reproducible installs. OCI registries for charts offer content-addressable storage with digest verification — HTTP repositories offer no integrity guarantees.

**Refs**: CWE-1104, OWASP A06:2021, SLSA Supply Chain Levels, NIST SP 800-161

---

## Additional Security Configurations

### Recommended Chart Directory Structure

```text
myapp/
├── Chart.yaml               # Chart metadata with exact dependency versions
├── Chart.lock               # Locked dependency digests (commit to version control)
├── values.yaml              # Secure defaults — no secrets, restricted security context
├── values.schema.json       # JSON schema validation for all values
├── .helmignore              # Exclude secrets, .env files, CI config from packages
├── templates/
│   ├── _helpers.tpl         # Named templates and input validation
│   ├── NOTES.txt            # Post-install guidance (no secret values)
│   ├── deployment.yaml      # SecurityContext, resource limits, probes
│   ├── service.yaml
│   ├── ingress.yaml         # TLS enforced by default
│   ├── serviceaccount.yaml  # Dedicated SA, automountServiceAccountToken: false
│   ├── role.yaml            # Namespace-scoped, minimal permissions
│   ├── rolebinding.yaml
│   ├── networkpolicy.yaml   # Default-deny with explicit allow rules
│   ├── externalsecret.yaml  # ESO ExternalSecret (optional)
│   └── hpa.yaml             # Horizontal pod autoscaler (optional)
└── charts/                  # Unpacked sub-chart dependencies
```

### Secure .helmignore

```gitignore
# .helmignore

# Secrets and credentials — must never be packaged into chart archives
.env
.env.*
*.pem
*.key
*-secret.yaml
*-credentials.yaml
secrets/

# Version control
.git
.gitignore

# CI/CD files
.github/
.gitlab-ci.yml
Jenkinsfile

# Development files
*.swp
*.swo
.DS_Store

# Test files (not needed in published chart)
tests/
*_test.yaml

# Documentation (reduce chart package size)
# Uncomment if docs are not needed in the package:
# docs/
# *.md
```

### Helm Release Hardening

```bash
# Verify no secrets in rendered output before install
helm template ./myapp --set image.tag=v1.0.0 | \
  grep -iE "(password|secret|token|key|credential)" && \
  echo "WARNING: Potential secret found in rendered templates" || \
  echo "No secrets detected in rendered output"

# Diff before upgrade (requires helm-diff plugin)
helm diff upgrade myapp ./myapp --values values-production.yaml

# Verify release state is encrypted at rest
# Helm v3 stores release state as Kubernetes Secrets (base64, not encrypted)
# Enable KMS encryption for Secrets in API server:
# --encryption-provider-config=/etc/kubernetes/enc/enc.yaml

# Audit installed chart versions
helm list --all-namespaces --output json | \
  jq '.[] | {name, namespace, chart, app_version, status}'
```

**Refs**: Helm Security Best Practices, CIS Kubernetes Benchmark, NIST 800-190 Section 4, OWASP A06:2021
