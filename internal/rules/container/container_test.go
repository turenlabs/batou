package container

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-CTR-001: Dockerfile running as root ---

func TestCTR001_NoUser(t *testing.T) {
	content := `FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-001")
}

func TestCTR001_UserRoot(t *testing.T) {
	content := `FROM python:3.12
USER root
COPY . .
CMD ["python", "app.py"]
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-001")
}

func TestCTR001_Safe_NonRootUser(t *testing.T) {
	content := `FROM node:20-alpine
RUN adduser -D appuser
USER appuser
COPY . .
CMD ["node", "server.js"]
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-001")
}

// --- BATOU-CTR-002: Docker COPY/ADD with wildcard ---

func TestCTR002_CopyDot(t *testing.T) {
	content := `FROM node:20-alpine
COPY . /app/
USER appuser
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-002")
}

func TestCTR002_CopyGlob(t *testing.T) {
	content := `FROM python:3.12
COPY * /app/
USER appuser
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-002")
}

func TestCTR002_Safe_SpecificCopy(t *testing.T) {
	content := `FROM node:20-alpine
COPY package.json package-lock.json ./
RUN npm install
COPY src/ ./src/
USER appuser
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-002")
}

// --- BATOU-CTR-003: Docker latest tag ---

func TestCTR003_LatestTag(t *testing.T) {
	content := `FROM node:latest
USER appuser
CMD ["node", "server.js"]
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-003")
}

func TestCTR003_NoTag(t *testing.T) {
	content := `FROM python
USER appuser
CMD ["python", "app.py"]
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-003")
}

func TestCTR003_Safe_PinnedVersion(t *testing.T) {
	content := `FROM node:20.11-alpine
USER appuser
CMD ["node", "server.js"]
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-003")
}

// --- BATOU-CTR-004: Docker SSH port ---

func TestCTR004_ExposeSSH(t *testing.T) {
	content := `FROM ubuntu:22.04
EXPOSE 22
USER appuser
CMD ["/usr/sbin/sshd"]
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-004")
}

func TestCTR004_Safe_ExposeHTTP(t *testing.T) {
	content := `FROM node:20-alpine
EXPOSE 3000
USER appuser
CMD ["node", "server.js"]
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-004")
}

// --- BATOU-CTR-005: Docker privileged mode ---

func TestCTR005_Privileged(t *testing.T) {
	content := `docker run --privileged myimage`
	result := testutil.ScanContent(t, "/app/deploy.sh", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-005")
}

func TestCTR005_CapAddAll(t *testing.T) {
	content := `docker run --cap-add=ALL myimage`
	result := testutil.ScanContent(t, "/app/deploy.sh", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-005")
}

func TestCTR005_CapAddSysAdmin(t *testing.T) {
	content := `docker run --cap-add=SYS_ADMIN myimage`
	result := testutil.ScanContent(t, "/app/deploy.sh", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-005")
}

func TestCTR005_Safe_NoCaps(t *testing.T) {
	content := `docker run --read-only myimage`
	result := testutil.ScanContent(t, "/app/deploy.sh", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-005")
}

// --- BATOU-CTR-006: Docker secrets in ENV/ARG ---

func TestCTR006_EnvPassword(t *testing.T) {
	content := `FROM node:20-alpine
ENV DB_PASSWORD=supersecret123
USER appuser
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-006")
}

func TestCTR006_ArgSecret(t *testing.T) {
	content := `FROM python:3.12
ARG API_KEY=sk-abc123def456
USER appuser
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-006")
}

func TestCTR006_Safe_NoValue(t *testing.T) {
	content := `FROM node:20-alpine
ARG DB_PASSWORD
USER appuser
`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-006")
}

// --- BATOU-CTR-007: Kubernetes privileged container ---

func TestCTR007_K8sPrivileged(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
`
	result := testutil.ScanContent(t, "/app/pod.yaml", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-007")
}

func TestCTR007_K8sAllowPrivEsc(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: true
`
	result := testutil.ScanContent(t, "/app/pod.yaml", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-007")
}

func TestCTR007_Safe_K8sNotPrivileged(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false
`
	result := testutil.ScanContent(t, "/app/pod.yaml", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-007")
}

// --- BATOU-CTR-008: Kubernetes hostNetwork/hostPID ---

func TestCTR008_HostNetwork(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: app
`
	result := testutil.ScanContent(t, "/app/pod.yaml", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-008")
}

func TestCTR008_HostPID(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
  - name: app
`
	result := testutil.ScanContent(t, "/app/pod.yaml", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-008")
}

func TestCTR008_Safe_NoHostNamespace(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  hostNetwork: false
  containers:
  - name: app
`
	result := testutil.ScanContent(t, "/app/pod.yaml", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-008")
}

// --- BATOU-CTR-009: Kubernetes no resource limits ---

func TestCTR009_NoLimits(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx:1.25
`
	result := testutil.ScanContent(t, "/app/pod.yaml", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-009")
}

func TestCTR009_Safe_WithLimits(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx:1.25
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
`
	result := testutil.ScanContent(t, "/app/pod.yaml", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-009")
}

// --- BATOU-CTR-010: Terraform open ingress ---

func TestCTR010_TF_OpenCIDR(t *testing.T) {
	content := `resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	result := testutil.ScanContent(t, "/infra/main.tf", content)
	testutil.MustFindRule(t, result, "BATOU-CTR-010")
}

func TestCTR010_Safe_RestrictedCIDR(t *testing.T) {
	content := `resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
`
	result := testutil.ScanContent(t, "/infra/main.tf", content)
	testutil.MustNotFindRule(t, result, "BATOU-CTR-010")
}
