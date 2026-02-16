package container

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// GTSS-CTR-001: Docker running as root
var (
	reDockerFROM      = regexp.MustCompile(`(?i)^FROM\s+`)
	reDockerUSER      = regexp.MustCompile(`(?i)^USER\s+\S+`)
	reDockerUserRoot  = regexp.MustCompile(`(?i)^USER\s+root\b`)
)

// GTSS-CTR-002: Docker COPY/ADD with wildcard
var (
	reDockerCopyWild  = regexp.MustCompile(`(?i)^(?:COPY|ADD)\s+(?:\.\s|\.\/\s|\*\s|\.\.\s)`)
	reDockerCopyDot   = regexp.MustCompile(`(?i)^(?:COPY|ADD)\s+\.\s+`)
	reDockerCopyGlob  = regexp.MustCompile(`(?i)^(?:COPY|ADD)\s+\*`)
)

// GTSS-CTR-003: Docker latest tag
var (
	reDockerFromLatest = regexp.MustCompile(`(?i)^FROM\s+\S+:latest\b`)
	reDockerFromNoTag  = regexp.MustCompile(`(?i)^FROM\s+([a-z0-9._/-]+)\s*$`)
	reDockerFromDigest = regexp.MustCompile(`(?i)^FROM\s+\S+@sha256:`)
)

// GTSS-CTR-004: Docker SSH port
var (
	reDockerExposeSSH  = regexp.MustCompile(`(?i)^EXPOSE\s+.*\b22\b`)
)

// GTSS-CTR-005: Docker privileged mode
var (
	reDockerPrivileged = regexp.MustCompile(`(?i)--privileged`)
	reDockerCapAdd     = regexp.MustCompile(`(?i)--cap-add\s*=?\s*(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN)`)
)

// GTSS-CTR-006: Docker secrets in ENV/ARG
var (
	reDockerEnvSecret = regexp.MustCompile(`(?i)^(?:ENV|ARG)\s+\S*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY|PRIVATE_KEY|AWS_SECRET|DB_PASS)\s*=\s*\S+`)
	reDockerEnvSecVar = regexp.MustCompile(`(?i)^(?:ENV|ARG)\s+\S*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY|PRIVATE_KEY|AWS_SECRET|DB_PASS)\b`)
)

// GTSS-CTR-007: Kubernetes privileged container
var (
	reK8sPrivileged     = regexp.MustCompile(`(?i)privileged\s*:\s*true`)
	reK8sAllowPrivEsc   = regexp.MustCompile(`(?i)allowPrivilegeEscalation\s*:\s*true`)
)

// GTSS-CTR-008: Kubernetes hostNetwork/hostPID
var (
	reK8sHostNetwork    = regexp.MustCompile(`(?i)hostNetwork\s*:\s*true`)
	reK8sHostPID        = regexp.MustCompile(`(?i)hostPID\s*:\s*true`)
	reK8sHostIPC        = regexp.MustCompile(`(?i)hostIPC\s*:\s*true`)
)

// GTSS-CTR-009: Kubernetes no resource limits
var (
	reK8sContainer      = regexp.MustCompile(`(?i)containers\s*:`)
	reK8sResources      = regexp.MustCompile(`(?i)resources\s*:`)
	reK8sLimits         = regexp.MustCompile(`(?i)limits\s*:`)
)

// GTSS-CTR-010: Terraform security group 0.0.0.0/0
var (
	reTFSecGroup       = regexp.MustCompile(`(?i)(?:resource\s+["']aws_security_group|ingress\s*\{)`)
	reTFCIDRAll        = regexp.MustCompile(`(?i)(?:cidr_blocks|cidr_ipv6)\s*=\s*\[\s*["'](?:0\.0\.0\.0/0|::/0)["']`)
	reTFIngressAll     = regexp.MustCompile(`(?i)(?:from_port|to_port)\s*=\s*0`)
)

// ---------------------------------------------------------------------------
// Helpers (package-scoped)
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&DockerRunAsRoot{})
	rules.Register(&DockerCopyWildcard{})
	rules.Register(&DockerLatestTag{})
	rules.Register(&DockerExposeSSH{})
	rules.Register(&DockerPrivileged{})
	rules.Register(&DockerSecretsInEnv{})
	rules.Register(&K8sPrivilegedContainer{})
	rules.Register(&K8sHostNamespace{})
	rules.Register(&K8sNoResourceLimits{})
	rules.Register(&TerraformOpenIngress{})
}

// ---------------------------------------------------------------------------
// GTSS-CTR-001: Dockerfile running as root
// ---------------------------------------------------------------------------

type DockerRunAsRoot struct{}

func (r *DockerRunAsRoot) ID() string                     { return "GTSS-CTR-001" }
func (r *DockerRunAsRoot) Name() string                   { return "DockerRunAsRoot" }
func (r *DockerRunAsRoot) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DockerRunAsRoot) Description() string {
	return "Detects Dockerfiles that do not include a USER instruction, meaning the container will run as root, violating the principle of least privilege."
}
func (r *DockerRunAsRoot) Languages() []rules.Language {
	return []rules.Language{rules.LangDocker}
}

func (r *DockerRunAsRoot) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangDocker {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")

	hasFROM := false
	hasUSER := false
	userIsRoot := false
	lastFromLine := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if reDockerFROM.MatchString(trimmed) {
			hasFROM = true
			lastFromLine = i + 1
			// Reset USER for multi-stage builds
			hasUSER = false
			userIsRoot = false
		}
		if reDockerUSER.MatchString(trimmed) {
			hasUSER = true
			if reDockerUserRoot.MatchString(trimmed) {
				userIsRoot = true
			} else {
				userIsRoot = false
			}
		}
	}

	if !hasFROM {
		return nil
	}

	if !hasUSER || userIsRoot {
		title := "Dockerfile has no USER instruction (runs as root)"
		if userIsRoot {
			title = "Dockerfile explicitly sets USER root"
		}
		return []rules.Finding{{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   "The container will run as root, which gives a container escape vulnerability maximum impact. An attacker who exploits the application gains root access to the host.",
			FilePath:      ctx.FilePath,
			LineNumber:    lastFromLine,
			MatchedText:   truncate(strings.TrimSpace(lines[lastFromLine-1]), 120),
			Suggestion:    "Add a USER instruction to run as a non-root user: RUN adduser -D appuser && USER appuser. Use the final stage's USER instruction for multi-stage builds.",
			CWEID:         "CWE-250",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"container", "docker", "least-privilege"},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GTSS-CTR-002: Docker COPY/ADD with wildcard
// ---------------------------------------------------------------------------

type DockerCopyWildcard struct{}

func (r *DockerCopyWildcard) ID() string                     { return "GTSS-CTR-002" }
func (r *DockerCopyWildcard) Name() string                   { return "DockerCopyWildcard" }
func (r *DockerCopyWildcard) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DockerCopyWildcard) Description() string {
	return "Detects Dockerfile COPY/ADD with wildcard or entire directory copy (COPY . or COPY *), which may accidentally include secrets, .env files, .git directories, or private keys."
}
func (r *DockerCopyWildcard) Languages() []rules.Language {
	return []rules.Language{rules.LangDocker}
}

func (r *DockerCopyWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangDocker {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reDockerCopyDot.MatchString(trimmed) || reDockerCopyGlob.MatchString(trimmed) || reDockerCopyWild.MatchString(trimmed) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Docker COPY/ADD with wildcard or entire directory",
				Description:   "COPY . or COPY * copies the entire build context including .env files, .git directory, private keys, and other secrets. Use a .dockerignore file and copy only needed files.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Copy only needed files explicitly (e.g., COPY package.json ./). Create a .dockerignore to exclude .env, .git, *.pem, and other sensitive files.",
				CWEID:         "CWE-200",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"container", "docker", "secrets-leak"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CTR-003: Docker using latest tag
// ---------------------------------------------------------------------------

type DockerLatestTag struct{}

func (r *DockerLatestTag) ID() string                     { return "GTSS-CTR-003" }
func (r *DockerLatestTag) Name() string                   { return "DockerLatestTag" }
func (r *DockerLatestTag) DefaultSeverity() rules.Severity { return rules.Low }
func (r *DockerLatestTag) Description() string {
	return "Detects Dockerfile FROM instructions using the :latest tag or no tag at all, making builds non-deterministic and potentially pulling vulnerable images."
}
func (r *DockerLatestTag) Languages() []rules.Language {
	return []rules.Language{rules.LangDocker}
}

func (r *DockerLatestTag) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangDocker {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var matched bool
		var title string
		if reDockerFromLatest.MatchString(trimmed) {
			matched = true
			title = "Docker FROM uses :latest tag (non-deterministic)"
		} else if reDockerFromNoTag.MatchString(trimmed) && !reDockerFromDigest.MatchString(trimmed) {
			// No tag at all implies :latest
			if !strings.Contains(trimmed, "AS ") && !strings.Contains(trimmed, " as ") && !strings.Contains(trimmed, "scratch") {
				matched = true
				title = "Docker FROM has no tag (defaults to :latest)"
			}
		}
		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Using :latest or no tag makes builds non-deterministic. The base image can change between builds, potentially introducing vulnerabilities or breaking changes without notice.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Pin the base image to a specific version tag or SHA256 digest. For example: FROM node:20.11-alpine or FROM node@sha256:abc123...",
				CWEID:         "CWE-829",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"container", "docker", "supply-chain"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CTR-004: Docker exposing SSH port
// ---------------------------------------------------------------------------

type DockerExposeSSH struct{}

func (r *DockerExposeSSH) ID() string                     { return "GTSS-CTR-004" }
func (r *DockerExposeSSH) Name() string                   { return "DockerExposeSSH" }
func (r *DockerExposeSSH) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DockerExposeSSH) Description() string {
	return "Detects Dockerfiles that expose SSH port 22, which is an anti-pattern for containers. Containers should be managed via orchestration, not SSH."
}
func (r *DockerExposeSSH) Languages() []rules.Language {
	return []rules.Language{rules.LangDocker}
}

func (r *DockerExposeSSH) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangDocker {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reDockerExposeSSH.MatchString(trimmed) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Docker container exposes SSH port 22",
				Description:   "Running SSH inside containers is an anti-pattern. It increases attack surface, makes containers stateful, and bypasses container orchestration. Use docker exec or kubectl exec for debugging.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Remove EXPOSE 22 and the SSH server. Use 'docker exec' or 'kubectl exec' for debugging. Use container orchestration for management.",
				CWEID:         "CWE-284",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"container", "docker", "ssh"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CTR-005: Docker privileged mode
// ---------------------------------------------------------------------------

type DockerPrivileged struct{}

func (r *DockerPrivileged) ID() string                     { return "GTSS-CTR-005" }
func (r *DockerPrivileged) Name() string                   { return "DockerPrivileged" }
func (r *DockerPrivileged) DefaultSeverity() rules.Severity { return rules.High }
func (r *DockerPrivileged) Description() string {
	return "Detects Docker --privileged flag or dangerous --cap-add options (ALL, SYS_ADMIN) in Docker run commands, compose files, or scripts."
}
func (r *DockerPrivileged) Languages() []rules.Language {
	return []rules.Language{rules.LangDocker, rules.LangYAML, rules.LangShell, rules.LangAny}
}

func (r *DockerPrivileged) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var m string
		var title string
		if loc := reDockerPrivileged.FindString(line); loc != "" {
			m = loc
			title = "Docker --privileged mode (full host access)"
		} else if loc := reDockerCapAdd.FindString(line); loc != "" {
			m = loc
			title = "Docker dangerous capability added"
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Privileged containers have full access to the host, including all devices and kernel capabilities. An attacker who compromises the container effectively controls the host.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Remove --privileged. Add only the specific capabilities needed with --cap-add. Use --security-opt and seccomp profiles for fine-grained control.",
				CWEID:         "CWE-250",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"container", "docker", "privileged"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CTR-006: Docker secrets in ENV/ARG
// ---------------------------------------------------------------------------

type DockerSecretsInEnv struct{}

func (r *DockerSecretsInEnv) ID() string                     { return "GTSS-CTR-006" }
func (r *DockerSecretsInEnv) Name() string                   { return "DockerSecretsInEnv" }
func (r *DockerSecretsInEnv) DefaultSeverity() rules.Severity { return rules.High }
func (r *DockerSecretsInEnv) Description() string {
	return "Detects secrets (passwords, tokens, API keys) hardcoded in Dockerfile ENV or ARG instructions. These values are visible in the image metadata and layers."
}
func (r *DockerSecretsInEnv) Languages() []rules.Language {
	return []rules.Language{rules.LangDocker}
}

func (r *DockerSecretsInEnv) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangDocker {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reDockerEnvSecret.FindString(trimmed); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Secret hardcoded in Dockerfile ENV/ARG",
				Description:   "Secrets in ENV or ARG instructions are baked into the Docker image and visible via 'docker inspect' and 'docker history'. They persist in all image layers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use Docker secrets, mount secrets at runtime via --env-file or -e flags, or use BuildKit --mount=type=secret for build-time secrets.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"container", "docker", "secrets", "hardcoded"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CTR-007: Kubernetes privileged container
// ---------------------------------------------------------------------------

type K8sPrivilegedContainer struct{}

func (r *K8sPrivilegedContainer) ID() string                     { return "GTSS-CTR-007" }
func (r *K8sPrivilegedContainer) Name() string                   { return "K8sPrivilegedContainer" }
func (r *K8sPrivilegedContainer) DefaultSeverity() rules.Severity { return rules.High }
func (r *K8sPrivilegedContainer) Description() string {
	return "Detects Kubernetes pod specs with privileged: true or allowPrivilegeEscalation: true in security contexts, granting the container full host access."
}
func (r *K8sPrivilegedContainer) Languages() []rules.Language {
	return []rules.Language{rules.LangYAML, rules.LangAny}
}

func (r *K8sPrivilegedContainer) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Only flag in YAML files that look like K8s manifests
	if !strings.Contains(ctx.Content, "apiVersion") && !strings.Contains(ctx.Content, "kind:") {
		return nil
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var m string
		var title string
		if loc := reK8sPrivileged.FindString(line); loc != "" {
			m = loc
			title = "Kubernetes privileged container (privileged: true)"
		} else if loc := reK8sAllowPrivEsc.FindString(line); loc != "" {
			m = loc
			title = "Kubernetes allowPrivilegeEscalation: true"
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Privileged containers have unrestricted host access, including all devices and kernel capabilities. This is the most dangerous Kubernetes security misconfiguration.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Set privileged: false and allowPrivilegeEscalation: false in the securityContext. Add only required capabilities with capabilities.add.",
				CWEID:         "CWE-250",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"container", "kubernetes", "privileged"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CTR-008: Kubernetes hostNetwork/hostPID enabled
// ---------------------------------------------------------------------------

type K8sHostNamespace struct{}

func (r *K8sHostNamespace) ID() string                     { return "GTSS-CTR-008" }
func (r *K8sHostNamespace) Name() string                   { return "K8sHostNamespace" }
func (r *K8sHostNamespace) DefaultSeverity() rules.Severity { return rules.High }
func (r *K8sHostNamespace) Description() string {
	return "Detects Kubernetes pod specs with hostNetwork, hostPID, or hostIPC enabled, which shares the host's network/PID/IPC namespace with the container."
}
func (r *K8sHostNamespace) Languages() []rules.Language {
	return []rules.Language{rules.LangYAML, rules.LangAny}
}

func (r *K8sHostNamespace) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	if !strings.Contains(ctx.Content, "apiVersion") && !strings.Contains(ctx.Content, "kind:") {
		return nil
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var m string
		var title string
		if loc := reK8sHostNetwork.FindString(line); loc != "" {
			m = loc
			title = "Kubernetes hostNetwork: true (shares host network)"
		} else if loc := reK8sHostPID.FindString(line); loc != "" {
			m = loc
			title = "Kubernetes hostPID: true (shares host PID namespace)"
		} else if loc := reK8sHostIPC.FindString(line); loc != "" {
			m = loc
			title = "Kubernetes hostIPC: true (shares host IPC namespace)"
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Sharing the host namespace breaks container isolation. hostNetwork exposes all host ports, hostPID allows seeing and signaling host processes, and hostIPC allows accessing host shared memory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Set hostNetwork: false, hostPID: false, and hostIPC: false. Use Kubernetes NetworkPolicies for network isolation instead.",
				CWEID:         "CWE-250",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"container", "kubernetes", "host-namespace"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CTR-009: Kubernetes no resource limits
// ---------------------------------------------------------------------------

type K8sNoResourceLimits struct{}

func (r *K8sNoResourceLimits) ID() string                     { return "GTSS-CTR-009" }
func (r *K8sNoResourceLimits) Name() string                   { return "K8sNoResourceLimits" }
func (r *K8sNoResourceLimits) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *K8sNoResourceLimits) Description() string {
	return "Detects Kubernetes container specs without resource limits, which can lead to resource exhaustion (CPU/memory) affecting other pods on the same node."
}
func (r *K8sNoResourceLimits) Languages() []rules.Language {
	return []rules.Language{rules.LangYAML, rules.LangAny}
}

func (r *K8sNoResourceLimits) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "apiVersion") && !strings.Contains(ctx.Content, "kind:") {
		return nil
	}

	hasContainers := reK8sContainer.MatchString(ctx.Content)
	hasResources := reK8sResources.MatchString(ctx.Content)
	hasLimits := reK8sLimits.MatchString(ctx.Content)

	if !hasContainers {
		return nil
	}

	if hasResources && hasLimits {
		return nil
	}

	// Find the containers: line to anchor the finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if reK8sContainer.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Kubernetes container without resource limits",
				Description:   "Containers without CPU/memory limits can consume unbounded resources, starving other pods on the same node. This can be exploited for denial-of-service attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Add resources.limits.cpu and resources.limits.memory to every container spec. Example: limits: { cpu: '500m', memory: '512Mi' }.",
				CWEID:         "CWE-770",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"container", "kubernetes", "resource-limits"},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GTSS-CTR-010: Terraform security group with 0.0.0.0/0 ingress
// ---------------------------------------------------------------------------

type TerraformOpenIngress struct{}

func (r *TerraformOpenIngress) ID() string                     { return "GTSS-CTR-010" }
func (r *TerraformOpenIngress) Name() string                   { return "TerraformOpenIngress" }
func (r *TerraformOpenIngress) DefaultSeverity() rules.Severity { return rules.High }
func (r *TerraformOpenIngress) Description() string {
	return "Detects Terraform AWS security group rules with 0.0.0.0/0 or ::/0 ingress CIDR, allowing unrestricted inbound traffic from the entire internet."
}
func (r *TerraformOpenIngress) Languages() []rules.Language {
	return []rules.Language{rules.LangTerraform}
}

func (r *TerraformOpenIngress) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangTerraform {
		return nil
	}

	// Only flag in files that contain security group resources
	if !reTFSecGroup.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reTFCIDRAll.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Terraform security group allows 0.0.0.0/0 ingress",
				Description:   "The security group ingress rule allows traffic from all IP addresses (0.0.0.0/0 or ::/0). This exposes the resource to the entire internet, increasing the attack surface significantly.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Restrict cidr_blocks to specific IP ranges that need access. Use VPN or bastion hosts for administrative access. Never open 0.0.0.0/0 for SSH (22) or RDP (3389) ports.",
				CWEID:         "CWE-284",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"container", "terraform", "security-group", "open-ingress"},
			})
		}
	}
	return findings
}
