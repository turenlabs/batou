package secrets

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended secret detection
// ---------------------------------------------------------------------------

var (
	// BATOU-SEC-007: Google API key (AIza...)
	reExtGoogleAPIKey = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(AIza[0-9A-Za-z\-_]{35})(?:[^A-Za-z0-9]|$)`)

	// BATOU-SEC-008: Slack webhook URL
	reExtSlackWebhook = regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}`)

	// BATOU-SEC-009: Twilio API key or Account SID
	reExtTwilioSID = regexp.MustCompile(`(?:^|[^A-Za-z0-9])((?:AC|SK)[0-9a-fA-F]{32})(?:[^A-Za-z0-9]|$)`)
	reExtTwilioAuth = regexp.MustCompile(`(?i)twilio.*(?:auth_token|authtoken|api_?secret)\s*[:=]\s*["']([A-Za-z0-9]{32})["']`)

	// BATOU-SEC-010: SendGrid API key (SG...)
	reExtSendGridKey = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?:[^A-Za-z0-9]|$)`)

	// BATOU-SEC-011: Mailgun API key
	reExtMailgunKey = regexp.MustCompile(`(?i)(?:mailgun|mg).*(?:api[_-]?key|secret)\s*[:=]\s*["']?(key-[A-Za-z0-9]{32})["']?`)

	// BATOU-SEC-012: Database connection string with embedded password
	reExtDBConnString = regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|mariadb)://[^\s:]+:[^\s@]{3,}@[^\s]+`)

	// BATOU-SEC-013: Private key in source (BEGIN PRIVATE KEY block)
	reExtPrivateKeyBlock = regexp.MustCompile(`-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH |ED25519 |ENCRYPTED )?PRIVATE KEY-----`)

	// BATOU-SEC-014: Azure storage account key
	reExtAzureStorageKey = regexp.MustCompile(`(?i)(?:AccountKey|azure[_-]?storage[_-]?key|AZURE_STORAGE_KEY)\s*[=:]\s*["']?([A-Za-z0-9+/]{86}==)["']?`)

	// BATOU-SEC-015: GCP service account JSON key
	reExtGCPServiceAccount = regexp.MustCompile(`"type"\s*:\s*"service_account"`)
	reExtGCPPrivateKeyID   = regexp.MustCompile(`"private_key_id"\s*:\s*"[A-Fa-f0-9]{40}"`)

	// BATOU-SEC-016: Generic high-entropy string in secret variable
	reExtSecretAssignment = regexp.MustCompile(`(?i)(?:secret|private[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key|api[_-]?token|auth[_-]?secret)\s*[:=]=?\s*["']([A-Za-z0-9+/=_\-]{16,})["']`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&GoogleAPIKeyRule{})
	rules.Register(&SlackWebhookRule{})
	rules.Register(&TwilioKeyRule{})
	rules.Register(&SendGridKeyRule{})
	rules.Register(&MailgunKeyRule{})
	rules.Register(&DBConnStringExtRule{})
	rules.Register(&PrivateKeyBlockRule{})
	rules.Register(&AzureStorageKeyRule{})
	rules.Register(&GCPServiceAccountRule{})
	rules.Register(&HighEntropySecretRule{})
}

// ========================================================================
// BATOU-SEC-007: Google API Key Pattern
// ========================================================================

type GoogleAPIKeyRule struct{}

func (r *GoogleAPIKeyRule) ID() string                     { return "BATOU-SEC-007" }
func (r *GoogleAPIKeyRule) Name() string                   { return "GoogleAPIKey" }
func (r *GoogleAPIKeyRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *GoogleAPIKeyRule) Description() string {
	return "Detects Google API keys (AIza...) hardcoded in source code."
}
func (r *GoogleAPIKeyRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *GoogleAPIKeyRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		m := reExtGoogleAPIKey.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		keyVal := m[1]
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Google API key exposed in source code",
			Description:   "A Google API key (" + redactValue(keyVal) + ") was found hardcoded. Google API keys can be used to consume quota, access restricted APIs, or incur charges on your account.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Rotate this API key immediately. Restrict it by IP, referrer, or API in the Google Cloud Console. Store it in environment variables or a secrets manager.",
			CWEID:         "CWE-798",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"secrets", "api-key", "google"},
		})
	}
	return findings
}

// ========================================================================
// BATOU-SEC-008: Slack Webhook URL
// ========================================================================

type SlackWebhookRule struct{}

func (r *SlackWebhookRule) ID() string                     { return "BATOU-SEC-008" }
func (r *SlackWebhookRule) Name() string                   { return "SlackWebhookURL" }
func (r *SlackWebhookRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *SlackWebhookRule) Description() string {
	return "Detects Slack webhook URLs hardcoded in source code."
}
func (r *SlackWebhookRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *SlackWebhookRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtSlackWebhook.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Slack webhook URL exposed in source code",
				Description:   "A Slack incoming webhook URL was found hardcoded. Anyone with this URL can post messages to the associated Slack channel.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Rotate this webhook URL in Slack settings. Store webhook URLs in environment variables or a secrets manager.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "webhook", "slack"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-SEC-009: Twilio API Key/SID
// ========================================================================

type TwilioKeyRule struct{}

func (r *TwilioKeyRule) ID() string                     { return "BATOU-SEC-009" }
func (r *TwilioKeyRule) Name() string                   { return "TwilioAPIKey" }
func (r *TwilioKeyRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *TwilioKeyRule) Description() string {
	return "Detects Twilio Account SIDs (AC...) and API keys (SK...) hardcoded in source code."
}
func (r *TwilioKeyRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *TwilioKeyRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	seen := make(map[int]bool)
	for i, line := range lines {
		if isCommentLine(line) || seen[i+1] {
			continue
		}
		if m := reExtTwilioSID.FindStringSubmatch(line); m != nil {
			seen[i+1] = true
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Twilio Account SID or API key exposed",
				Description:   "A Twilio identifier (" + redactValue(m[1]) + ") was found hardcoded. This can be used to access Twilio APIs, send SMS, or make phone calls on your account.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Rotate this credential. Store Twilio SIDs and auth tokens in environment variables.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "api-key", "twilio"},
			})
		}
		if !seen[i+1] {
			if m := reExtTwilioAuth.FindStringSubmatch(line); m != nil {
				seen[i+1] = true
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Twilio auth token exposed",
					Description:   "A Twilio auth token (" + redactValue(m[1]) + ") was found hardcoded.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Rotate this auth token immediately and store it in a secrets manager.",
					CWEID:         "CWE-798",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"secrets", "api-key", "twilio"},
				})
			}
		}
	}
	return findings
}

// ========================================================================
// BATOU-SEC-010: SendGrid API Key
// ========================================================================

type SendGridKeyRule struct{}

func (r *SendGridKeyRule) ID() string                     { return "BATOU-SEC-010" }
func (r *SendGridKeyRule) Name() string                   { return "SendGridAPIKey" }
func (r *SendGridKeyRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *SendGridKeyRule) Description() string {
	return "Detects SendGrid API keys (SG...) hardcoded in source code."
}
func (r *SendGridKeyRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *SendGridKeyRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtSendGridKey.FindStringSubmatch(line); m != nil {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SendGrid API key exposed in source code",
				Description:   "A SendGrid API key (" + redactValue(m[1]) + ") was found hardcoded. This key can be used to send emails as your domain.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Rotate this API key in the SendGrid dashboard. Store it in environment variables or a secrets manager.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "api-key", "sendgrid"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-SEC-011: Mailgun API Key
// ========================================================================

type MailgunKeyRule struct{}

func (r *MailgunKeyRule) ID() string                     { return "BATOU-SEC-011" }
func (r *MailgunKeyRule) Name() string                   { return "MailgunAPIKey" }
func (r *MailgunKeyRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *MailgunKeyRule) Description() string {
	return "Detects Mailgun API keys (key-...) hardcoded in source code."
}
func (r *MailgunKeyRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *MailgunKeyRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtMailgunKey.FindStringSubmatch(line); m != nil {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Mailgun API key exposed in source code",
				Description:   "A Mailgun API key (" + redactValue(m[1]) + ") was found hardcoded. This key can be used to send emails from your Mailgun domain.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Rotate this API key in the Mailgun dashboard. Store it in environment variables or a secrets manager.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "api-key", "mailgun"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-SEC-012: Database Connection String with Password
// ========================================================================

type DBConnStringExtRule struct{}

func (r *DBConnStringExtRule) ID() string                     { return "BATOU-SEC-012" }
func (r *DBConnStringExtRule) Name() string                   { return "DBConnectionStringExt" }
func (r *DBConnStringExtRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *DBConnStringExtRule) Description() string {
	return "Detects database connection strings with embedded passwords in URI format."
}
func (r *DBConnStringExtRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *DBConnStringExtRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtDBConnString.FindString(line); m != "" {
			lower := strings.ToLower(line)
			// Exclude placeholder URIs
			if strings.Contains(lower, "username:password@") ||
				strings.Contains(lower, "user:pass@") ||
				strings.Contains(lower, "user:password@") ||
				strings.Contains(lower, "<password>") ||
				strings.Contains(lower, "${") ||
				strings.Contains(lower, "{{") {
				continue
			}
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Database connection string with embedded password",
				Description:   "A database connection URI with credentials was found. If source code is exposed, the database credentials are compromised.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use environment variables for database connection parameters. Construct the connection string at runtime from separately managed credentials.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "credentials", "database", "connection-string"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-SEC-013: Private Key in Source (PEM Format)
// ========================================================================

type PrivateKeyBlockRule struct{}

func (r *PrivateKeyBlockRule) ID() string                     { return "BATOU-SEC-013" }
func (r *PrivateKeyBlockRule) Name() string                   { return "PrivateKeyBlock" }
func (r *PrivateKeyBlockRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PrivateKeyBlockRule) Description() string {
	return "Detects PEM-encoded private keys embedded in source code, including encrypted private keys."
}
func (r *PrivateKeyBlockRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PrivateKeyBlockRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if reExtPrivateKeyBlock.MatchString(line) {
			match := reExtPrivateKeyBlock.FindString(line)
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Private key embedded in source code",
				Description:   "A PEM-encoded private key was found in the source file. Private keys must never be stored in source code repositories.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   match,
				Suggestion:    "Remove the private key from source code immediately. Store it in a secure key management system (AWS KMS, HashiCorp Vault, Azure Key Vault) or load it from a file path specified via environment variable.",
				CWEID:         "CWE-321",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "private-key", "cryptography", "pem"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-SEC-014: Azure Storage Account Key
// ========================================================================

type AzureStorageKeyRule struct{}

func (r *AzureStorageKeyRule) ID() string                     { return "BATOU-SEC-014" }
func (r *AzureStorageKeyRule) Name() string                   { return "AzureStorageKey" }
func (r *AzureStorageKeyRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *AzureStorageKeyRule) Description() string {
	return "Detects Azure Storage account keys hardcoded in source code."
}
func (r *AzureStorageKeyRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *AzureStorageKeyRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtAzureStorageKey.FindStringSubmatch(line); m != nil {
			if isPlaceholder(m[1]) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Azure Storage account key exposed",
				Description:   "An Azure Storage account key (" + redactValue(m[1]) + ") was found hardcoded. This key provides full access to the storage account.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Rotate this key in the Azure Portal. Use Azure Managed Identity or store the key in Azure Key Vault.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "api-key", "azure", "cloud"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-SEC-015: GCP Service Account JSON Key
// ========================================================================

type GCPServiceAccountRule struct{}

func (r *GCPServiceAccountRule) ID() string                     { return "BATOU-SEC-015" }
func (r *GCPServiceAccountRule) Name() string                   { return "GCPServiceAccountKey" }
func (r *GCPServiceAccountRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *GCPServiceAccountRule) Description() string {
	return "Detects GCP service account JSON key files embedded in source code."
}
func (r *GCPServiceAccountRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *GCPServiceAccountRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	// Check if the content matches service account JSON structure
	if !reExtGCPServiceAccount.MatchString(ctx.Content) {
		return nil
	}
	if !reExtGCPPrivateKeyID.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if reExtGCPServiceAccount.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GCP service account JSON key in source code",
				Description:   "A GCP service account key file was found embedded in source code. These keys provide authentication to Google Cloud services and should never be committed to source control.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Remove the service account key from source code. Use Workload Identity Federation or store the key file path in an environment variable (GOOGLE_APPLICATION_CREDENTIALS). Rotate the key in the GCP Console.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "service-account", "gcp", "cloud"},
			})
			break // Only report once per file
		}
	}
	return findings
}

// ========================================================================
// BATOU-SEC-016: Generic High-Entropy String in Secret Variable
// ========================================================================

type HighEntropySecretRule struct{}

func (r *HighEntropySecretRule) ID() string                     { return "BATOU-SEC-016" }
func (r *HighEntropySecretRule) Name() string                   { return "HighEntropySecret" }
func (r *HighEntropySecretRule) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *HighEntropySecretRule) Description() string {
	return "Detects high-entropy strings assigned to variables with secret-indicating names."
}
func (r *HighEntropySecretRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *HighEntropySecretRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		m := reExtSecretAssignment.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		value := m[1]
		if isPlaceholder(value) {
			continue
		}
		if !hasHighEntropy(value, 3.5) || !hasCharacterDiversity(value) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "High-entropy string in secret variable",
			Description:   "A high-entropy string (" + redactValue(value) + ") was found assigned to a variable with a secret-indicating name. This may be a real credential.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Move this value to an environment variable or secrets manager. If this is not a real secret, rename the variable to avoid confusion.",
			CWEID:         "CWE-798",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"secrets", "high-entropy", "credentials"},
		})
	}
	return findings
}
