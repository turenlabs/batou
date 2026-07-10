package crypto

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// Representative crypto-heavy source: a spread of lines that the CRY rules scan,
// most of which carry no crypto trigger (the realistic majority case where the
// per-(pattern x line) re-lowering dominated). Built once, ~210 lines, with
// LinesLower populated exactly as the scanner does before fanning out rules.
var lowermigBench = func() *rules.ScanContext {
	base := []string{
		"package handler",
		"import crypto/md5",
		"func process(data []byte) string {",
		"  h := md5.New()",
		"  s := sha1.Sum(data)",
		"  cipher, _ := des.NewCipher(key)",
		"  tlsCfg := &tls.Config{InsecureSkipVerify: true}",
		"  block, _ := aes.NewCipher(k) // ECB",
		"  rsa.GenerateKey(rand.Reader, 1024)",
		"  u := \"http://example.com/api\"",
		"  log.Printf(\"processing %d bytes for user %s\", len(data), name)",
		"  result := db.Query(query, args...)",
		"  for i, v := range items { total += v.Amount }",
		"  if cfg.Enabled && cfg.Timeout > 0 { retry() }",
		"  return hex.EncodeToString(h.Sum(nil))",
	}
	var lines []string
	for len(lines) < 210 {
		lines = append(lines, base...)
	}
	content := strings.Join(lines, "\n")
	lower := make([]string, len(lines))
	for i, l := range lines {
		lower[i] = strings.ToLower(l)
	}
	return &rules.ScanContext{
		FilePath:     "/app/handler.go",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangGo,
	}
}()

// cryptoBenchRules are the CRY rules carrying the bulk of the migrated G* sites.
func cryptoBenchRules() []rules.Rule {
	return []rules.Rule{
		&WeakHashing{}, &InsecureRandom{}, &WeakCipher{}, &HardcodedIV{},
		&InsecureTLS{}, &WeakKeySize{},
	}
}

// BenchmarkCryptoScan_LowerMigrated runs the migrated CRY rules over the
// LinesLower-populated context (the shared-lowered-line path). Compare allocs/op
// against the pre-migration crypto.go (git stash the file, re-run) to quantify
// the per-(pattern x line) re-lowering removed by the *Lower migration.
func BenchmarkCryptoScan_LowerMigrated(b *testing.B) {
	rs := cryptoBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigBench))
		}
	}
	_ = n
}
