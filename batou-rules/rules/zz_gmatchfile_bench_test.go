package rules

import (
	"regexp"
	"strings"
	"testing"
)

// Representative whole-file guard regexes, same shape as the 407 migrated ones
// (case-insensitive alternations of API/header literals). On a file that does
// not contain the literals — the common case — GMatchFile's fold-aware
// required-literal prefilter returns false in ~tens of ns, while the raw
// (?i) MatchString backtracks over the whole file.
var gmfBenchGuards = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.set|\.add_header|response\[|headers\[)\s*\(?\s*["']`),
	regexp.MustCompile(`(?i)["']Content-Security-Policy["']`),
	regexp.MustCompile(`(?i)(?:helmet\.contentSecurityPolicy|csp\s*\(|contentSecurityPolicy\s*\()`),
	regexp.MustCompile(`(?i)["']X-Frame-Options["']`),
	regexp.MustCompile(`(?i)helmet\.frameguard|frameguard\s*\(`),
	regexp.MustCompile(`(?i)(?:require\(['"]express|from\s+['"]express|require\(['"]fastify)`),
	regexp.MustCompile(`(?i)(?:executeQuery|createStatement|prepareStatement|rawQuery)\s*\(`),
	regexp.MustCompile(`(?i)(?:innerHTML|dangerouslySetInnerHTML|document\.write)\s*[=(]`),
	regexp.MustCompile(`(?i)(?:Runtime\.getRuntime|ProcessBuilder|os\.system|subprocess\.)`),
	regexp.MustCompile(`(?i)(?:MessageDigest|MD5|SHA-?1|DESKeySpec|Cipher\.getInstance)`),
	regexp.MustCompile(`(?i)(?:setAttribute|putValue|addFlashAttribute)\s*\(`),
	regexp.MustCompile(`(?i)(?:jwt\.sign|jwt\.verify|jsonwebtoken|HS256|none\s*algorithm)`),
}

// A realistic ~240-line source file that contains NONE of the guard literals
// (the dominant real-world case the gate optimizes).
var gmfBenchCtx = func() *ScanContext {
	base := []string{
		"package service",
		"import (",
		"  \"fmt\"",
		"  \"strings\"",
		"  \"time\"",
		")",
		"// Coordinator schedules background reconciliation work across shards.",
		"type Coordinator struct {",
		"  shards   []shard",
		"  interval time.Duration",
		"  metrics  *metricsBuf",
		"}",
		"func (c *Coordinator) reconcile(ctx context, id int) (int, error) {",
		"  total := 0",
		"  for _, s := range c.shards {",
		"    n, err := s.flush(ctx, id)",
		"    if err != nil { return total, fmt.Errorf(\"flush %d: %w\", id, err) }",
		"    total += n",
		"  }",
		"  c.metrics.observe(\"reconcile.count\", float64(total))",
		"  return total, nil",
		"}",
		"func normalize(parts []string) string {",
		"  out := make([]string, 0, len(parts))",
		"  for _, p := range parts { out = append(out, strings.TrimSpace(p)) }",
		"  return strings.Join(out, \"/\")",
		"}",
	}
	var lines []string
	for len(lines) < 240 {
		lines = append(lines, base...)
	}
	content := strings.Join(lines, "\n")
	return &ScanContext{
		FilePath:     "/app/coordinator.go",
		Content:      content,
		ContentLower: strings.ToLower(content),
		Language:     LangGo,
	}
}()

// BenchmarkWholeFileGuard_Raw is the pre-migration form: raw (?i) MatchString
// over the whole file for every guard.
func BenchmarkWholeFileGuard_Raw(b *testing.B) {
	b.ReportAllocs()
	var hit int
	for i := 0; i < b.N; i++ {
		for _, re := range gmfBenchGuards {
			if re.MatchString(gmfBenchCtx.Content) {
				hit++
			}
		}
	}
	_ = hit
}

// BenchmarkWholeFileGuard_GMatchFile is the migrated form: the fold-aware
// prefilter gates each guard against the once-lowered content.
func BenchmarkWholeFileGuard_GMatchFile(b *testing.B) {
	b.ReportAllocs()
	var hit int
	for i := 0; i < b.N; i++ {
		for _, re := range gmfBenchGuards {
			if GMatchFile(re, gmfBenchCtx) {
				hit++
			}
		}
	}
	_ = hit
}
