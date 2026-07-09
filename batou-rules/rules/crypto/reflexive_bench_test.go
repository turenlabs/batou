package crypto

import "testing"

// representative source lines: most lines have no ==/!= (the gate's win case).
var benchLines = []string{
	"func computeHash(password string) []byte {",
	"  h := sha256.New()",
	"  return h.Sum(nil)",
	"const config = { timeout: 30, retries: 3 }",
	"logger.Info(\"processing request\", \"user\", userID)",
	"if token === storedToken {",            // comparison, runs regex
	"x = y + z",                              // single =, gate skips
	"  result := db.Query(sql, args...)",
	"if a.secret == a.secret { return true }", // reflexive, runs regex
	"  for i := range items {",
}

func BenchmarkReflexiveGated(b *testing.B) {
	b.ReportAllocs()
	var sink bool
	for i := 0; i < b.N; i++ {
		for _, l := range benchLines {
			sink = isReflexiveCompare(l)
		}
	}
	_ = sink
}

func BenchmarkReflexiveUngated(b *testing.B) {
	b.ReportAllocs()
	var sink bool
	for i := 0; i < b.N; i++ {
		for _, l := range benchLines {
			sink = reflexiveCompareUngated(l)
		}
	}
	_ = sink
}
