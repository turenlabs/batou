package golang

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// real grafana lines loaded once
var benchLines, benchLower = func() ([]string, []string) {
	b, _ := os.ReadFile("/tmp/graf_sample_lines.txt")
	ls := strings.Split(string(b), "\n")
	lo := make([]string, len(ls))
	for i, l := range ls {
		lo[i] = strings.ToLower(l)
	}
	return ls, lo
}()

// a representative set of the golang rule patterns (mix of (?i) and not)
var benchPats = []*regexp.Regexp{
	reGORMRawSprintf, reGORMRawConcat, reGORMWhereConcat,
	reTemplateHTML, reTemplateHTMLAttr, reTemplateJS, reTemplateCSS, reTemplateURL,
	reListenAndServe, reGinBind, reGinValidate, reEchoValidate,
	reFilepathJoin, reHasPrefix, reUserInputHTTP,
	reGoRandCryptoUse, reGoCryptoContext,
	reGoFuncInHandler, reGoFuncNamed, reContextDone, reHTTPHandlerSig,
	reGlobalMapAccess, reMutexUsage,
	reFormHandler, reCSRFMiddleware, reFormParse,
	reJWTSigningKey, reJWTKeyVariable, reJWTKeyLiteral,
	reGinSetTrustedProxies, reEchoIPExtractor,
	reResponseWrite, reFprintfResponse, reSetContentType,
}

// BenchGFind: current merged approach — GFind re-lowers the line per call
func BenchmarkGate_GFind(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for _, line := range benchLines {
			for _, re := range benchPats {
				_ = rules.GFind(re, line)
			}
		}
	}
}

// BenchSharedLower: task-prescribed — LineMightMatch on the precomputed lowered line, raw regex after
func BenchmarkGate_SharedLower(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for i, line := range benchLines {
			lo := benchLower[i]
			for _, re := range benchPats {
				if rules.LineMightMatch(lo, re) {
					_ = re.FindString(line)
				}
			}
		}
	}
}

// BenchUngated: no gate at all (the pre-#1205 world)
func BenchmarkGate_Ungated(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for _, line := range benchLines {
			for _, re := range benchPats {
				_ = re.FindString(line)
			}
		}
	}
}
