package php

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a PHP-rule-heavy ScanContext: a spread of lines the PHP
// rules scan, most of which carry no trigger (the realistic majority case where
// the per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate
// dominated). LinesLower is populated exactly as the scanner does before fanning
// out rules, so the migrated *Lower call sites take the shared-lowered-line fast
// path.
func lowermigCtx(base []string) *rules.ScanContext {
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
		FilePath:     "/app/index.php",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangPHP,
	}
}

// phpBenchRules returns every registered PHP rule (BATOU-PHP-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func phpBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-PHP-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigPHPBench = lowermigCtx([]string{
	"<?php",
	"$name = $_GET['name'];",
	"$q = \"SELECT * FROM users WHERE name = '\" . $name . \"'\";",
	"$res = mysqli_query($conn, $q);",
	"include($_GET['page'] . '.php');",
	"$data = file_get_contents($url);",
	"curl_setopt($ch, CURLOPT_URL, $url);",
	"system('ls ' . $dir);",
	"$out = `cat $file`;",
	"mail($to, $subject, $body, $headers);",
	"$obj = unserialize($payload);",
	"eval($code);",
	"extract($_POST);",
	"$x = create_function('$a', $body);",
	"file_put_contents($path, $content);",
	"ldap_search($conn, $base, '(uid=' . $user . ')');",
	"preg_replace('/x/e', $repl, $subject);",
	"ini_set('display_errors', 1);",
	"$r = rand();",
	"$total = array_sum($items);",
	"foreach ($list as $it) { $acc[] = $it['name']; }",
	"if ($cfg['enabled'] && $cfg['timeout'] > 0) { retry(); }",
	"error_log('processed ' . $count . ' records');",
	"return render('index', $model);",
	"?>",
})

// BenchmarkPHPScan_LowerMigrated runs every PHP rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration php/*.go to quantify the per-(pattern × line) re-lowering removed
// by the *Lower migration.
func BenchmarkPHPScan_LowerMigrated(b *testing.B) {
	rs := phpBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigPHPBench))
		}
	}
	_ = n
}
