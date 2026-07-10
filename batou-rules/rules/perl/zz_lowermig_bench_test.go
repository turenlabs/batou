package perl

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a Perl-rule-heavy ScanContext: a spread of lines the Perl
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
		FilePath:     "/app/cgi-bin/app.pl",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangPerl,
	}
}

// plBenchRules returns every registered Perl rule (BATOU-PL-*) — the set carrying
// the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func plBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-PL-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigPLBench = lowermigCtx([]string{
	"#!/usr/bin/perl",
	"use strict;",
	"use CGI;",
	"my $q = CGI->new;",
	"my $name = $q->param('name');",
	"system(\"ls $name\");",
	"exec(\"cat \" . $name);",
	"my $out = `grep $name file.txt`;",
	"my $r = qx/echo $name/;",
	"open(FH, \"cat $name |\");",
	"$dbh->do(\"SELECT * FROM users WHERE name = '$name'\");",
	"$dbh->prepare(\"SELECT * FROM t WHERE x = \" . $name);",
	"eval \"$name\";",
	"eval $name;",
	"open(my $fh, $name);",
	"my $re = qr/$name/;",
	"if ($x =~ /$name/) { }",
	"print $q->param('html');",
	"print \"Content-type: text/html\";",
	"$ldap->search(filter => \"(cn=$name)\");",
	"my $data = Storable::thaw($name);",
	"my $y = YAML::Load($name);",
	"open(F, \">$name\");",
	"chmod(0777, $name);",
	"mkdir($name, 0777);",
	"srand(time);",
	"my $token = rand();",
	"my $sum = 0;",
	"$sum += $_ for @items;",
	"return $sum;",
})

// BenchmarkPerlScan_LowerMigrated runs every Perl rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration perl/*.go to quantify the per-(pattern × line) re-lowering removed
// by the *Lower migration.
func BenchmarkPerlScan_LowerMigrated(b *testing.B) {
	rs := plBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigPLBench))
		}
	}
	_ = n
}
