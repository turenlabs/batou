package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP XPath injection tests — Symfony DomCrawler (CWE-643)
// =========================================================================

func TestPHP_XPath_Symfony_FilterXPath_Unsanitized(t *testing.T) {
	code := `<?php
use Symfony\Component\DomCrawler\Crawler;
function handler() {
    $expr = $_GET["xpath"];
    $crawler = new Crawler($html);
    $nodes = $crawler->filterXPath($expr);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for $_GET -> Crawler->filterXPath")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_XPath_Symfony_Evaluate_Unsanitized(t *testing.T) {
	code := `<?php
use Symfony\Component\DomCrawler\Crawler;
function handler() {
    $expr = $_POST["xpath"];
    $crawler = new Crawler($html);
    $result = $crawler->evaluate($expr);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for $_POST -> $crawler->evaluate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative case: hardcoded XPath constant with no user input — no flow.
func TestPHP_XPath_Symfony_FilterXPath_HardcodedSafe(t *testing.T) {
	code := `<?php
use Symfony\Component\DomCrawler\Crawler;
function handler() {
    $crawler = new Crawler($html);
    $nodes = $crawler->filterXPath('//div[@id="main"]');
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("hardcoded XPath literal must not trigger XPath injection sink")
	}
}

// Negative case: a non-Crawler object's evaluate() must not fire our sink.
func TestPHP_XPath_Evaluate_NonCrawler(t *testing.T) {
	code := `<?php
function handler() {
    $expr = $_GET["x"];
    $scorer = new Evaluator();
    $score = $scorer->evaluate($expr);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("evaluate() on a non-Crawler receiver must not fire Symfony XPath sink")
	}
}
