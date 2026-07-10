package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Paws::Kinesis and Paws::Lambda second-order read sources.
//
// Perl already modeled Paws::S3 GetObject, Paws::SQS ReceiveMessage, and the
// Paws::DynamoDB read operations as external second-order sources, but two AWS
// data-read paths were missing:
//
//   * Paws::Kinesis GetRecords — a producer may write attacker-controlled
//     bytes to a shard on one request; a consumer reads them back later.
//   * Paws::Lambda Invoke — the response Payload is the output of the invoked
//     function, which may itself process untrusted input.
//
// Mirrors the cross-language AWS second-order read-source wave (Go Kinesis,
// Rust DynamoDB+Kinesis, Java/Cpp AWS reads).
//
// Receiver "$kinesis" / "$lambda" match the catalog ObjectTypes
// "Paws::Kinesis" / "Paws::Lambda" (last path component) via the tsflow
// exact-match heuristic — the same mechanism that scopes "$dynamodb" to
// "Paws::DynamoDB".
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

func TestPerl_PawsKinesis_GetRecords_SecondOrder_Command(t *testing.T) {
	code := `
use Paws;
sub handler {
    my $kinesis = Paws->service('Kinesis');
    my $resp = $kinesis->GetRecords(ShardIterator => $it);
    return system("echo " . $resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $kinesis->GetRecords -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_PawsKinesis_GetRecords_SecondOrder_Eval(t *testing.T) {
	code := `
use Paws;
sub handler {
    my $kinesis = Paws->service('Kinesis');
    my $resp = $kinesis->GetRecords(ShardIterator => $it);
    eval($resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for $kinesis->GetRecords -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_PawsLambda_Invoke_SecondOrder_Command(t *testing.T) {
	code := `
use Paws;
sub handler {
    my $lambda = Paws->service('Lambda');
    my $resp = $lambda->Invoke(FunctionName => 'proc', Payload => $body);
    return system("/usr/bin/run " . $resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $lambda->Invoke -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a hardcoded constant fed to the same sink must NOT produce
// a flow — proves the Kinesis/Lambda read result is what introduces taint, not
// the sink itself.
func TestPerl_PawsKinesisLambda_ConstantArg_NoFlow(t *testing.T) {
	code := `
sub handler {
    my $resp = "constant-value";
    return system("echo " . $resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect SnkCommand flow for a hardcoded constant -> system")
	}
}
