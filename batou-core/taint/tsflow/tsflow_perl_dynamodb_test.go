package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Paws::DynamoDB second-order read sources (CWE-89/78/943).
//
// Perl already modeled Paws::S3 GetObject and Paws::SQS ReceiveMessage as
// external second-order sources, but the Paws::DynamoDB read operations
// (GetItem / BatchGetItem / Query / Scan / TransactGetItems) were missing.
// A value an untrusted user stored via PutItem on one request and read back
// via GetItem on a later request was therefore not flagged when later
// concatenated into a command / SQL / eval / HTML sink.
//
// Mirrors the cross-language DynamoDB second-order read-source wave
// (Python boto3, Go aws-sdk-go-v2 DynamoDB).
//
// Receiver "$dynamodb" matches the catalog ObjectType "Paws::DynamoDB"
// (last path component "dynamodb") via the tsflow exact-match heuristic.
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

func TestPerl_PawsDynamoDB_GetItem_SecondOrder_Command(t *testing.T) {
	code := `
use Paws;
sub handler {
    my $dynamodb = Paws->service('DynamoDB');
    my $resp = $dynamodb->GetItem(TableName => 'users', Key => { id => { S => '1' } });
    return system("echo " . $resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $dynamodb->GetItem -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_PawsDynamoDB_BatchGetItem_SecondOrder_Command(t *testing.T) {
	code := `
use Paws;
sub handler {
    my $dynamodb = Paws->service('DynamoDB');
    my $resp = $dynamodb->BatchGetItem(RequestItems => $items);
    return system("/usr/bin/run " . $resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $dynamodb->BatchGetItem -> system")
	}
}

func TestPerl_PawsDynamoDB_Query_SecondOrder_Eval(t *testing.T) {
	code := `
use Paws;
sub handler {
    my $dynamodb = Paws->service('DynamoDB');
    my $resp = $dynamodb->Query(TableName => 'users', KeyConditionExpression => 'id = :v');
    eval($resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for $dynamodb->Query -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_PawsDynamoDB_Scan_SecondOrder_Command(t *testing.T) {
	code := `
use Paws;
sub handler {
    my $dynamodb = Paws->service('DynamoDB');
    my $resp = $dynamodb->Scan(TableName => 'users');
    return system("echo " . $resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $dynamodb->Scan -> system")
	}
}

func TestPerl_PawsDynamoDB_TransactGetItems_SecondOrder_Command(t *testing.T) {
	code := `
use Paws;
sub handler {
    my $dynamodb = Paws->service('DynamoDB');
    my $resp = $dynamodb->TransactGetItems(TransactItems => $txs);
    return system("echo " . $resp);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $dynamodb->TransactGetItems -> system")
	}
}

// Negative control: a hardcoded constant fed to the same sink must NOT
// produce a flow — proves the DynamoDB read result is what introduces taint,
// not the sink itself.
func TestPerl_PawsDynamoDB_ConstantArg_NoFlow(t *testing.T) {
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
