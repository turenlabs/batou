package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for framework-shaped RPC entry-point parameter sources:
//   - gRPC server handler request messages (`req *pb.XRequest`)
//   - gqlgen resolver method arguments (`id string` after a context.Context)
//
// These model the typed-parameter taint surface that the older catalog only
// covered via the graphql.GetFieldContext(...).Args helper path. The handlers
// are gated on a leading context.Context (the universal gRPC/gqlgen shape) to
// keep the false-positive rate low; the negative tests below pin that guard.

// gRPC: request message field reached via a generated getter flows to exec.
func TestAnalyzeGo_GRPC_RequestGetter_CmdInj(t *testing.T) {
	code := `package handlers

import (
	"context"
	"os/exec"

	pb "example.com/proto"
)

type server struct{}

func (s *server) RunCommand(ctx context.Context, req *pb.RunCommandRequest) (*pb.RunCommandResponse, error) {
	cmd := req.GetShellCmd()
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return nil, err
	}
	return &pb.RunCommandResponse{Output: string(out)}, nil
}
`
	flows := AnalyzeGo(code, "/app/grpc.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for gRPC req.GetShellCmd() -> exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// gRPC: request message field reached via a direct field read flows to SQL.
func TestAnalyzeGo_GRPC_RequestField_SQLi(t *testing.T) {
	code := `package handlers

import (
	"context"
	"database/sql"

	pb "example.com/proto"
)

var db *sql.DB

func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (string, error) {
	row := db.QueryRow("SELECT name FROM users WHERE id = '" + req.Id + "'")
	var name string
	_ = row.Scan(&name)
	return name, nil
}
`
	flows := AnalyzeGo(code, "/app/grpc.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for gRPC req.Id -> db.QueryRow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// gqlgen: a typed resolver argument flows into a SQL sink.
func TestAnalyzeGo_Gqlgen_ResolverArg_SQLi(t *testing.T) {
	code := `package handlers

import (
	"context"
	"database/sql"
	"fmt"
)

func (r *queryResolver) User(ctx context.Context, id string) (string, error) {
	db := r.conn
	q := fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", id)
	row := db.QueryRow(q)
	var name string
	_ = row.Scan(&name)
	return name, nil
}

type queryResolver struct {
	conn *sql.DB
}
`
	flows := AnalyzeGo(code, "/app/resolver.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for gqlgen resolver arg id -> db.QueryRow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// gqlgen: a typed resolver argument flows into a command-execution sink.
func TestAnalyzeGo_Gqlgen_ResolverArg_CmdInj(t *testing.T) {
	code := `package handlers

import (
	"context"
	"os/exec"
)

func (r *mutationResolver) Ping(ctx context.Context, host string) (string, error) {
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type mutationResolver struct{}
`
	flows := AnalyzeGo(code, "/app/resolver.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for gqlgen resolver arg host -> exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Precision guard 1: a non-resolver helper that happens to take
// (context.Context, string) must NOT auto-taint its string argument — only
// *...Resolver receivers seed resolver args. Without this guard the broad
// "context.Context first param" shape would taint ordinary internal helpers.
func TestAnalyzeGo_Gqlgen_NonResolverHelper_NoFlow(t *testing.T) {
	code := `package handlers

import (
	"context"
	"os/exec"
)

type service struct{}

func (s *service) lookup(ctx context.Context, name string) (string, error) {
	out, err := exec.Command("getent", "hosts", name).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
`
	flows := AnalyzeGo(code, "/app/svc.go")
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("FP: non-resolver helper (*service.lookup) arg should not be auto-tainted")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Precision guard 2: a request-message-shaped parameter without a leading
// context.Context (not a gRPC handler) must NOT be auto-tainted. A locally
// declared struct named "...Request" passed to a plain function is not an RPC
// entry point.
func TestAnalyzeGo_GRPC_NoContextLeadingParam_NoFlow(t *testing.T) {
	code := `package handlers

import (
	"os/exec"

	pb "example.com/proto"
)

func process(req *pb.RunCommandRequest) error {
	return exec.Command("sh", "-c", req.GetShellCmd()).Run()
}
`
	flows := AnalyzeGo(code, "/app/proc.go")
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("FP: request param without a leading context.Context should not be auto-tainted")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
