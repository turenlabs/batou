package languages

import "testing"

func TestIsGoGRPCRequestParamType(t *testing.T) {
	tests := []struct {
		typeName string
		want     bool
	}{
		// gRPC/protobuf request messages — package-qualified pointer, ...Request.
		{"*pb.RunCommandRequest", true},
		{"*userpb.GetUserRequest", true},
		{"*proto.LoginRequest", true},
		{"pb.RunCommandRequest", true}, // value form (rare but valid)
		// Not request messages.
		{"*http.Request", true}, // package-qualified ...Request — handled by the
		// context.Context-first guard in the caller (a real *http.Request handler
		// has signature (w, r), not (ctx, r)), so this is acceptable to match here.
		{"*pb.RunCommandResponse", false}, // response, not request
		{"string", false},                 // scalar
		{"Request", false},                // bare local type, no package qualifier
		{"*Request", false},               // bare local pointer, no package qualifier
		{"context.Context", false},        // the leading ctx param
		{"", false},
	}
	for _, tt := range tests {
		if got := IsGoGRPCRequestParamType(tt.typeName); got != tt.want {
			t.Errorf("IsGoGRPCRequestParamType(%q) = %v, want %v", tt.typeName, got, tt.want)
		}
	}
}

func TestIsGoArchiveEntryParamType(t *testing.T) {
	tests := []struct {
		typeName string
		want     bool
	}{
		// Archive-entry types — the real canonType exprToTypeString produces
		// for `f *zip.File` / `h *tar.Header` parameters.
		{"*zip.File", true},
		{"*tar.Header", true},
		{"zip.File", true},   // value form (rare but valid)
		{"tar.Header", true}, // value form
		// Not archive entries.
		{"*http.Request", false},   // HTTP request, different type
		{"*File", false},           // bare local pointer, no package qualifier
		{"File", false},            // bare local struct named File
		{"Header", false},          // bare local struct named Header
		{"*archive.File", false},   // wrong package qualifier
		{"*zip.ReadCloser", false}, // zip type but not an entry
		{"*tar.Reader", false},     // tar type but not an entry
		{"string", false},          // scalar
		{"context.Context", false}, // leading ctx param
		{"", false},
	}
	for _, tt := range tests {
		if got := IsGoArchiveEntryParamType(tt.typeName); got != tt.want {
			t.Errorf("IsGoArchiveEntryParamType(%q) = %v, want %v", tt.typeName, got, tt.want)
		}
	}
}

func TestIsGoGraphQLResolverReceiver(t *testing.T) {
	tests := []struct {
		recv string
		want bool
	}{
		{"*queryResolver", true},
		{"*mutationResolver", true},
		{"queryResolver", true},
		{"*Resolver", true},
		{"*model.queryResolver", true},
		{"*server", false},
		{"*service", false},
		{"queryResolverHelper", false}, // does not end in Resolver
		{"", false},
	}
	for _, tt := range tests {
		if got := IsGoGraphQLResolverReceiver(tt.recv); got != tt.want {
			t.Errorf("IsGoGraphQLResolverReceiver(%q) = %v, want %v", tt.recv, got, tt.want)
		}
	}
}
