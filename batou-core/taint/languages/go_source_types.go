package languages

import (
	"strings"

	"github.com/turenlabs/batou-core/taint"
)

// KnownGoSourceTypes maps a canonical Go type string (pointer + default-alias
// qualified) to the source category that values of that type represent.
//
// Keys use the default alias of the import path — e.g. "*http.Request" for
// "net/http" and "*gin.Context" for "github.com/gin-gonic/gin". Aliased
// imports are canonicalised via astflow.CanonicalizeType before lookup, so
// `import h "net/http"` still resolves `*h.Request` to "*http.Request".
//
// A parameter whose type matches one of these entries is treated as carrying
// tainted input without requiring a specific method-call source.
var KnownGoSourceTypes = map[string]taint.SourceCategory{
	"*http.Request": taint.SrcUserInput,
	// http.ResponseWriter is intentionally absent — it's the outbound
	// side of an HTTP handler (where the server writes responses),
	// not a taint source. Marking it as a source caused proxy/handler
	// patterns like `handle(w, r) { proxy(w, r, ...) }` to flag `w`
	// as a tainted argument, surfacing log-injection / xss false
	// positives on the writer itself. See the matching comment on
	// graph/extractor_golang.go: goTypeCatalog.
	"*gin.Context":          taint.SrcUserInput,
	"echo.Context":          taint.SrcUserInput,
	"*fiber.Ctx":            taint.SrcUserInput,
	"*mux.Router":           taint.SrcUserInput,
	"*sql.Rows":             taint.SrcDatabase,
	"*sql.Row":              taint.SrcDatabase,
	"*gorm.DB":              taint.SrcDatabase,
	"*sqlx.Rows":            taint.SrcDatabase,
	"*sqlx.Row":             taint.SrcDatabase,
	"io.Reader":             taint.SrcNetwork,
	"io.ReadCloser":         taint.SrcNetwork,
	"*multipart.FileHeader": taint.SrcUserInput,
	"*multipart.Form":       taint.SrcUserInput,
	"net.Conn":              taint.SrcNetwork,
	"*amqp.Delivery":        taint.SrcExternal,
	"*redis.Message":        taint.SrcExternal,
	"*kafka.Message":        taint.SrcExternal,
	"*nats.Msg":             taint.SrcExternal,
	"*pubsub.Message":       taint.SrcExternal,
}

// LookupGoSourceType returns the source category for a canonical Go type,
// or ("", false) if the type is not a known source.
func LookupGoSourceType(canonicalType string) (taint.SourceCategory, bool) {
	cat, ok := KnownGoSourceTypes[canonicalType]
	return cat, ok
}

// IsGoGRPCRequestParamType reports whether a parameter type string looks like a
// generated gRPC/protobuf request message — i.e. a pointer to a struct from a
// proto-generated package whose type name ends in "Request" (e.g.
// "*pb.RunCommandRequest", "*userpb.GetUserRequest", "*proto.LoginRequest").
//
// gRPC server handlers have the canonical signature
//
//	func (s *server) Method(ctx context.Context, req *pb.MethodRequest) (*pb.MethodResponse, error)
//
// where the request message carries every client-supplied field. Field reads on
// that message (`req.Cmd`, `req.GetCmd()`) are attacker-controlled, so the
// parameter itself must be seeded as a taint source. astflow's
// seedHTTPHandlerParams previously SKIPPED any type containing "request"
// (intended for *http.Request), which silently dropped the gRPC request message.
//
// The match is intentionally conservative: it requires a package-qualified
// pointer type (a dot before the final name) so that bare local structs named
// "...Request" in non-RPC code are not auto-tainted. The companion
// context.Context-first-parameter check in the caller further narrows this to
// the RPC handler shape.
func IsGoGRPCRequestParamType(typeName string) bool {
	t := strings.TrimPrefix(typeName, "*")
	dot := strings.LastIndex(t, ".")
	if dot <= 0 || dot == len(t)-1 {
		return false // must be pkg.Name with a non-empty pkg and name
	}
	name := t[dot+1:]
	return strings.HasSuffix(name, "Request")
}

// IsGoArchiveEntryParamType reports whether a parameter type string is a Go
// archive-entry type that can only be obtained by opening an untrusted archive
// — `*zip.File` (archive/zip) or `*tar.Header` (archive/tar).
//
// You never construct one of these yourself in normal flow; the only way to
// hold a `*zip.File` / `*tar.Header` is to iterate the entries of an archive a
// caller handed you, so every field on it (`.Name`, `.Linkname`) is
// attacker-controlled archive metadata. A per-entry extractor helper
//
//	func extractEntry(dest string, f *zip.File) {
//		fpath := filepath.Join(dest, f.Name) // attacker-controlled
//		out, _ := os.Create(fpath)           // zip-slip: CWE-22
//	}
//
// is the dominant real-world (refactored) shape of zip-slip / tar-slip. The
// existing catalog sources key on the OpenReader/NewReader/Next CALL and so
// miss this param-typed form; seeding the parameter itself as a source closes
// the gap. This is exactly how CodeQL models archive entries.
//
// The match is conservative: it requires the `zip.`/`tar.` package qualifier
// (after stripping a leading `*`) so a local struct named `File` or `Header` is
// never auto-tainted. Unlike the gRPC `...Request` predicate, the type alone is
// an unambiguous external-origin signal, so the caller does NOT gate it on a
// leading context.Context parameter.
func IsGoArchiveEntryParamType(typeName string) bool {
	t := strings.TrimPrefix(typeName, "*")
	switch t {
	case "zip.File", "tar.Header":
		return true
	}
	return false
}

// IsGoGraphQLResolverReceiver reports whether a receiver type name looks like a
// gqlgen-generated GraphQL resolver — the type names gqlgen emits end in
// "Resolver" (e.g. "queryResolver", "mutationResolver", "*Resolver").
//
// gqlgen passes a GraphQL field's client-supplied arguments directly as typed
// method parameters after the leading context.Context:
//
//	func (r *queryResolver) User(ctx context.Context, id string) (*model.User, error)
//
// Here `id` is the client-controlled GraphQL argument. Those scalar/struct args
// are taint sources but were not modeled (only the graphql.GetFieldContext(...)
// .Args helper path was). The caller seeds non-context resolver args once the
// receiver is confirmed to be a resolver and the first param is context.Context.
func IsGoGraphQLResolverReceiver(receiverType string) bool {
	t := strings.TrimPrefix(receiverType, "*")
	// Use the final path/struct component so "*model.queryResolver" matches.
	if dot := strings.LastIndex(t, "."); dot >= 0 {
		t = t[dot+1:]
	}
	return strings.HasSuffix(t, "Resolver")
}
