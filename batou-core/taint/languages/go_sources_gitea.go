package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// giteaGoSources holds Gitea web-context user-input sources not modeled in the
// shared go_sources.go literal. Appended to (*GoCatalog).Sources(). The
// ObjectType matches the existing Gitea context entries; the astflow/ssaflow
// matcher already has a Gitea/Macaron receiver case so `ctx`/`c` resolve.
// IDs verified collision-free against the existing go.gitea.* sources.
func giteaGoSources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- Form coercion accessors not yet modeled ---
		{ID: "go.gitea.context.form_trim", Category: taint.SrcUserInput, Language: rules.LangGo, Pattern: `\.FormTrim\s*\(`, ObjectType: "code.gitea.io/gitea/modules/context.Context", MethodName: "FormTrim", Description: "Gitea Context.FormTrim — whitespace-trimmed form/query parameter (user-supplied, still raw string)", Assigns: "return"},
		{ID: "go.gitea.context.form_optionalbool", Category: taint.SrcUserInput, Language: rules.LangGo, Pattern: `\.FormOptionalBool\s*\(`, ObjectType: "code.gitea.io/gitea/modules/context.Context", MethodName: "FormOptionalBool", Description: "Gitea Context.FormOptionalBool — coerced optional boolean form parameter (user-influenced before coercion)", Assigns: "return"},
		{ID: "go.gitea.context.form_stringint64s", Category: taint.SrcUserInput, Language: rules.LangGo, Pattern: `\.FormStringInt64s\s*\(`, ObjectType: "code.gitea.io/gitea/modules/context.Context", MethodName: "FormStringInt64s", Description: "Gitea Context.FormStringInt64s — repeated form parameter coerced to []int64 (user-supplied list)", Assigns: "return"},

		// --- Upload sources ---
		{ID: "go.gitea.context.req_formfile", Category: taint.SrcUserInput, Language: rules.LangGo, Pattern: `\.Req\.FormFile\s*\(`, ObjectType: "code.gitea.io/gitea/modules/context.Context", MethodName: "Req.FormFile", Description: "Gitea Context.Req.FormFile — uploaded multipart file + *FileHeader (filename and contents are user-supplied)", Assigns: "return"},
		{ID: "go.gitea.context.uploadstream", Category: taint.SrcUserInput, Language: rules.LangGo, Pattern: `\.UploadStream\s*\(`, ObjectType: "code.gitea.io/gitea/modules/context.Context", MethodName: "UploadStream", Description: "Gitea Context.UploadStream — request upload stream reader (raw user-supplied bytes)", Assigns: "return"},

		// NOTE: the URL-derived Repo context FIELD reads (ctx.Repo.TreePath /
		// BranchName / CommitID) were evaluated and deliberately NOT added. The
		// current Go taint engine is field-insensitive on a shared receiver, so
		// tainting one ctx.Repo.* field taints the whole ctx.Repo object — which
		// then flags every unrelated same-origin ctx.Repo.RepoLink redirect as a
		// false open-redirect (verified: 10 FPs in routers/web/repo on Gitea).
		// Re-introduce these only once the engine tracks per-field taint.
	}
}
