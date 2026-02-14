package framework

import "github.com/turenio/gtss/internal/rules"

func init() {
	// Rails rules
	rules.Register(&RailsHTMLSafe{})
	rules.Register(&RailsRenderInline{})
	rules.Register(&RailsConstantize{})
	rules.Register(&RailsPermitBang{})
	rules.Register(&RailsMisconfig{})
	rules.Register(&RailsSQLParams{})

	// Laravel rules
	rules.Register(&LaravelDBRaw{})
	rules.Register(&LaravelBladeUnescaped{})
	rules.Register(&LaravelMassAssignment{})
	rules.Register(&LaravelDebugMode{})
	rules.Register(&LaravelAppKey{})
	rules.Register(&LaravelUnserialize{})
	rules.Register(&LaravelStorageTraversal{})

	// React rules
	rules.Register(&ReactSSRUnsanitized{})
	rules.Register(&ReactRefInnerHTML{})
	rules.Register(&ReactPropSpreading{})
	rules.Register(&ReactDynamicScriptIframe{})

	// Tauri rules
	rules.Register(&TauriShellAllowlist{})
	rules.Register(&TauriFilesystemScope{})
	rules.Register(&TauriIPCInjection{})
	rules.Register(&TauriProtocolHandler{})
	rules.Register(&TauriCSPMissing{})
	rules.Register(&TauriWindowExposure{})
	rules.Register(&TauriDangerousPerms{})
	rules.Register(&TauriInsecureUpdater{})
}
