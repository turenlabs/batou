package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

func (c *ZigCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- Path normalization ---
		{
			ID:          "zig.fs.path.normalize",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.normalize\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.normalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path normalization (resolves .. and . components)",
		},
		{
			ID:          "zig.fs.path.resolve",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.resolve\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.resolve",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path resolution against base directory",
		},

		// --- Path canonicalization ---
		{
			ID:          "zig.fs.Dir.realpathAlloc",
			Language:    rules.LangZig,
			Pattern:     `\.realpathAlloc\s*\(`,
			ObjectType:  "std.fs.Dir",
			MethodName:  "Dir.realpathAlloc",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path canonicalization (resolves symlinks, prevents traversal)",
		},
		{
			ID:          "zig.fs.realpathAlloc",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.realpathAlloc\s*\(`,
			ObjectType:  "std.fs",
			MethodName:  "std.fs.realpathAlloc",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Absolute path canonicalization with symlink resolution",
		},

		// --- String sanitization ---
		{
			ID:          "zig.mem.trim",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.trim\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.trim",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Memory trim operation (strips specified bytes)",
		},
		{
			ID:          "zig.mem.splitSequence",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.splitSequence\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.splitSequence",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Split by sequence for structured parsing",
		},

		// --- Numeric conversion ---
		{
			ID:          "zig.fmt.parseInt",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.parseInt\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.parseInt",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "String to integer parsing (restricts to numeric values)",
		},
		{
			ID:          "zig.fmt.parseFloat",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.parseFloat\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.parseFloat",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "String to float parsing (restricts to numeric values)",
		},
		{
			ID:          "zig.fmt.parseUnsigned",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.parseUnsigned\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.parseUnsigned",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "String to unsigned integer parsing",
		},

		// --- Path component extraction ---
		{
			ID:          "zig.fs.path.basename",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.basename\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract file name component (strips directory traversal)",
		},

		// --- URL encoding ---
		{
			ID:          "zig.Uri.escapeString",
			Language:    rules.LangZig,
			Pattern:     `std\.Uri\.escapeString\s*\(`,
			ObjectType:  "std.Uri",
			MethodName:  "std.Uri.escapeString",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHTMLOutput},
			Description: "URI string escaping for safe URL construction",
		},
	}
}
