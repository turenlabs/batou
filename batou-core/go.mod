module github.com/turenlabs/batou-core

go 1.25.5

require (
	github.com/gofrs/flock v0.13.0
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82
	github.com/turenlabs/batou-rules v0.0.0
	golang.org/x/tools v0.45.0
)

require (
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

replace github.com/turenlabs/batou-rules => ../batou-rules
