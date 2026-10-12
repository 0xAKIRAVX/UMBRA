//go:build tools

// keeps golang.org/x/mobile/cmd/gobind in the module graph for gomobile bind
package tools

import _ "golang.org/x/mobile/cmd/gobind"
