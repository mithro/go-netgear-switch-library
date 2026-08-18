package main

import (
	"context"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// main runs the production server: BuildServer wired to the process's real
// environment (nil -> os.LookupEnv), over stdio -- mirroring server.py's
// `main()`: `build_server().run()`.
func main() {
	server := BuildServer(nil)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "gngsw-mcp: %s\n", err)
		os.Exit(1)
	}
}
