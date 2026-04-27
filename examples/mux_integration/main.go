// Example: how a Mux-shaped consumer wires a profile loaded from YAML
// onto an *exec.Cmd before spawning a CLI provider.
//
// Run:
//
//	go run ./examples/mux_integration -profile testdata/workspace-only.yaml -workspace /tmp/ws
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/hollis-labs/go-sandbox/sandbox"
)

func main() {
	profilePath := flag.String("profile", "", "path to a sandbox profile YAML file")
	workspace := flag.String("workspace", "", "absolute path to the session workspace")
	command := flag.String("cmd", "/bin/sh", "command to spawn under the sandbox")
	flag.Parse()

	if *profilePath == "" || *workspace == "" {
		flag.Usage()
		os.Exit(2)
	}

	p, err := sandbox.LoadProfile(*profilePath)
	if err != nil {
		log.Fatalf("load profile: %v", err)
	}

	cmd := exec.Command(*command, flag.Args()...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	cleanup, err := sandbox.Apply(cmd, p, *workspace)
	if err != nil {
		log.Fatalf("apply sandbox: %v", err)
	}
	defer cleanup()

	fmt.Printf("running %q under sandbox profile %q (workspace=%s)\n",
		*command, p.ID, *workspace)

	if err := cmd.Run(); err != nil {
		log.Fatalf("command failed: %v", err)
	}
}
