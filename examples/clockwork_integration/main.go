// Example: how a Clockwork-shaped executor builds a Profile programmatically
// (rather than from YAML) and applies it to an *exec.Cmd for an isolated
// task run.
//
// Run:
//
//	go run ./examples/clockwork_integration -workspace /tmp/cw-task-1
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
	workspace := flag.String("workspace", "", "absolute path to the task workspace")
	allowNet := flag.Bool("net", false, "allow outbound network")
	allowLoopback := flag.Bool("allow-loopback", false, "allow 127.0.0.0/8 and ::1 while --net=false")
	flag.Parse()

	if *workspace == "" {
		flag.Usage()
		os.Exit(2)
	}

	p := sandbox.Profile{
		ID:          "clockwork-task",
		Description: "Clockwork executor task — workspace write only, no network unless --net.",
		FS: sandbox.FSSpec{
			Write: []string{"workspace"},
			Read:  []string{"workspace"},
			Deny:  []string{"${HOME}/.ssh", "${HOME}/.aws"},
		},
		Net:           *allowNet,
		AllowLoopback: *allowLoopback,
		Subprocess:    true,
	}

	cmd := exec.Command("/bin/sh", "-c", "echo running in sandbox; ls -la "+*workspace)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cleanup, err := sandbox.Apply(cmd, p, *workspace)
	if err != nil {
		log.Fatalf("apply sandbox: %v", err)
	}
	defer cleanup()

	fmt.Printf("running task under profile %q (net=%v allow_loopback=%v)\n", p.ID, p.Net, p.AllowLoopback)
	if err := cmd.Run(); err != nil {
		log.Fatalf("task failed: %v", err)
	}
}
