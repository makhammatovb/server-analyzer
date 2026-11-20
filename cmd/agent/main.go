// Command fleetguard-agent is the FleetGuard host agent. It has two
// subcommands: enrol, which redeems a one-time token, and run, which sends
// heartbeats. There is deliberately no subcommand, flag, file or socket that
// acknowledges, approves or silences anything: an attacker with root on this
// host must not be able to confirm the alert announcing their own intrusion.
// The agent reports only; it never kills a process, edits an account or
// changes a firewall rule, and it never listens on a port.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/makhammatovb/fleetguard/internal/agent"
)

const (
	defaultConfigPath = "/etc/fleetguard/agent.yaml"
	// tokenEnv carries the enrolment token without putting it on the command
	// line, where any local user could read it from ps.
	tokenEnv = "FG_ENROL_TOKEN" //nolint:gosec // the name of an environment variable, not a credential
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stderr))
}

func realMain(args []string, errw io.Writer) int {
	if len(args) == 0 {
		usage(errw)
		return 2
	}
	var err error
	switch args[0] {
	case "enrol":
		err = enrolCmd(args[1:], errw)
	case "run":
		err = runCmd(args[1:], errw)
	case "-h", "--help", "help":
		usage(errw)
		return 0
	default:
		_, _ = fmt.Fprintf(errw, "fleetguard-agent: unknown command %q\n", args[0])
		usage(errw)
		return 2
	}
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, context.Canceled):
		return 0 // stopped by a signal
	default:
		_, _ = fmt.Fprintf(errw, "fleetguard-agent: %v\n", err)
		return 1
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: FG_ENROL_TOKEN=<token> fleetguard-agent enrol [--config=<path>]\n       fleetguard-agent run [--config=<path>]")
}

func loadConfig(fs *flag.FlagSet, args []string) (agent.Config, error) {
	path := fs.String("config", defaultConfigPath, "path to the agent config file")
	stateDir := fs.String("state-dir", agent.DefaultStateDir, "directory holding the agent's identity")
	if err := fs.Parse(args); err != nil {
		return agent.Config{}, err
	}
	cfg, err := agent.LoadConfig(*path)
	if err != nil {
		return agent.Config{}, err
	}
	cfg.StateDir = *stateDir
	return cfg, nil
}

func enrolCmd(args []string, errw io.Writer) error {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(errw)
	token := fs.String("token", "", "one-time enrolment token; prefer the "+tokenEnv+" environment variable, since argv is visible to every local user in ps")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if *token == "" {
		*token = os.Getenv(tokenEnv)
	}
	if *token == "" {
		return errors.New("enrol: a token is required: set " + tokenEnv + " (or pass --token)")
	}
	host, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("enrol: read hostname: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	id, err := agent.EnrolOrResume(ctx, cfg, *token, host, agent.Version)
	if errors.Is(err, agent.ErrAlreadyEnrolled) {
		fmt.Println("already enrolled; nothing to do")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Printf("enrolled as server %s\n", id.ServerID)
	return nil
}

func runCmd(args []string, errw io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(errw)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx, cfg, time.Now)
}
