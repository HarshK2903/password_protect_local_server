package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"fileshare/internal/app"
	"fileshare/internal/telemetry"
)

var Version = "dev"

const usage = `Fileshare — a private, read-only HTTPS file server

Usage:
  fileshare share DIRECTORY --cert server.crt --key server.key [options]
  fileshare version

Authentication and read-only access are always enabled. The default bind address
is 127.0.0.1. Select a specific LAN address with --bind to share with other devices.
Use "fileshare share --help" for all options.
`

func Run(ctx context.Context, args []string, input *os.File, output, errOutput io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprint(output, usage)
		return err
	}
	switch args[0] {
	case "version", "--version":
		_, err := fmt.Fprintf(output, "fileshare %s\n", Version)
		return err
	case "share":
		c, err := ParseShare(args[1:], errOutput)
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		if err != nil {
			return err
		}
		c, err = app.Prepare(c)
		if err != nil {
			return err
		}
		password, err := ReadPassword(c.PasswordFile, input, errOutput)
		if err != nil {
			return err
		}
		a, err := app.New(c, password, telemetry.Logger(errOutput))
		clear(password)
		if err != nil {
			return err
		}
		return a.Run(ctx)
	default:
		return fmt.Errorf("unknown command %q; use fileshare --help", args[0])
	}
}
