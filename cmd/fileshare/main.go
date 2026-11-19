package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"fileshare/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "fileshare:", err)
		os.Exit(1)
	}
}
