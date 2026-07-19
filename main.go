package main

import (
	"os"

	"github.com/concrnt/concrnt-policy-compiler/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
