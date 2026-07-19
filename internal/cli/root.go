package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "concrnt-policy-compiler",
	Short:         "Compile Rego policies into concrnt policy documents",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// collectSources expands file and directory arguments into a list of .rego files.
func collectSources(args []string) ([]string, error) {
	var sources []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			sources = append(sources, arg)
			continue
		}
		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".rego") {
				sources = append(sources, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no .rego files found")
	}
	return sources, nil
}
