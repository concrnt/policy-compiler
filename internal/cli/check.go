package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/concrnt/concrnt-policy-compiler/internal/compiler"
)

var checkCmd = &cobra.Command{
	Use:   "check <file|dir>...",
	Short: "Compile without writing output; exits non-zero on any error",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sources, err := collectSources(args)
		if err != nil {
			return err
		}

		failed := 0
		for _, src := range sources {
			if _, err := compiler.CompileFile(src); err != nil {
				fmt.Fprintln(os.Stderr, err)
				failed++
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d policies failed to compile", failed, len(sources))
		}
		fmt.Printf("%d policies OK\n", len(sources))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
