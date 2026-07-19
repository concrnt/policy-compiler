package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/concrnt/concrnt-policy-compiler/internal/compiler"
)

var buildCmd = &cobra.Command{
	Use:   "build <file|dir>...",
	Short: "Compile .rego policies and write <name>.json for each",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		outdir, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}
		stdout, err := cmd.Flags().GetBool("stdout")
		if err != nil {
			return err
		}

		sources, err := collectSources(args)
		if err != nil {
			return err
		}

		failed := 0
		for _, src := range sources {
			doc, err := compiler.CompileFile(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				failed++
				continue
			}
			data, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				return fmt.Errorf("%s: %w", src, err)
			}
			data = append(data, '\n')

			if stdout {
				os.Stdout.Write(data)
				continue
			}
			if err := os.MkdirAll(outdir, 0o755); err != nil {
				return err
			}
			out := filepath.Join(outdir, doc.Name+".json")
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}
			fmt.Printf("%s -> %s\n", src, out)
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d policies failed to compile", failed, len(sources))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(buildCmd)

	buildCmd.Flags().StringP("output", "o", ".", "output directory")
	buildCmd.Flags().Bool("stdout", false, "write compiled JSON to stdout instead of files")
}
