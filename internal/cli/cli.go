package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/concrnt/concrnt-policy-compiler/internal/compiler"
)

const usage = `concrnt-policy-compiler compiles Rego policies into concrnt policy documents.

Usage:
  concrnt-policy-compiler build [-o outdir] [-stdout] <file|dir>...
      Compile .rego files and write <name>.json for each policy.
  concrnt-policy-compiler check <file|dir>...
      Compile without writing output; exits non-zero on any error.
`

func Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "build":
		return runBuild(args[1:])
	case "check":
		return runCheck(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// collectSources expands file and directory arguments into a list of .rego files.
func collectSources(args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no input files given")
	}
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

func runBuild(args []string) int {
	flags := flag.NewFlagSet("build", flag.ExitOnError)
	outdir := flags.String("o", ".", "output directory")
	stdout := flags.Bool("stdout", false, "write compiled JSON to stdout instead of files")
	flags.Parse(args)

	sources, err := collectSources(flags.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	failed := false
	for _, src := range sources {
		doc, err := compiler.CompileFile(src)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
			continue
		}
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", src, err)
			failed = true
			continue
		}
		data = append(data, '\n')

		if *stdout {
			os.Stdout.Write(data)
			continue
		}
		if err := os.MkdirAll(*outdir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		out := filepath.Join(*outdir, doc.Name+".json")
		if err := os.WriteFile(out, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("%s -> %s\n", src, out)
	}
	if failed {
		return 1
	}
	return 0
}

func runCheck(args []string) int {
	sources, err := collectSources(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	failed := false
	for _, src := range sources {
		if _, err := compiler.CompileFile(src); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
	}
	if failed {
		return 1
	}
	fmt.Printf("%d policies OK\n", len(sources))
	return 0
}
