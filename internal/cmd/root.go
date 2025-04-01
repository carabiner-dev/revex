// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"

	"github.com/carabiner-dev/revex/pkg/fix"
)

const appname = "revex"

type commandLineOptions struct {
	logLevel string
}

var commandLineOpts = commandLineOptions{}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}

type Options struct {
	Path               string
	FixGoVulnCheckPurl bool
	FilterStatuses     []string
	GoVulnCheck        struct {
		ProductID string
		Hash      string
		Purl      string
	}
}

func (o *Options) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&o.Path, "path", "", "Path to the VEX file to correct",
	)
	cmd.PersistentFlags().StringVar(
		&o.GoVulnCheck.ProductID, "gvc-product-id", "", "ID to use in govulncheck's invalid VEX products",
	)
	cmd.PersistentFlags().StringVar(
		&o.GoVulnCheck.Purl, "gvc-product-purl", "", "package URL to use in govulncheck's invalid VEX products (or ID if it's a purl)",
	)
	cmd.PersistentFlags().StringVar(
		&o.GoVulnCheck.Hash, "gvc-product-hash", "", "hash to use in corrected VEX product",
	)
	cmd.PersistentFlags().BoolVar(
		&o.FixGoVulnCheckPurl, "gvc-fix-purls", true, "Fix weird purls in govulncheck",
	)
	cmd.PersistentFlags().StringSliceVar(
		&o.FilterStatuses, "filter-status", nil, "filter out statements with statuses other than this",
	)
}

// Execute builds the command
func Execute() error {
	opts := Options{
		FixGoVulnCheckPurl: false,
		GoVulnCheck: struct {
			ProductID string
			Hash      string
			Purl      string
		}{},
	}

	rootCmd := &cobra.Command{
		Short: fmt.Sprintf("%s: correct VEX documents", appname),
		Long: `
revex: A simple tool to correct know errors in VEX documents.

This tool collects hacks to address problems know in the output of common tools.
It is designed to receive a piped VEX document in its input, apply a couple of
fixes and output the correct document.

The fixes are enabled through the command line, they flags are prefixed with 
a string that indicates which tool each fix is intended to work with.

--gcv Fixes (govulncheck)

The govulnchecl security tool can output native vex documents but it has two
problems: It creates invalid product entries and it generates package urls 
that are not compatible with the way most tools expect. To correct them:

  --gvc-fix-purls (bool)
    When enabled, revex will look for the percent-escaped purls from govulncheck
    and rewrite them to their unescaped equivalents.

  --gvc-product-id / --gvc-product-purl
    This flag rewrites the string "Unknown Product" with the supplied id. If
	the ID is a package URL it will also be populated int the product identifier.
	If the prodouct ID is not a package URL, you can still set it using the
	--gvc-product-purl flag.

`,
		Use: fmt.Sprintf("%s [flags] document.openvex.json", appname),
		Example: `
The simplest way to use revex is to pipe the VEX output of the tool you need
to correct through it, for example:

  govulncheck -format openvex ./... | \
      revex --gvc-fix-purls --gvc-product-id="pkg:generic/myapp@1.0.0"
`,
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.Path == "" && len(args) > 0 {
				opts.Path = args[0]
			}
			if opts.Path == "" {
				fi, err := os.Stdin.Stat()
				if err != nil {
					return fmt.Errorf("checking stdin for data: %w", err)
				}
				if (fi.Mode() & os.ModeCharDevice) != 0 {
					return errors.New("document path not specified")
				}
				opts.Path = "-"
			}

			if opts.GoVulnCheck.Purl == "" {
				if strings.HasPrefix(opts.GoVulnCheck.ProductID, "pkg:golang") {
					opts.GoVulnCheck.Purl = opts.GoVulnCheck.ProductID
				}
			}

			if opts.GoVulnCheck.ProductID == "" {
				opts.GoVulnCheck.ProductID = opts.GoVulnCheck.Purl
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			//
			fixer := fix.Fixer{}

			correctors := []fix.Corrector{}

			if opts.FixGoVulnCheckPurl {
				correctors = append(correctors, fix.WithFixVulncheckPurls())
			}

			if opts.GoVulnCheck.ProductID != "" || opts.GoVulnCheck.Hash != "" {
				prod := &vex.Component{
					ID:          opts.GoVulnCheck.ProductID,
					Identifiers: map[vex.IdentifierType]string{},
					Hashes:      map[vex.Algorithm]vex.Hash{},
				}

				if opts.GoVulnCheck.Purl != "" {
					prod.Identifiers[vex.PURL] = opts.GoVulnCheck.Purl
				}

				if opts.GoVulnCheck.Hash != "" {
					algo, val, ok := strings.Cut(opts.GoVulnCheck.Hash, ":")
					if ok {
						// TODO(puerco): Check hash algo rithm
						prod.Hashes[vex.Algorithm(algo)] = vex.Hash(val)
					}
				}
				correctors = append(correctors, fix.WithFixVulncheckProducts(prod))
			}

			if len(opts.FilterStatuses) > 0 {
				correctors = append(correctors, fix.WithFilterStatus(opts.FilterStatuses))
			}

			var in io.Reader
			var err error
			if opts.Path == "-" {
				in = os.Stdin
			} else {
				in, err = os.Open(opts.Path)
				if err != nil {
					return fmt.Errorf("opening vex file: %w", err)
				}
			}

			if err := fixer.CorrectStream(in, os.Stdout, correctors...); err != nil {
				return err
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level", "info", fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)

	opts.AddFlags(rootCmd)

	return rootCmd.Execute()
}
