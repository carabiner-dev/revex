// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/carabiner-dev/revex/pkg/fix"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
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
	FixGoVulnCheckPurl bool
	GoVulnCheck        struct {
		ProductID string
		Purl      string
	}
}

func (o *Options) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&o.GoVulnCheck.ProductID, "gvc-product-id", "", "ID to use in govulncheck's invalid VEX products",
	)
	cmd.PersistentFlags().StringVar(
		&o.GoVulnCheck.Purl, "gvc-product-purl", "", "package URL to use in govulncheck's invalid VEX products (or ID if it's a purl)",
	)
	cmd.PersistentFlags().BoolVar(
		&o.FixGoVulnCheckPurl, "gvc-fix-purls", true, "Fix weird purls in govulncheck",
	)
}

// Execute builds the command
func Execute() error {
	opts := Options{
		FixGoVulnCheckPurl: false,
		GoVulnCheck: struct {
			ProductID string
			Purl      string
		}{},
	}

	var rootCmd = &cobra.Command{
		Short:             fmt.Sprintf("%s: correct VEX documents", appname),
		Long:              fmt.Sprintf("%s: correct VEX documents", appname),
		Use:               appname,
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
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

			var correctors = []fix.Corrector{}

			if opts.FixGoVulnCheckPurl {
				correctors = append(correctors, fix.WithFixVulncheckPurls())
			}

			if opts.GoVulnCheck.ProductID != "" {
				prod := &vex.Component{
					ID:          opts.GoVulnCheck.ProductID,
					Identifiers: map[vex.IdentifierType]string{},
				}

				if opts.GoVulnCheck.Purl != "" {
					prod.Identifiers[vex.PURL] = opts.GoVulnCheck.Purl
				}
				correctors = append(correctors, fix.WithFixVulncheckProducts(prod))
			}

			fixer.CorrectStream(
				os.Stdin, os.Stdout,
				correctors...,
			)
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
