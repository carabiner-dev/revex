// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/openvex/go-vex/pkg/vex"
	purl "github.com/package-url/packageurl-go"
)

type FixPack struct {
	Params []string
	Func   func()
}

func WithFixVulncheckPurls() Corrector {
	return func(doc *vex.VEX) error {
		if doc == nil {
			return fmt.Errorf("vex document is nil")
		}

		// Only apply this fix if tooling is vulncheck
		if !strings.HasPrefix(doc.Tooling, "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck") {
			return nil
		}

		// Cycle and correct
		for i := range doc.Statements {
			for j := range doc.Statements[i].Products {
				for k := range doc.Statements[i].Products[j].Subcomponents {
					badpurl := doc.Statements[i].Products[j].Subcomponents[k].ID
					// Cheapo Heuristics to check if the purl is affected
					if !strings.HasPrefix(badpurl, "pkg:golang/") || !strings.Contains(badpurl, "%") {
						continue
					}
					p, err := purl.FromString(badpurl)
					if err != nil {
						return fmt.Errorf("parsing govulncheck purl %q: %w", badpurl, err)
					}
					nname, err := url.PathUnescape(p.Name)
					if err != nil {
						return fmt.Errorf("deconding url escaped code: %w", err)
					}
					newpurl := fmt.Sprintf("pkg:golang/%s@%s", nname, p.Version)
					doc.Statements[i].Products[j].Subcomponents[k].ID = newpurl
				}
			}
		}
		return nil
	}
}

// WithFixVulncheckProducts
func WithFixVulncheckProducts(product *vex.Component) Corrector {
	return func(doc *vex.VEX) error {
		if doc == nil {
			return fmt.Errorf("vex document is nil")
		}
		for i := range doc.Statements {
			for j := range doc.Statements[i].Products {
				if doc.Statements[i].Products[j].ID == "Unknown Product" {
					doc.Statements[i].Products[j].ID = product.ID
					doc.Statements[i].Products[j].Hashes = product.Hashes
					doc.Statements[i].Products[j].Supplier = product.Supplier
					doc.Statements[i].Products[j].Identifiers = product.Identifiers
				}
			}
		}
		return nil
	}
}

// WithFixVulncheckProducts  S ~[]E, E any]
func WithFilterStatus[T ~[]string](statuses T) Corrector {
	return func(doc *vex.VEX) error {
		if doc == nil {
			return fmt.Errorf("vex document is nil")
		}
		statements := doc.Statements
		doc.Statements = []vex.Statement{}
		for i := range statements {
			if slices.Contains(statuses, string(statements[i].Status)) {
				doc.Statements = append(doc.Statements, statements[i])
			}
		}
		return nil
	}
}
