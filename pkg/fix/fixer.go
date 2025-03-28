// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"fmt"
	"io"

	"github.com/openvex/go-vex/pkg/vex"
)

type Fixer struct {
}

type Corrector func(*vex.VEX) error

// CorrectStream reads a VEX document from the reader r, applies
// some corrections and rewrites it on writer w.
func (fix *Fixer) CorrectStream(r io.Reader, w io.Writer, fncs ...Corrector) error {
	// Read doc
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading data: %w", err)
	}
	doc, err := vex.Parse(data)
	if err != nil {
		return fmt.Errorf("parsing vex data: %w", err)
	}

	// Now apply all the correctors
	for _, fn := range fncs {
		if err := fn(doc); err != nil {
			return err
		}
	}

	return doc.ToJSON(w)
}
