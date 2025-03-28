// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/carabiner-dev/revex/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Printf("! Error: %v", err)
	}
}
