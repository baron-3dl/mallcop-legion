package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

func runConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	chartPath := fs.String("chart", defaultChart, "Path to the legion chart TOML")

	if err := fs.Parse(args); err != nil {
		return err
	}

	data, err := os.ReadFile(*chartPath)
	if err != nil {
		return fmt.Errorf("reading chart %s: %w", *chartPath, err)
	}

	// Validate: parse as generic TOML to catch syntax errors.
	var v interface{}
	if err := toml.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("invalid TOML in %s: %w", *chartPath, err)
	}

	fmt.Printf("Chart: %s\n", *chartPath)
	fmt.Printf("Config OK\n\n")
	fmt.Printf("%s", data)
	return nil
}
