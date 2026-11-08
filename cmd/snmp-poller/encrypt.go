package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// encryptCmd implements -encrypt: it prints one credential encrypted
// (~~HEX~~) for the configuration file, with the key keyPath or, when empty,
// <data_dir of configPath>/key.dat. The value is the single argument, else
// the first line of piped stdin, else typed twice at the terminal without
// echo (the safest: arguments are visible in shell history and ps).
func encryptCmd(configPath, keyPath string, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintf(stderr, "encrypt: expected one value, got %d arguments (quote a value with spaces; flags go before it)\n", len(args))
		return 2
	}
	if keyPath == "" {
		dataDir, err := config.DataDir(configPath)
		if err != nil {
			fmt.Fprintf(stderr, "encrypt: %v (use -key to give the key file)\n", err)
			return 2
		}
		keyPath = config.KeyPath(dataDir)
	}

	var value string
	var err error
	switch fd := int(stdin.Fd()); {
	case len(args) == 1:
		value = args[0]
	case term.IsTerminal(fd):
		value, err = prompt(fd, stderr)
	default:
		value, err = readLine(stdin)
	}
	if err != nil {
		fmt.Fprintf(stderr, "encrypt: %v\n", err)
		return 1
	}

	enc, created, err := config.EncryptValue(keyPath, value)
	if err != nil {
		fmt.Fprintf(stderr, "encrypt: %v\n", err)
		return 1
	}
	if created {
		fmt.Fprintf(stderr, "key generated: %s (back it up: encrypted values cannot be read without it)\n", keyPath)
	}
	fmt.Fprintln(stdout, enc)
	return 0
}

// prompt reads the value twice from the terminal, without echo.
func prompt(fd int, stderr io.Writer) (string, error) {
	read := func(label string) (string, error) {
		fmt.Fprint(stderr, label)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		return string(b), err
	}
	v, err := read("Value to encrypt: ")
	if err != nil {
		return "", err
	}
	again, err := read("Again: ")
	if err != nil {
		return "", err
	}
	if v != again {
		return "", errors.New("the values do not match")
	}
	return v, nil
}

// readLine reads the value from piped input: the first line, without its
// line ending.
func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
