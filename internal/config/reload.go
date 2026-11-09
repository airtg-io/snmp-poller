package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// fileData is a file read by Load, with its content.
type fileData struct {
	path string
	data []byte
}

// Path returns the main configuration file, "" when the configuration was
// not read from a file.
func (c *Config) Path() string { return c.files[0].path }

// Fingerprint identifies the content of every file of the configuration
// (main file, include directory, capabilities) as read by Load, and as
// rewritten by Seal since.
func (c *Config) Fingerprint() string {
	var files []fileData
	for _, f := range c.files {
		files = append(files, fileData{f.path, f.source})
	}
	return fingerprint(append(files, c.capFiles...))
}

// DiskFingerprint reads the files of the configuration again, from the
// same main file and directories, and returns their fingerprint: it
// differs from Fingerprint when a file was changed, added or removed.
func (c *Config) DiskFingerprint() (string, error) {
	path := c.Path()
	if path == "" {
		return "", errors.New("configuration not read from a file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	files := []fileData{{path, data}}
	for _, dir := range []string{c.Global.IncludeDir, c.Global.CapabilitiesDir} {
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		for _, e := range entries {
			if !isYAMLFile(e) {
				continue
			}
			p := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				return "", err
			}
			files = append(files, fileData{p, data})
		}
	}
	return fingerprint(files), nil
}

func fingerprint(files []fileData) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00%d\x00", f.path, len(f.data))
		h.Write(f.data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// DiscoveryKey identifies what the discovery of the device depends on: the
// agent (address, port, transport), the SNMP version, credentials and
// context, the Vault path and the capabilities. A device whose key changes
// must be discovered again; any other change (intervals, timeouts,
// sinks, trace, ...) applies without discovery.
func (s *DeviceSpec) DiscoveryKey() string {
	h := sha256.New()
	n := s.SNMP
	fmt.Fprintf(h, "%q %d %q %q %q %q %q %q %q %q %q %q %q %q\n", s.Address, s.Port, s.Transport,
		n.Version, n.Community.Reveal(), n.Username, n.SecurityLevel, n.AuthProtocol, n.AuthPassword.Reveal(),
		n.PrivProtocol, n.PrivPassword.Reveal(), n.ContextName, n.ContextEngineID, s.VaultPath)
	for _, c := range s.Capabilities {
		fmt.Fprintln(h, c.Fingerprint())
	}
	return hex.EncodeToString(h.Sum(nil))
}
