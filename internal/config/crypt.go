package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// KeyFile is the name, in the data directory, of the key that encrypts the
// credentials written in the configuration file.
const KeyFile = "key.dat"

const keySize = 32 // AES-256

// encryptedPattern matches an encrypted secret: ~~, hex digit pairs, ~~.
var encryptedPattern = regexp.MustCompile(`^~~(?:[0-9A-Fa-f]{2})+~~$`)

// KeyPath returns the path of the key file in dataDir.
func KeyPath(dataDir string) string { return filepath.Join(dataDir, KeyFile) }

func loadKey(path string) ([]byte, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(k) != keySize {
		return nil, fmt.Errorf("%s: invalid key (%d bytes, want %d)", path, len(k), keySize)
	}
	return k, nil
}

// ensureKey loads the key at path, generating it first when it does not
// exist. created reports whether it was generated.
func ensureKey(path string) (key []byte, created bool, err error) {
	key, err = loadKey(path)
	if !errors.Is(err, fs.ErrNotExist) {
		return key, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, false, err
	}
	key = make([]byte, keySize)
	rand.Read(key)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Created concurrently by another process: use that one.
		key, err = loadKey(path)
		return key, false, err
	}
	if err != nil {
		return nil, false, err
	}
	_, err = f.Write(key)
	if err2 := f.Sync(); err == nil {
		err = err2
	}
	if err2 := f.Close(); err == nil {
		err = err2
	}
	if err != nil {
		os.Remove(path)
		return nil, false, err
	}
	return key, true, nil
}

// encrypt returns ~~HEX~~ where HEX is the AES-256-GCM nonce, ciphertext and
// tag of plain.
func encrypt(key []byte, plain string) string {
	gcm := newGCM(key)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return "~~" + strings.ToUpper(hex.EncodeToString(sealed)) + "~~"
}

func decrypt(key []byte, s string) (string, error) {
	sealed, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(s, "~~"), "~~"))
	if err != nil {
		return "", err
	}
	gcm := newGCM(key)
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("encrypted credential is truncated")
	}
	n := gcm.NonceSize()
	plain, err := gcm.Open(nil, sealed[:n], sealed[n:], nil)
	if err != nil {
		return "", errors.New("cannot decrypt credential: it was encrypted with another key")
	}
	return string(plain), nil
}

func newGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // key size is checked by loadKey
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

// secrets returns every secret of one decoded configuration file, with its
// location in that file for error messages, including those of disabled
// devices.
func (c *Config) secrets() []namedSecret {
	var out []namedSecret
	add := func(name string, s *Secret) {
		if s.src.raw != "" {
			out = append(out, namedSecret{name, s})
		}
	}
	for i := range c.Devices {
		if s := c.Devices[i].SNMP; s != nil {
			p := fmt.Sprintf("devices[%d].snmp.", i)
			add(p+"community", &s.Community)
			add(p+"auth_password", &s.AuthPassword)
			add(p+"priv_password", &s.PrivPassword)
		}
	}
	for i := range c.Sinks {
		p := fmt.Sprintf("sinks[%d].", i)
		add(p+"token", &c.Sinks[i].Token)
		add(p+"password", &c.Sinks[i].Password)
	}
	if v := c.Vault; v != nil {
		add("vault.auth.token", &v.Auth.Token)
		add("vault.auth.secret_id", &v.Auth.SecretID)
		add("vault.auth.password", &v.Auth.Password)
	}
	return out
}

type namedSecret struct {
	name string
	*Secret
}

// resolveSecrets expands, decrypts and stores the clear-text value of every
// secret. The key is only read when a secret is encrypted.
func (c *Config) resolveSecrets() error {
	path := KeyPath(c.Global.DataDir)
	var key []byte
	getKey := func() ([]byte, error) {
		if key != nil {
			return key, nil
		}
		k, err := loadKey(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("credentials are encrypted but the key %s does not exist", path)
		}
		key = k
		return k, err
	}
	var errs []error
	for _, f := range c.files {
		for _, s := range f.doc.secrets() {
			if err := s.resolve(getKey); err != nil {
				errs = append(errs, inFile(f.path, fmt.Errorf("%s: %w", s.name, err)))
			}
		}
	}
	// Sinks are merged by value: take their resolved secrets.
	var resolved []Sink
	for _, f := range c.files {
		resolved = append(resolved, f.doc.Sinks...)
	}
	for i := range c.Sinks {
		c.Sinks[i].Token, c.Sinks[i].Password = resolved[i].Token, resolved[i].Password
	}
	return errors.Join(errs...)
}

// SealResult reports what Seal did.
type SealResult struct {
	KeyPath    string
	KeyCreated bool
	// Encrypted is the number of clear-text credentials encrypted, in
	// Files, the configuration files rewritten.
	Encrypted int
	Files     []string
}

// Seal makes sure the key exists, generating it when missing (even with
// nothing to encrypt: it is ready for later credentials and for -encrypt),
// and replaces every clear-text credential of the configuration files with
// its encrypted form. Only the credential values change:
// comments, layout and everything else are kept byte for byte. Each file is
// replaced atomically; a file that cannot be rewritten (e.g. read-only)
// does not prevent the others.
func (c *Config) Seal() (SealResult, error) {
	res := SealResult{KeyPath: KeyPath(c.Global.DataDir)}
	key, created, err := ensureKey(res.KeyPath)
	if err != nil {
		return res, fmt.Errorf("key: %w", err)
	}
	res.KeyCreated = created
	var errs []error
	for _, f := range c.files {
		n, err := f.seal(key)
		if err != nil {
			errs = append(errs, inFile(f.path, err))
		}
		if n > 0 {
			res.Encrypted += n
			res.Files = append(res.Files, f.path)
		}
	}
	return res, errors.Join(errs...)
}

// seal encrypts the clear-text credentials of one file and returns how
// many it encrypted.
func (f *configFile) seal(key []byte) (int, error) {
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	seen := map[[2]int]bool{} // a YAML alias repeats the same scalar
	for _, s := range f.doc.secrets() {
		pos := [2]int{s.src.line, s.src.col}
		if !s.isClear() || seen[pos] {
			continue
		}
		seen[pos] = true
		start, end, err := scalarSpan(f.source, s.Secret)
		if err != nil {
			return 0, fmt.Errorf("%s (line %d): %w", s.name, s.src.line, err)
		}
		edits = append(edits, edit{start, end, encrypt(key, s.value)})
	}
	if len(edits) == 0 {
		return 0, nil
	}
	if f.path == "" {
		return 0, errors.New("seal: configuration not read from a file")
	}
	// Apply from the end so earlier offsets stay valid.
	slices.SortFunc(edits, func(a, b edit) int { return a.start - b.start })
	out := bytes.Clone(f.source)
	for i := len(edits) - 1; i >= 0; i-- {
		e := edits[i]
		out = append(out[:e.start:e.start], append([]byte(e.text), out[e.end:]...)...)
	}

	// Never write a file that would not read back to the same credentials.
	if err := verifySealed(out, key, len(edits), f.doc.secretValues()); err != nil {
		return 0, fmt.Errorf("seal: %w", err)
	}
	if err := writeAtomic(f.path, out); err != nil {
		return 0, err
	}
	f.source = out
	return len(edits), nil
}

// secretValues returns the clear-text value of every secret, in order.
func (c *Config) secretValues() []string {
	var vals []string
	for _, s := range c.secrets() {
		vals = append(vals, s.value)
	}
	return vals
}

// verifySealed decodes the rewritten document and checks it holds the same
// secrets, none of them left in clear text but environment references.
func verifySealed(doc, key []byte, encrypted int, want []string) error {
	var c Config
	if err := yaml.Unmarshal(doc, &c); err != nil {
		return fmt.Errorf("rewritten file does not parse: %w", err)
	}
	got := c.secrets()
	if len(got) != len(want) {
		return fmt.Errorf("rewritten file has %d credentials, want %d", len(got), len(want))
	}
	for i, s := range got {
		if s.isClear() {
			return fmt.Errorf("%s still in clear text", s.name)
		}
		if err := s.resolve(func() ([]byte, error) { return key, nil }); err != nil {
			return err
		}
		if s.value != want[i] {
			return fmt.Errorf("%s does not read back", s.name)
		}
	}
	return nil
}

// scalarSpan returns the byte range of the secret's scalar in doc. Only
// single-line plain and quoted scalars are supported: the range is checked
// to hold exactly the value that was decoded.
func scalarSpan(doc []byte, s *Secret) (start, end int, err error) {
	unsupported := errors.New("cannot encrypt in place: write the credential on one line, plain or quoted")
	lines := bytes.SplitAfter(doc, []byte("\n"))
	if s.src.line < 1 || s.src.line > len(lines) {
		return 0, 0, unsupported
	}
	start = 0
	for _, l := range lines[:s.src.line-1] {
		start += len(l)
	}
	line := lines[s.src.line-1]
	// yaml.v3 columns count characters, not bytes.
	off := 0
	for range s.src.col - 1 {
		if off >= len(line) {
			return 0, 0, unsupported
		}
		_, size := utf8.DecodeRune(line[off:])
		off += size
	}
	start += off
	rest := line[off:]

	switch s.src.style {
	case 0: // plain
		if !bytes.HasPrefix(rest, []byte(s.src.raw)) {
			return 0, 0, unsupported
		}
		end = start + len(s.src.raw)
	case yaml.DoubleQuotedStyle, yaml.SingleQuotedStyle:
		q := rest[0]
		i := 1
		for ; i < len(rest); i++ {
			if rest[i] == '\n' {
				return 0, 0, unsupported
			}
			if q == '"' && rest[i] == '\\' {
				i++
				continue
			}
			if rest[i] == q {
				if q == '\'' && i+1 < len(rest) && rest[i+1] == '\'' {
					i++
					continue
				}
				break
			}
		}
		if i >= len(rest) {
			return 0, 0, unsupported
		}
		end = start + i + 1
		var v string
		if err := yaml.Unmarshal(rest[:i+1], &v); err != nil || v != s.src.raw {
			return 0, 0, unsupported
		}
	default:
		return 0, 0, unsupported
	}
	return start, end, nil
}

// writeAtomic replaces path (following symlinks) with data, keeping its
// permissions.
func writeAtomic(path string, data []byte) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(real)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(real), "."+filepath.Base(real)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err2 := f.Chmod(info.Mode().Perm()); err == nil {
		err = err2
	}
	if err2 := f.Sync(); err == nil {
		err = err2
	}
	if err2 := f.Close(); err == nil {
		err = err2
	}
	if err == nil {
		err = os.Rename(tmp, real)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// EncryptValue returns plain encrypted for the configuration file
// (~~HEX~~), with the key at keyPath, generated first when missing.
func EncryptValue(keyPath, plain string) (enc string, keyCreated bool, err error) {
	if plain == "" {
		return "", false, errors.New("nothing to encrypt: the value is empty")
	}
	key, created, err := ensureKey(keyPath)
	if err != nil {
		return "", false, fmt.Errorf("key: %w", err)
	}
	return encrypt(key, plain), created, nil
}

// DataDir returns global.data_dir of the configuration file at path
// ("data" when unset) without validating the rest of the file, so a key can
// be located before the configuration is complete.
func DataDir(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc struct {
		Global struct {
			DataDir string `yaml:"data_dir"`
		} `yaml:"global"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if doc.Global.DataDir == "" {
		return "data", nil
	}
	return doc.Global.DataDir, nil
}
