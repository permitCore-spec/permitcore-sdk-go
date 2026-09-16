package permitcore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// GetHardwareID generates a stable hardware fingerprint (SHA-256 hex of machine
// identifiers). Deliberately never includes a MAC address — see this SDK's README for why.
func GetHardwareID() string {
	components := []string{
		hostname(),
		runtime.GOOS,
		runtime.GOARCH,
		strconv.Itoa(runtime.NumCPU()),
		getOrCreateSeed(),
	}
	nonEmpty := make([]string, 0, len(components))
	for _, c := range components {
		if c != "" {
			nonEmpty = append(nonEmpty, c)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(nonEmpty, "|")))
	return hex.EncodeToString(sum[:])
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// getOrCreateSeed persists a random per-machine seed under the user's home directory —
// the same role a MAC address might otherwise play, without the privacy/permission issues
// of reading one. Created once, reused on every later call.
func getOrCreateSeed() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	seedPath := filepath.Join(home, ".permitcore_seed")

	if data, err := os.ReadFile(seedPath); err == nil {
		return strings.TrimSpace(string(data))
	}

	seed := newRandomID()
	_ = os.WriteFile(seedPath, []byte(seed), 0o600)
	return seed
}

// newRandomID generates a random UUID-v4-shaped string with no external dependency.
func newRandomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
