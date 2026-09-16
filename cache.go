package permitcore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ── validate()/activate() offline grace cache (pc_grace_v1) ────────────────────────────────

type cacheEntry struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
}

// saveCache persists the SIGNED grace-cache token, never the raw response — the server only
// issues OfflineCacheToken when a grace period is configured, so a missing token already
// means "nothing to cache."
func (c *Client) saveCache(licenseKey string, result *LicenseResult) {
	if !c.enableCache || result.OfflineCacheToken == "" {
		return
	}

	tenantSlug := extractUnverifiedTenantSlug(result.OfflineCacheToken)
	if tenantSlug == "" {
		return
	}

	var pubKeyResp struct {
		PublicKey string `json:"publicKey"`
	}
	if err := c.get("api/v1/"+url.PathEscape(tenantSlug)+"/public-key", &pubKeyResp); err != nil || pubKeyResp.PublicKey == "" {
		return
	}

	// Verify before persisting anything — never cache a token this SDK can't itself verify
	// later; that would just recreate the old "trust an opaque file" problem.
	if check := VerifyGraceCacheToken(result.OfflineCacheToken, pubKeyResp.PublicKey); !check.IsValid {
		return
	}

	data, err := json.Marshal(cacheEntry{Token: result.OfflineCacheToken, PublicKey: pubKeyResp.PublicKey})
	if err != nil {
		return
	}
	_ = os.WriteFile(cachePath(licenseKey), data, 0o600) // cache failure must never block the normal online flow
}

func (c *Client) loadCache(licenseKey string) *LicenseResult {
	if !c.enableCache {
		return nil
	}

	data, err := os.ReadFile(cachePath(licenseKey))
	if err != nil {
		return nil
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil || entry.Token == "" || entry.PublicKey == "" {
		return nil
	}

	// No network call here — verification uses only the public key persisted alongside the
	// token at save time. This is the entire point: a hand-edited cache file (or one copied to
	// another machine) fails ECDSA verification instead of silently working.
	check := VerifyGraceCacheToken(entry.Token, entry.PublicKey)
	if !check.IsValid || check.Payload == nil {
		return nil
	}

	p := check.Payload
	var remaining *int
	if p.RemainingActivations != 0 {
		v := p.RemainingActivations
		remaining = &v
	}

	return &LicenseResult{
		IsValid:              p.IsValid,
		ProductName:          p.ProductName,
		RemainingActivations: remaining,
		ExpiresAt:            p.ExpiresAt,
		Features:             p.Features,
		IsOffline:            true,
		Message:              "Offline mode — valid until " + p.ValidUntil + " (cryptographically verified)",
	}
}

// extractUnverifiedTenantSlug reads only the tenantSlug field out of a pc_grace_v1 token's
// payload, WITHOUT verifying the signature — safe to do because it's only used to pick which
// tenant's public-key endpoint to fetch. VerifyGraceCacheToken is what actually establishes
// trust before anything gets persisted to disk.
func extractUnverifiedTenantSlug(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != graceTokenPrefix {
		return ""
	}
	jsonBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var data struct {
		TenantSlug string `json:"tenantSlug"`
	}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return ""
	}
	return data.TenantSlug
}

// ── activate_offline()/validate_offline() local persistence (pc_offline_v1) ────────────────
// Unlike the grace cache above, no signature check is needed on load — ActivateOffline
// already verified the token's signature before ever calling saveOfflineCache.

func saveOfflineCache(deviceID string, payload *OfflineTokenPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(offlineCachePath(deviceID), data, 0o600)
}

func loadOfflineCache(deviceID string) (*OfflineTokenPayload, error) {
	data, err := os.ReadFile(offlineCachePath(deviceID))
	if err != nil {
		return nil, err
	}
	var payload OfflineTokenPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func cachePath(licenseKey string) string {
	return filepath.Join(homeDirOrTemp(), ".permitcore_cache_"+shortHash(licenseKey))
}

func offlineCachePath(deviceID string) string {
	return filepath.Join(homeDirOrTemp(), ".permitcore_offline_"+shortHash(deviceID))
}

func homeDirOrTemp() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return os.TempDir()
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}
