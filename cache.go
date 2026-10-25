package permitcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type cacheEntry struct {
	Token string `json:"token"`
}

func (c *Client) effectiveDeviceID(id string) string {
	if strings.TrimSpace(id) == "" {
		id = c.deviceID
	}
	if strings.TrimSpace(id) == "" {
		id = GetHardwareID()
	}
	return strings.ToLower(strings.TrimSpace(id))
}
func proofHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
func (c *Client) cachePath(key string) string {
	return filepath.Join(c.cacheDirectory, ".permitcore_cache_v2_"+proofHash(key))
}
func (c *Client) offlinePath(id string) string {
	return filepath.Join(c.cacheDirectory, ".permitcore_offline_v2_"+proofHash(id))
}

func (c *Client) trustedGraceToken(token, key, deviceID, productID string, activation bool) *GraceCachePayload {
	for _, pin := range c.trustedPublicKeys {
		result := VerifyGraceCacheToken(token, pin)
		p := result.Payload
		if !result.IsValid || p == nil || !p.IsValid || p.LicenseKeySHA256 != proofHash(key) || p.ProductID == "" ||
			(productID != "" && !strings.EqualFold(p.ProductID, productID)) ||
			(p.DeviceID != "" && !strings.EqualFold(strings.TrimSpace(p.DeviceID), deviceID)) ||
			((activation || p.NodeLocked == nil || *p.NodeLocked) && (p.DeviceActivated == nil || !*p.DeviceActivated || p.DeviceID == "")) {
			continue
		}
		return p
	}
	return nil
}
func (c *Client) saveCache(key string, result *LicenseResult, deviceID, productID string, activation bool) {
	if !c.enableCache || result.OfflineCacheToken == "" {
		return
	}
	if c.trustedGraceToken(result.OfflineCacheToken, key, deviceID, productID, activation) == nil {
		return
	}
	data, err := json.Marshal(cacheEntry{Token: result.OfflineCacheToken})
	if err != nil {
		return
	}
	if os.MkdirAll(c.cacheDirectory, 0700) != nil {
		return
	}
	_ = os.WriteFile(c.cachePath(key), data, 0600)
}
func (c *Client) loadCache(key, deviceID, productID string, activation bool) *LicenseResult {
	if !c.enableCache {
		return nil
	}
	data, err := os.ReadFile(c.cachePath(key))
	if err != nil {
		return nil
	}
	var entry cacheEntry
	if json.Unmarshal(data, &entry) != nil {
		return nil
	}
	p := c.trustedGraceToken(entry.Token, key, deviceID, productID, activation)
	if p == nil {
		return nil
	}
	remaining := p.RemainingActivations
	return &LicenseResult{IsValid: true, ProductID: p.ProductID, NodeLocked: p.NodeLocked != nil && *p.NodeLocked,
		ProductName: p.ProductName, RemainingActivations: &remaining, ExpiresAt: p.ExpiresAt,
		Features: p.Features, IsOffline: true, Message: "Offline mode — valid until " + p.ValidUntil + " (cryptographically verified)"}
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
