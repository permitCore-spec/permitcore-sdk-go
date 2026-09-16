package permitcore

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

// Offline/grace-cache token verification — entirely local, no network call. Mirrors
// PermitCore.Infrastructure.Services.OfflineActivationService.Verify/VerifyGraceCache
// byte-for-byte: ECDSA P-256, SHA-256, RAW IEEE P1363 signature (64-byte r||s — Go's
// ecdsa.Verify takes r/s directly, so unlike SDKs built on OpenSSL/PHP-openssl/Python-
// cryptography this needs no P1363-to-DER conversion). The signature covers the UTF-8
// bytes of the base64url-encoded PAYLOAD STRING, not the decoded JSON bytes.

const offlineTokenPrefix = "pc_offline_v1"
const graceTokenPrefix = "pc_grace_v1"

// VerifyOfflineToken verifies a pc_offline_v1 offline activation token entirely locally.
// This is the primitive every other offline_* function builds on. Never panics — a
// malformed, tampered, or expired token just comes back with IsValid=false and a
// descriptive Message.
func VerifyOfflineToken(token string, publicKeyBase64Spki string) *OfflineTokenResult {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != offlineTokenPrefix {
		return &OfflineTokenResult{IsValid: false, Message: "Malformed token."}
	}

	pub, err := parsePublicKey(publicKeyBase64Spki)
	if err != nil {
		return &OfflineTokenResult{IsValid: false, Message: "Invalid or corrupt token."}
	}

	if !verifyP1363Signature(pub, parts[1], parts[2]) {
		return &OfflineTokenResult{IsValid: false, Message: "Invalid signature."}
	}

	jsonBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return &OfflineTokenResult{IsValid: false, Message: "Invalid or corrupt token."}
	}
	var payload OfflineTokenPayload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return &OfflineTokenResult{IsValid: false, Message: "Invalid or corrupt token."}
	}

	if payload.ExpiresAt != "" {
		if expiry, err := time.Parse(time.RFC3339, payload.ExpiresAt); err == nil && expiry.Before(time.Now().UTC()) {
			return &OfflineTokenResult{IsValid: false, Message: "Token expired.", Payload: &payload}
		}
	}

	return &OfflineTokenResult{IsValid: true, Message: "Valid.", Payload: &payload}
}

// VerifyGraceCacheToken verifies a pc_grace_v1 offline grace-cache token entirely locally.
// Exposed publicly so a custom integration (not using the built-in disk cache) can build its
// own caching around the same verified primitive.
func VerifyGraceCacheToken(token string, publicKeyBase64Spki string) *GraceCacheResult {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != graceTokenPrefix {
		return &GraceCacheResult{IsValid: false, Message: "Malformed token."}
	}

	pub, err := parsePublicKey(publicKeyBase64Spki)
	if err != nil {
		return &GraceCacheResult{IsValid: false, Message: "Invalid or corrupt token."}
	}

	if !verifyP1363Signature(pub, parts[1], parts[2]) {
		return &GraceCacheResult{IsValid: false, Message: "Invalid signature."}
	}

	jsonBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return &GraceCacheResult{IsValid: false, Message: "Invalid or corrupt token."}
	}
	var payload GraceCachePayload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return &GraceCacheResult{IsValid: false, Message: "Invalid or corrupt token."}
	}

	if payload.ValidUntil != "" {
		if expiry, err := time.Parse(time.RFC3339, payload.ValidUntil); err == nil && expiry.Before(time.Now().UTC()) {
			return &GraceCacheResult{IsValid: false, Message: "Grace period expired.", Payload: &payload}
		}
	}

	return &GraceCacheResult{IsValid: true, Message: "Valid.", Payload: &payload}
}

// ActivateOffline verifies an offline token, checks it was issued for this device, and — on
// success — persists the verified payload to local disk so ValidateOffline can be called
// later without needing the original token again.
func ActivateOffline(token string, publicKeyBase64Spki string, deviceID string) *OfflineTokenResult {
	result := VerifyOfflineToken(token, publicKeyBase64Spki)
	if !result.IsValid || result.Payload == nil {
		return result
	}

	if !strings.EqualFold(result.Payload.DeviceID, deviceID) {
		return &OfflineTokenResult{
			IsValid: false,
			Message: "Token was issued for a different device.",
			Payload: result.Payload,
		}
	}

	_ = saveOfflineCache(deviceID, result.Payload) // cache failure must never block a successful verification
	return result
}

// ValidateOffline reads the locally persisted offline-activation result (from a prior
// ActivateOffline call) and checks it's still within its validity window. No network call,
// no token needed — call this on every app launch once already offline-activated.
func ValidateOffline(deviceID string) *OfflineTokenResult {
	payload, err := loadOfflineCache(deviceID)
	if err != nil || payload == nil {
		return &OfflineTokenResult{IsValid: false, Message: "No local offline activation found."}
	}

	if !strings.EqualFold(payload.DeviceID, deviceID) {
		return &OfflineTokenResult{IsValid: false, Message: "Device mismatch.", Payload: payload}
	}

	if payload.ExpiresAt != "" {
		if expiry, err := time.Parse(time.RFC3339, payload.ExpiresAt); err == nil && expiry.Before(time.Now().UTC()) {
			return &OfflineTokenResult{IsValid: false, Message: "Offline activation expired.", Payload: payload}
		}
	}

	return &OfflineTokenResult{IsValid: true, Message: "Valid (offline).", Payload: payload}
}

// VerifyOfflineOnline asks the server to verify the token AND check its revocation status.
// Requires network — use VerifyOfflineToken for pure offline verification, which needs no
// server round trip at all.
func (c *Client) VerifyOfflineOnline(token string) *OfflineTokenResult {
	var data struct {
		IsValid bool   `json:"isValid"`
		Message string `json:"message"`
	}
	if err := c.post("api/v1/offline/verify", map[string]string{"token": token}, &data); err != nil {
		return &OfflineTokenResult{IsValid: false, Message: "Cannot reach license server."}
	}
	return &OfflineTokenResult{IsValid: data.IsValid, Message: data.Message}
}

// parsePublicKey decodes a base64-encoded X.509 SubjectPublicKeyInfo (SPKI) DER blob — the
// same format TenantSigningKey.PublicKeyBase64Spki is stored/exported in server-side — into
// an *ecdsa.PublicKey.
func parsePublicKey(publicKeyBase64Spki string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(publicKeyBase64Spki)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errNotECDSAKey
	}
	return pub, nil
}

var errNotECDSAKey = &offlineError{"public key is not an ECDSA key"}

type offlineError struct{ msg string }

func (e *offlineError) Error() string { return e.msg }

// verifyP1363Signature verifies a raw 64-byte IEEE P1363 (r||s) signature over the UTF-8
// bytes of payloadB64Url (the base64url-encoded payload STRING, not the decoded JSON) — the
// exact byte range OfflineActivationService.Sign() signs server-side.
func verifyP1363Signature(pub *ecdsa.PublicKey, payloadB64Url string, sigB64Url string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64Url)
	if err != nil || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	hash := sha256.Sum256([]byte(payloadB64Url))
	return ecdsa.Verify(pub, hash[:], r, s)
}
