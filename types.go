package permitcore

import "strings"

// LicenseResult is returned by Validate and Activate. Never nil — a network failure or a
// rejected key both come back as a LicenseResult with IsValid=false, never an error, so
// callers don't need a second branch on top of the usual `if !result.IsValid`.
type LicenseResult struct {
	IsValid              bool              `json:"isValid"`
	ProductName          string            `json:"productName,omitempty"`
	RemainingActivations *int              `json:"remainingActivations,omitempty"`
	ExpiresAt            string            `json:"expiresAt,omitempty"`
	Message              string            `json:"message,omitempty"`
	CustomFields         map[string]string `json:"customFields,omitempty"`
	VendorWarning        string            `json:"vendorWarning,omitempty"`
	Features             []string          `json:"features,omitempty"`
	IsTrial              bool              `json:"isTrial,omitempty"`
	TrialDaysRemaining   *int              `json:"trialDaysRemaining,omitempty"`
	NodeLocked           bool              `json:"nodeLocked,omitempty"`
	OfflineGraceDays     *int              `json:"offlineGraceDays,omitempty"`
	MinVersion           string            `json:"minVersion,omitempty"`
	MaxVersion           string            `json:"maxVersion,omitempty"`
	// IsOffline is set locally by this SDK (never sent by the server) — true when this
	// result came from the local disk cache instead of a real network round trip.
	IsOffline         bool   `json:"-"`
	OfflineCacheToken string `json:"offlineCacheToken,omitempty"`
	// ErrorCode is a stable, machine-readable failure reason (e.g. "NotFound",
	// "SeatsExhausted", "Expired") — empty on success. Message stays free-text for display;
	// branch on this for programmatic logic instead, since message wording may change.
	ErrorCode string `json:"errorCode,omitempty"`
}

// HasFeature reports whether the license includes the given feature flag (case-insensitive).
func (r *LicenseResult) HasFeature(feature string) bool {
	if r == nil {
		return false
	}
	for _, f := range r.Features {
		if strings.EqualFold(f, feature) {
			return true
		}
	}
	return false
}

// FloatingSession is returned by Checkout and Heartbeat.
type FloatingSession struct {
	Success      bool   `json:"success"`
	SessionToken string `json:"sessionToken,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
	Message      string `json:"message,omitempty"`
}

// OfflineTokenPayload is the decoded payload of a pc_offline_v1 offline activation token.
type OfflineTokenPayload struct {
	Version    int    `json:"version"`
	TokenID    string `json:"tokenId"`
	TenantSlug string `json:"tenantSlug"`
	// Kid identifies which of the tenant's signing keys produced this token — nil on tokens
	// issued before key versioning existed (see the "legacy_null_kid" shared test vector).
	// Informational only: VerifyOfflineToken is handed the public key to verify against
	// directly and does not look it up via this field.
	Kid            *string `json:"kid"`
	TenantID       string  `json:"tenantId"`
	LicenseID      string  `json:"licenseId"`
	LicenseKeyHash string  `json:"licenseKeyHash"`
	DeviceID       string  `json:"deviceId"`
	DeviceName     string  `json:"deviceName"`
	ProductName    string  `json:"productName"`
	MaxActivations int     `json:"maxActivations"`
	IssuedAt       string  `json:"issuedAt"`
	ExpiresAt      string  `json:"expiresAt"`
}

// OfflineTokenResult is returned by every offline-token verification method. Payload is nil
// only when the token was malformed before any crypto was attempted.
type OfflineTokenResult struct {
	IsValid bool
	Message string
	Payload *OfflineTokenPayload
}

// GraceCachePayload is the decoded, verified payload of a pc_grace_v1 offline grace-cache token.
type GraceCachePayload struct {
	Version              int      `json:"version"`
	TenantSlug           string   `json:"tenantSlug"`
	Kid                  *string  `json:"kid"`
	LicenseKeyHash       string   `json:"licenseKeyHash"`
	DeviceID             string   `json:"deviceId"`
	IsValid              bool     `json:"isValid"`
	ProductName          string   `json:"productName"`
	Features             []string `json:"features"`
	RemainingActivations int      `json:"remainingActivations"`
	ExpiresAt            string   `json:"expiresAt"`
	IssuedAt             string   `json:"issuedAt"`
	ValidUntil           string   `json:"validUntil"`
}

// GraceCacheResult is returned by VerifyGraceCacheToken.
type GraceCacheResult struct {
	IsValid bool
	Message string
	Payload *GraceCachePayload
}
