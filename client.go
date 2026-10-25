// Package permitcore is the official Go client for PermitCore license management
// (https://permitcore.dev). Zero external dependencies — everything here is standard
// library (net/http, crypto/ecdsa, encoding/json).
//
// Quick start:
//
//	client := permitcore.New("https://api.permitcore.dev")
//	result := client.Validate("PERMIT-XXXX-XXXX-XXXX-XXXX", "", "")
//
//	if result.IsValid {
//		fmt.Println("Valid! Product:", result.ProductName)
//		if result.HasFeature("export") {
//			enableExport()
//		}
//	}
package permitcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Version is this SDK release; module releases also use the matching v2.1.1 git tag.
const Version = "2.1.1"

const userAgent = "PermitCore-Go/1.0"

// Client is the official PermitCore Go SDK client. Safe for concurrent use — it holds no
// mutable state beyond the http.Client and the immutable options it was constructed with.
type Client struct {
	baseURL           string
	httpClient        *http.Client
	enableCache       bool
	trustedPublicKeys []string
	cacheDirectory    string
	deviceID          string
	maxRetries        int
}

// Options configures New. Zero value is the documented default: offline disk caching
// enabled, 10 second HTTP timeout and two additional safe attempts.
type Options struct {
	TrustedPublicKeys []string
	CacheDirectory    string
	DeviceID          string
	// EnableOfflineCache caches a signed grace-cache token to local disk so Validate/Activate
	// can fall back to a cryptographically-verified last-known-good result when the server is
	// unreachable. Defaults to true (pass Options{EnableOfflineCache: false} to disable).
	DisableOfflineCache bool
	// Timeout is the transport timeout per attempt. Defaults to 10 seconds when zero.
	Timeout time.Duration
	// MaxRetries is optional: nil means two; a pointer to zero disables retries (range 0–5).
	MaxRetries *int
}

// New creates a PermitCoreClient for the given API base URL, e.g. "https://api.permitcore.dev".
func New(baseURL string, opts ...Options) *Client {
	o := Options{}
	if len(opts) > 0 {
		o = opts[0]
	}
	timeout := o.Timeout
	if timeout < 0 {
		panic("Timeout must not be negative")
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	retries := 2
	if o.MaxRetries != nil {
		retries = *o.MaxRetries
	}
	if retries < 0 || retries > 5 {
		panic("MaxRetries must be between 0 and 5")
	}
	if o.CacheDirectory == "" {
		o.CacheDirectory = homeDirOrTemp()
	}
	return &Client{
		baseURL:           strings.TrimRight(baseURL, "/"),
		httpClient:        &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		enableCache:       !o.DisableOfflineCache,
		trustedPublicKeys: append([]string(nil), o.TrustedPublicKeys...),
		cacheDirectory:    o.CacheDirectory,
		deviceID:          o.DeviceID,
		maxRetries:        retries,
	}
}

// Validate validates a license key. Does NOT consume an activation slot. version is optional
// (pass "" to omit) — lets the server enforce MinVersion/MaxVersion restrictions on the
// license. expectedProductID is optional (pass "" to omit) — lets the server reject the key if
// it doesn't belong to this product. Falls back to the local disk cache when the server is
// unreachable, as long as the license has an offline grace period configured.
func (c *Client) Validate(licenseKey string, version string, expectedProductID string) *LicenseResult {
	body := map[string]string{"licenseKey": licenseKey}
	if c.enableCache && len(c.trustedPublicKeys) > 0 {
		body["deviceId"] = c.effectiveDeviceID("")
	}
	if version != "" {
		body["version"] = version
	}
	if expectedProductID != "" {
		body["expectedProductId"] = expectedProductID
	}

	var result LicenseResult
	if err := c.post("api/v1/validate", body, &result); err != nil {
		if rejected := rejectedLicense(err); rejected != nil {
			return rejected
		}
		if cached := c.loadCache(licenseKey, c.effectiveDeviceID(""), expectedProductID, false); cached != nil {
			return cached
		}
		return &LicenseResult{IsValid: false, Message: "Cannot reach license server.", IsOffline: true, ErrorCode: "RequestFailed"}
	}

	if result.IsValid {
		c.saveCache(licenseKey, &result, c.effectiveDeviceID(""), expectedProductID, false)
	}
	return &result
}

// Activate validates AND activates the key on this device. Call only once per installation —
// use Validate on every later launch. deviceID defaults to GetHardwareID() when empty.
// version is optional, same meaning as Validate's. expectedProductID is optional (pass "" to
// omit) — lets the server reject the key if it doesn't belong to this product.
func (c *Client) Activate(licenseKey string, deviceID string, deviceName string, version string, expectedProductID string) *LicenseResult {
	hwid := c.effectiveDeviceID(deviceID)

	var nonceResp struct {
		Nonce string `json:"nonce"`
	}
	if err := c.get("api/v1/nonce", &nonceResp); err != nil {
		if rejected := rejectedLicense(err); rejected != nil {
			return rejected
		}
		if cached := c.loadCache(licenseKey, hwid, expectedProductID, true); cached != nil {
			// [S-Continuity] A device that already activated successfully before (e.g. an app
			// that re-runs Activate on every launch, or a reinstall that kept the cache file)
			// falls back to that cached result instead of failing outright.
			return cached
		}
		return &LicenseResult{IsValid: false, Message: "Cannot reach license server.", IsOffline: true, ErrorCode: "RequestFailed"}
	}

	if strings.TrimSpace(nonceResp.Nonce) == "" {
		return &LicenseResult{ErrorCode: "InvalidResponse", Message: "Invalid nonce response."}
	}
	body := map[string]string{"licenseKey": licenseKey, "deviceId": hwid, "nonce": nonceResp.Nonce}
	if deviceName != "" {
		body["deviceName"] = deviceName
	}
	if version != "" {
		body["version"] = version
	}
	if expectedProductID != "" {
		body["expectedProductId"] = expectedProductID
	}

	var result LicenseResult
	if err := c.post("api/v1/activate", body, &result); err != nil {
		if rejected := rejectedLicense(err); rejected != nil {
			return rejected
		}
		if cached := c.loadCache(licenseKey, hwid, expectedProductID, true); cached != nil {
			return cached
		}
		return &LicenseResult{IsValid: false, Message: "Cannot reach license server.", IsOffline: true, ErrorCode: "RequestFailed"}
	}

	if result.IsValid {
		c.saveCache(licenseKey, &result, hwid, expectedProductID, true)
	}
	return &result
}

// Meter records a usage event for metered billing. meta may be nil. Returns true if the
// event was recorded on the server, false on any failure (network error, or the server
// rejecting the event) — never panics.
func (c *Client) Meter(licenseKey string, eventName string, quantity int, meta map[string]any) bool {
	if quantity <= 0 {
		quantity = 1
	}
	body := map[string]any{"licenseKey": licenseKey, "eventName": eventName, "quantity": quantity}
	if meta != nil {
		body["meta"] = meta
	}

	var data struct {
		Recorded bool `json:"recorded"`
	}
	if err := c.post("api/v1/meter", body, &data); err != nil {
		return false
	}
	return data.Recorded
}

// Checkout checks out a concurrent seat for a floating license. deviceID defaults to
// GetHardwareID() when empty.
// Deactivate confirms HTTP 204. Protected portal policy is never bypassed.
func (c *Client) Deactivate(tenantSlug, licenseKey, activationID string) bool {
	_ = os.Remove(c.cachePath(licenseKey))
	var ack noContentResult
	if err := c.post("api/v1/portal/"+url.PathEscape(tenantSlug)+"/deactivate",
		map[string]string{"licenseKey": licenseKey, "activationId": activationID}, &ack); err != nil {
		return false
	}
	return ack.confirmed
}

func (c *Client) Checkout(licenseKey string, deviceID string, deviceName string) *FloatingSession {
	if deviceID == "" {
		deviceID = GetHardwareID()
	}
	body := map[string]string{"licenseKey": licenseKey, "deviceId": deviceID}
	if deviceName != "" {
		body["deviceName"] = deviceName
	}
	return c.floatingRequest("checkout", body)
}

func (c *Client) Heartbeat(sessionToken string) *FloatingSession {
	return c.floatingRequest("heartbeat", map[string]string{"sessionToken": sessionToken})
}

func (c *Client) floatingRequest(operation string, body any) *FloatingSession {
	failure := func() *FloatingSession {
		return &FloatingSession{ErrorCode: "RequestFailed", Message: "Cannot complete floating request."}
	}
	var raw map[string]any
	if err := c.post("api/v1/float/"+operation, body, &raw); err != nil {
		return failure()
	}
	success, ok := raw["success"].(bool)
	if !ok {
		return failure()
	}
	for _, field := range []string{"sessionToken", "expiresAt", "message", "errorCode"} {
		if value := raw[field]; value != nil {
			if _, ok := value.(string); !ok {
				return failure()
			}
		}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return failure()
	}
	var session FloatingSession
	if json.Unmarshal(encoded, &session) != nil {
		return failure()
	}
	if !success {
		session.SessionToken = ""
		session.ExpiresAt = ""
		if session.ErrorCode == "" {
			session.ErrorCode = "FloatingDenied"
		}
		return &session
	}
	if strings.TrimSpace(session.SessionToken) == "" || strings.TrimSpace(session.ExpiresAt) == "" {
		return failure()
	}
	session.ErrorCode = ""
	return &session
}

type noContentResult struct{ confirmed bool }

func (c *Client) TryCheckin(sessionToken string) bool {
	var ack noContentResult
	if err := c.post("api/v1/float/checkin", map[string]string{"sessionToken": sessionToken}, &ack); err != nil {
		return false
	}
	return ack.confirmed
}

// Best-effort compatibility method; TryCheckin reports confirmed HTTP release.
func (c *Client) Checkin(sessionToken string) { c.TryCheckin(sessionToken) }

// ── HTTP helpers ─────────────────────────────────────────────────────────────

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	return c.do(req, out)
}

func (c *Client) post(path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	path := req.URL.EscapedPath()
	safe := req.Method == http.MethodGet && (strings.HasSuffix(path, "/api/v1/nonce") || strings.HasSuffix(path, "/public-key")) ||
		req.Method == http.MethodPost && (strings.HasSuffix(path, "/api/v1/validate") || strings.HasSuffix(path, "/api/v1/float/heartbeat"))
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		current := req.Clone(req.Context())
		if attempt > 0 && req.Body != nil {
			if req.GetBody == nil {
				return fmt.Errorf("request body cannot be replayed")
			}
			var err error
			current.Body, err = req.GetBody()
			if err != nil {
				return err
			}
		}
		var err error
		resp, err = c.httpClient.Do(current)
		if err == nil && resp.StatusCode < 500 {
			break
		}
		if resp != nil {
			resp.Body.Close()
			if err == nil {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}
		if !safe || attempt >= c.maxRetries || req.Context().Err() != nil {
			return err
		}
		delay := 250 * time.Millisecond * time.Duration(1<<attempt)
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-req.Context().Done():
			timer.Stop()
			return req.Context().Err()
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		body, _ := io.ReadAll(resp.Body)
		return &httpRejection{status: resp.StatusCode, body: body}
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if ack, ok := out.(*noContentResult); ok {
		ack.confirmed = resp.StatusCode == http.StatusNoContent
		return nil
	}
	if out == nil {
		return nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return &invalidResponse{}
	}
	if result, ok := out.(*LicenseResult); ok {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return &invalidResponse{}
		}
		var valid bool
		if field, exists := fields["isValid"]; !exists || string(field) == "null" || json.Unmarshal(field, &valid) != nil {
			return &invalidResponse{}
		}
		if json.Unmarshal(raw, result) != nil {
			return &invalidResponse{}
		}
		result.IsOffline = false
		if !result.IsValid {
			result.OfflineCacheToken = ""
		}
		return nil
	}
	if len(raw) == 0 && resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if json.Unmarshal(raw, out) != nil {
		return &invalidResponse{}
	}
	return nil
}

type invalidResponse struct{}

func (*invalidResponse) Error() string { return "Invalid response from server." }

type httpRejection struct {
	status int
	body   []byte
}

func (e *httpRejection) Error() string { return fmt.Sprintf("HTTP %d.", e.status) }

func rejectedLicense(err error) *LicenseResult {
	var invalid *invalidResponse
	if errors.As(err, &invalid) {
		return &LicenseResult{ErrorCode: "InvalidResponse", Message: invalid.Error()}
	}
	var rejection *httpRejection
	if !errors.As(err, &rejection) {
		return nil
	}
	var result LicenseResult
	_ = json.Unmarshal(rejection.body, &result)
	result.IsValid = false
	result.IsOffline = false
	result.OfflineCacheToken = ""
	if result.ErrorCode == "" {
		result.ErrorCode = "HttpError"
	}
	if result.Message == "" {
		result.Message = rejection.Error()
	}
	return &result
}
