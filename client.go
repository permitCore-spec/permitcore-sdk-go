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
	"net/http"
	"strings"
	"time"
)

const userAgent = "PermitCore-Go/1.0"

// Client is the official PermitCore Go SDK client. Safe for concurrent use — it holds no
// mutable state beyond the http.Client and the immutable options it was constructed with.
type Client struct {
	baseURL     string
	httpClient  *http.Client
	enableCache bool
}

// Options configures New. Zero value is the documented default: offline disk caching
// enabled, 5 second HTTP timeout.
type Options struct {
	// EnableOfflineCache caches a signed grace-cache token to local disk so Validate/Activate
	// can fall back to a cryptographically-verified last-known-good result when the server is
	// unreachable. Defaults to true (pass Options{EnableOfflineCache: false} to disable).
	DisableOfflineCache bool
	// Timeout is the HTTP request timeout. Defaults to 5 seconds when zero.
	Timeout time.Duration
}

// New creates a PermitCoreClient for the given API base URL, e.g. "https://api.permitcore.dev".
func New(baseURL string, opts ...Options) *Client {
	o := Options{}
	if len(opts) > 0 {
		o = opts[0]
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		httpClient:  &http.Client{Timeout: timeout},
		enableCache: !o.DisableOfflineCache,
	}
}

// Validate validates a license key. Does NOT consume an activation slot. version is optional
// (pass "" to omit) — lets the server enforce MinVersion/MaxVersion restrictions on the
// license. expectedProductID is optional (pass "" to omit) — lets the server reject the key if
// it doesn't belong to this product. Falls back to the local disk cache when the server is
// unreachable, as long as the license has an offline grace period configured.
func (c *Client) Validate(licenseKey string, version string, expectedProductID string) *LicenseResult {
	body := map[string]string{"licenseKey": licenseKey}
	if version != "" {
		body["version"] = version
	}
	if expectedProductID != "" {
		body["expectedProductId"] = expectedProductID
	}

	var result LicenseResult
	if err := c.post("api/v1/validate", body, &result); err != nil {
		if cached := c.loadCache(licenseKey); cached != nil {
			return cached
		}
		return &LicenseResult{IsValid: false, Message: "Cannot reach license server.", IsOffline: true}
	}

	if result.IsValid {
		c.saveCache(licenseKey, &result)
	}
	return &result
}

// Activate validates AND activates the key on this device. Call only once per installation —
// use Validate on every later launch. deviceID defaults to GetHardwareID() when empty.
// version is optional, same meaning as Validate's. expectedProductID is optional (pass "" to
// omit) — lets the server reject the key if it doesn't belong to this product.
func (c *Client) Activate(licenseKey string, deviceID string, deviceName string, version string, expectedProductID string) *LicenseResult {
	hwid := deviceID
	if hwid == "" {
		hwid = GetHardwareID()
	}

	var nonceResp struct {
		Nonce string `json:"nonce"`
	}
	if err := c.get("api/v1/nonce", &nonceResp); err != nil {
		if cached := c.loadCache(licenseKey); cached != nil {
			// [S-Continuity] A device that already activated successfully before (e.g. an app
			// that re-runs Activate on every launch, or a reinstall that kept the cache file)
			// falls back to that cached result instead of failing outright.
			return cached
		}
		return &LicenseResult{IsValid: false, Message: "Cannot reach license server.", IsOffline: true}
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
		if cached := c.loadCache(licenseKey); cached != nil {
			return cached
		}
		return &LicenseResult{IsValid: false, Message: "Cannot reach license server.", IsOffline: true}
	}

	if result.IsValid {
		c.saveCache(licenseKey, &result)
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
func (c *Client) Checkout(licenseKey string, deviceID string, deviceName string) *FloatingSession {
	hwid := deviceID
	if hwid == "" {
		hwid = GetHardwareID()
	}
	body := map[string]string{"licenseKey": licenseKey, "deviceId": hwid}
	if deviceName != "" {
		body["deviceName"] = deviceName
	}

	var session FloatingSession
	if err := c.post("api/v1/float/checkout", body, &session); err != nil {
		return &FloatingSession{Success: false, Message: "Cannot reach license server."}
	}
	return &session
}

// Heartbeat keeps a floating session alive. Call every 4-5 minutes.
func (c *Client) Heartbeat(sessionToken string) *FloatingSession {
	// [S-Float] Session token in the POST body — never the URL path — matches
	// FloatingController.Heartbeat's FloatingTokenRequest exactly.
	var session FloatingSession
	if err := c.post("api/v1/float/heartbeat", map[string]string{"sessionToken": sessionToken}, &session); err != nil {
		return &FloatingSession{Success: false, Message: "Cannot reach license server."}
	}
	return &session
}

// Checkin releases a floating seat. Best-effort — errors are swallowed, matching every other
// PermitCore SDK's checkin() (a failed release on process exit must never block shutdown).
func (c *Client) Checkin(sessionToken string) {
	_ = c.post("api/v1/float/checkin", map[string]string{"sessionToken": sessionToken}, nil)
}

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
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
