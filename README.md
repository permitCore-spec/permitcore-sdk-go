# PermitCore Go SDK

Official Go client for [PermitCore](https://permitcore.dev) license management.

**Requirements:** Go 1.21+, zero dependencies — everything is standard library
(`net/http`, `crypto/ecdsa`, `encoding/json`).

---

## Installation

Published as a real, tagged Go module:

```
go get github.com/permitCore-spec/permitcore-sdk-go@v1.1.0
```

Go modules are VCS/tag-based, not served from a central package registry like npm or PyPI — this
tagged repository *is* the registry, no separate publish step needed.

Working from a local source ZIP instead (Admin panel → SDKs, or `GET /api/sdks/go` — e.g. for
local edits before a real release)? Extract it, then add a `replace` directive to your own
`go.mod` pointing at the extracted folder:

```
require github.com/permitCore-spec/permitcore-sdk-go v0.0.0

replace github.com/permitCore-spec/permitcore-sdk-go => ./permitcore-sdk-go
```

---

## Quick start

```go
import "github.com/permitCore-spec/permitcore-sdk-go"

client := permitcore.New("https://api.permitcore.dev")
result := client.Validate("PERMIT-XXXX-XXXX-XXXX-XXXX", "", "")

if !result.IsValid {
	log.Fatalf("License invalid: %s", result.Message)
}

if result.HasFeature("export") {
	enableExport()
}
if result.IsTrial {
	fmt.Printf("Trial — %d days remaining\n", *result.TrialDaysRemaining)
}
```

---

## Validate

```go
result := client.Validate(licenseKey, "2.3.1", "") // version and expectedProductID are optional — pass "" to omit

// result.IsValid                  bool
// result.ProductName              string
// result.ProductID                string  (the license's real product GUID — always present when found)
// result.RemainingActivations     *int
// result.ExpiresAt                string  (ISO 8601)
// result.Features                 []string
// result.CustomFields             map[string]string
// result.IsTrial                  bool
// result.TrialDaysRemaining       *int
// result.NodeLocked               bool
// result.OfflineGraceDays         *int
// result.MinVersion / MaxVersion  string
// result.VendorWarning            string
// result.Message                  string
// result.IsOffline                bool  (true when served from local cache)
// result.ErrorCode                string (stable machine-readable reason, e.g. "NotFound", "WrongProduct")
```

`Validate` never consumes an activation slot. It falls back to the local disk cache when the
server is unreachable, as long as the license has an offline grace period configured. Passing
`version` lets the *server* enforce `MinVersion`/`MaxVersion` restrictions on the license.

`Validate`/`Activate` never return a Go `error` — a network failure and a rejected key both
come back as a `*LicenseResult` with `IsValid == false`, so there's only one branch to check.

**Product scoping**: `Validate`/`Activate` find a key purely by the key itself — by default, any
active key belonging to your tenant validates successfully, regardless of which of your products
it was actually issued for. If your app should only accept keys issued for *this* product, either
check `result.ProductID` yourself, or pass `expectedProductID` and let the server reject a
mismatch for you (`result.ErrorCode == "WrongProduct"`). Pass `""` to omit. Find your product's ID
in the Admin panel under Products (or on a license's own detail page).

---

## Activate

```go
result := client.Activate(
	licenseKey,
	"",                      // deviceId — auto-generated HWID when empty
	"Production Server #1",  // deviceName
	"2.3.1",                 // version, optional — pass "" to omit
	"",                      // expectedProductID, optional — pass "" to omit
)

if !result.IsValid {
	log.Fatalf("Activation failed: %s", result.Message)
}
```

Call `Activate` **once** per installation. Use `Validate` on every subsequent launch.

---

## Meter (usage events)

```go
// Record a single API call
recorded := client.Meter(licenseKey, "api_call", 1, nil)

// Record bulk usage with metadata
recorded := client.Meter(licenseKey, "export", 5, map[string]any{"format": "pdf", "pages": 12})
```

Returns `true` if the event was recorded on the server, `false` on any failure (network error,
or the server rejecting the event).

---

## Floating licenses

```go
// Check out a seat at session start
session := client.Checkout(licenseKey, "", "")
if !session.Success {
	log.Fatalf("No seats available: %s", session.Message)
}
token := session.SessionToken

// Heartbeat every 4-5 minutes to keep the seat alive
client.Heartbeat(token)

// Release the seat when done
client.Checkin(token)
```

---

## Offline license tokens

An offline activation token (`pc_offline_v1.<payload>.<signature>`) lets your app verify a
license with **zero network calls**, using ECDSA P-256 signature verification against your
tenant's public key (`GET /api/v1/{tenantSlug}/public-key`). Useful for air-gapped or
intermittently-connected deployments. No extra package needed — `crypto/ecdsa` is standard
library, unlike SDKs whose crypto library (OpenSSL, Python `cryptography`) is an optional
dependency.

```go
// Pure local verification — no network call, no panic (malformed/tampered/expired input just
// comes back as IsValid=false with a descriptive Message).
result := permitcore.VerifyOfflineToken(token, publicKeyBase64)

if result.IsValid {
	fmt.Println("Valid! Product:", result.Payload.ProductName)
} else {
	fmt.Println("Invalid:", result.Message)
}
```

```go
// Verify + bind to this device + persist locally (call once, e.g. at install time)
result := permitcore.ActivateOffline(token, publicKeyBase64, deviceID)

// On every later launch — no token needed, reads the local cache, still no network call
result := permitcore.ValidateOffline(deviceID)
```

```go
// Optional: ask the server to verify the token AND check its revocation status (requires network)
result := client.VerifyOfflineOnline(token)
```

All four return an `*OfflineTokenResult{IsValid, Message, Payload}`. `Payload`
(`*OfflineTokenPayload`) carries `TokenID`, `TenantSlug`, `Kid`, `TenantID`, `LicenseID`,
`LicenseKeyHash`, `DeviceID`, `DeviceName`, `ProductName`, `MaxActivations`, `IssuedAt`,
`ExpiresAt`. `Kid` (a `*string`) identifies which of the tenant's signing keys produced the
token — `nil` on tokens issued before key versioning existed; informational only,
`VerifyOfflineToken` still verifies against whatever `publicKeyBase64` you pass it.

`ActivateOffline`'s local cache is stored under the user's home directory as
`.permitcore_offline_<hash>` (same convention as the `Validate`/`Activate` cache, keyed by
device ID instead of license key).

---

## Version enforcement

```go
result := client.Validate(licenseKey, "", "")

myVersion := "2.3.0"
if result.MinVersion != "" && myVersion < result.MinVersion {
	log.Fatalf("Please update to version %s or newer.", result.MinVersion)
}
if result.MaxVersion != "" && myVersion > result.MaxVersion {
	log.Fatalf("This build (%s) is not licensed for versions above %s.", myVersion, result.MaxVersion)
}
```

Pass `version` to `Validate`/`Activate` to also have the *server* enforce this — otherwise
only the client-side string comparison above happens (works for simple `major.minor.patch`
schemes; use a real semver package if you need more).

---

## Offline grace pattern

```go
result := client.Validate(licenseKey, "", "") // falls back to cache automatically

if !result.IsValid {
	log.Fatalf("License invalid: %s", result.Message)
}
if result.IsOffline {
	showNotice("Running in offline mode. Connect to the internet to refresh your license.")
}
```

The cache is stored under the user's home directory as `.permitcore_cache_<hash>`. It expires
after `OfflineGraceDays` days and is cryptographically signed (`pc_grace_v1`, ECDSA P-256) —
a hand-edited cache file fails verification instead of silently working.

---

## Constructor options

```go
client := permitcore.New("https://api.permitcore.dev", permitcore.Options{
	DisableOfflineCache: false,        // default false — set true to always require network
	Timeout:             5 * time.Second,
})
```

---

## LicenseResult reference

| Field | Type | Description |
|---|---|---|
| `IsValid` | `bool` | True if the license is active and valid |
| `ProductName` | `string` | Product the license belongs to |
| `ProductID` | `string` | GUID of the product the license belongs to. Always present when the key was found, regardless of whether `expectedProductID` was passed |
| `RemainingActivations` | `*int` | Slots left before MaxActivations is reached |
| `ExpiresAt` | `string` | Expiry date (ISO 8601 UTC), empty if perpetual |
| `Features` | `[]string` | Feature flag list, e.g. `["export", "api"]` |
| `CustomFields` | `map[string]string` | Arbitrary key/value metadata set on the license |
| `IsTrial` | `bool` | True for trial licenses |
| `TrialDaysRemaining` | `*int` | Days until trial expires |
| `NodeLocked` | `bool` | True if bound to a specific device |
| `OfflineGraceDays` | `*int` | How many days the cache is valid |
| `MinVersion` / `MaxVersion` | `string` | Version enforcement bounds |
| `VendorWarning` | `string` | Non-fatal message from the vendor |
| `Message` | `string` | Reason when `IsValid == false` |
| `IsOffline` | `bool` | True when result came from local cache |
| `ErrorCode` | `string` | Stable, machine-readable failure reason |

`HasFeature(feature string) bool` — case-insensitive feature check.

---

## Development

```bash
go test ./...
```

`vectors_test.go` runs this SDK's `VerifyOfflineToken`/`VerifyGraceCacheToken` against the
shared, language-agnostic cross-SDK protocol vectors in `../test-vectors/vectors.json` (fixed
ECDSA P-256/SHA-256 tokens every PermitCore SDK verifies identically — see that file's own
`schemaNote`) and checks the `validate`/`activate` request bodies this SDK builds match the
shared `requestShapes` key sets exactly.
