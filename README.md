# PermitCore Go SDK

Official Go client for [PermitCore](https://permitcore.dev) license management.

**Requirements:** Go 1.21+, zero dependencies — everything is standard library
(`net/http`, `crypto/ecdsa`, `encoding/json`).

---

## Installation

Install the matching tagged Go module when that version is available:

```
# Requires this exact version to be available in the module registry/tag:
go get github.com/permitCore-spec/permitcore-sdk-go/v2@v2.1.1
```

Go modules are VCS/tag-based, not served from a central package registry like npm or PyPI — this
tagged repository *is* the registry, no separate publish step needed.

Working from a local source ZIP instead (Admin panel → SDKs, or `GET /api/sdks/go` — e.g. for
local edits before a real release)? Extract it, then add a `replace` directive to your own
`go.mod` pointing at the extracted folder:

```
require github.com/permitCore-spec/permitcore-sdk-go/v2 v2.1.1

replace github.com/permitCore-spec/permitcore-sdk-go/v2 => ./permitcore-sdk-go
```

---

## Quick start

```go
import "github.com/permitCore-spec/permitcore-sdk-go/v2"

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

## Offline activation and grace — SDK 2 migration

Configure trusted tenant **ECDSA P-256 SPKI/base64 public keys** in your application before using
offline mode. Obtain `publicKey` from `GET /api/v1/{tenantSlug}/public-key` while connected to
your verified API origin, review it as the vendor, and distribute it in trusted application
configuration. It is public; the signing **private key must never ship to customers**. Do not
read trust keys from an editable license/cache file. Missing pins disable cached authorization;
online validation/activation continue to work. Registry publication and hosted release gates must be recorded separately from source
availability. Earlier 1.x cached-key/decoded-payload behavior is
not a secure substitute for this migration.

Signed grace tokens bind the exact license key SHA-256, the checked product (including the
requested covered bundle member), and optional normalized device ID. Offline activation and
node-locked validation also require signed evidence of an existing device activation. Validation
never allocates a seat. A removed device cannot refresh activation evidence; an already-issued
proof remains usable until its signed deadline. Provide the same configured device ID on every
launch when using custom device identities. IDs are trimmed and compared without case.

The client stores **only the original signed token** and re-verifies signature, version,
deadline and context on every cache read. Legacy `.permitcore_cache_*` and decoded offline files
are ignored. New filenames are `.permitcore_cache_v2_<full lowercase SHA-256 of license key>` and
`.permitcore_offline_v2_<full lowercase SHA-256 of normalized device ID>`. Choose a private,
application-specific cache directory. Defaults retain the platform SDK location: .NET local
application data; Python/Go home; Node/Java/C++/PHP system temp; Unity its configured directory
(or temp). Hardware seed generation retains its existing SDK behavior.

Manual offline helpers are **instance methods** using configured trust; they no longer accept a
public key argument. .NET helpers were static; Go helpers were package functions; C++ persisted
validation was static. Raw `VerifyOfflineToken` / `verifyOfflineToken` / `verify_offline_token`
and grace-verification primitives still accept an explicit key, without establishing its trust.
Pass the expected product for product pinning. Legacy original signed manual tokens can still
verify with a trusted key, but product-pinned use requires a newly issued token with `productId`.

Keep active and approved previous public keys in the configured list during deliberate rotation.
Removing a compromised pin requires an application/configuration update. Offline verification
cannot discover revocations, server-side device removal or payment changes while disconnected.
It does not stop local clock manipulation or application patching. Grace uses signed `validUntil`,
manual tokens use signed `expiresAt`; Store paid-through/payment-grace caps are not extended.
Online HTTP rejection remains authoritative; only network/5xx outages use grace fallback.

```go
// SDK 2 source module: github.com/permitCore-spec/permitcore-sdk-go/v2
client := permitcore.New("https://api.permitcore.dev", permitcore.Options{
    TrustedPublicKeys: []string{trustedTenantPublicKey},
    CacheDirectory: appCacheDirectory,
    DeviceID: stableDeviceID,
})
first := client.ActivateOffline(token, "", productID)
later := client.ValidateOffline("", productID)
onlineOrGrace := client.Validate(licenseKey, "", productID)
```

[Full SDK migration and offline setup](https://permitcore.dev/docs/offline-licensing).

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

## Store subscription payment status (1.2.0)

Online validate/activate results include `paymentStatus` (`active`, `past_due`, `unpaid`,
`canceled`, or null/empty for other licenses) and `isInGracePeriod`. Use the language's normal
field naming (`PaymentStatus`/`IsInGracePeriod`, `payment_status`/`is_in_grace_period`, or
camelCase). Show a card-update notice for `past_due` or `unpaid` while `isValid` is true.
Paid renewals extend the same key to Stripe's paid billing-period end. Default payment grace is
14 days from paid-through, configurable in Store settings and overridable per license.
Access expires at the grace deadline; an ended subscription revokes the license.

Signed offline cache tokens are capped at paid-through plus grace and refreshed on successful
online validation after payment. An offline cached result cannot discover a payment-state change;
reconnect for current payment metadata. The signed deadline remains authoritative offline.
## Admin dashboard sessions

The Admin dashboard uses a server-enforced 30-minute inactivity timeout and a five-minute warning.
Interactive browser activity, including keyboard shortcuts consumed by help dialogs, renews that session; background JWT refresh keeps its existing deadline.
Concurrent Admin sign-ins preserve the winning session; if Sign In asks you to retry, sign in again.
SDK license validation, activation, floating seats, metering and API-key authentication retain their
documented behavior. See [Admin session help](https://permitcore.dev/docs/admin).

PermitCore website analytics excludes internal/test traffic; this does not change SDK requests,
responses, offline validation or license processing. See the [Cookie Policy](https://permitcore.dev/cookies).

Website activation reporting is isolated to production background jobs. An analytics queue
outage does not change a successful SDK license-validation response.

Project website: [PermitCore](https://permitcore.dev/) — public directory links, including
LaunchNest and ToolFame, are in its footer. [API and SDK documentation](https://permitcore.dev/docs).


Paddle credit-only subscription updates do not create or renew licenses or clear payment debt.
This server payment handling does not change any SDK API or wire format; all eight SDKs keep
the same entitlement behavior. See the [provider guide](https://permitcore.dev/docs/store#checkout-provider).


Admin payment settings show saved provider/mode and safe expandable event details. This does
not change SDK requests, responses, retries or entitlement behavior in any of the eight SDKs.
The [Store setup guide](https://permitcore.dev/docs/store#checkout-provider) explains configuration.

## HTTP failure handling — SDK 2.1.1

SDK 2.1.1 includes the earlier HTTP-authority fixes for validate/activate: a 4xx response
cannot return successful offline validation, even if a previously verified cache exists. Valid
server error codes are retained; empty, malformed or contradictory rejection bodies return
`HttpError`. A failed or interrupted rejection body does not erase a received HTTP status.
Network and 5xx unavailability can still use the existing cryptographically verified
cache within its signed deadline. Safe requests now use bounded retries as described below.

Check your registry for available versions; a source download and a published package are separate
distributions. Release acceptance and current availability are recorded in the public SDK documentation.
See [SDK availability and HTTP behavior](https://permitcore.dev/docs/sdks) for publication and environment acceptance; source availability is not a registry release.


## Floating sessions — SDK 2.1.1

SDK 2.1.1 includes the preceding HTTP-authority fixes and floating checkout,
heartbeat and release in all eight clients. Registry availability must be verified separately.

Methods: `Checkout / Heartbeat / TryCheckin / Checkin` (in that order). Checkout sends the license key and device ID, plus an
optional device name, in a POST body. Omit the device ID to use the SDK hardware fingerprint.
Heartbeat sends the session token in a POST body. Keep tokens private and release the seat when
your application finishes; floating operations never use the offline license cache.

Checkout/heartbeat return a session with success=false and no token/expiry on failure.
Network, HTTP and malformed-response failures use `RequestFailed`. A business denial preserves
its server error code, or uses `FloatingDenied` when none is supplied. Only a successful response
with credentials grants a session. Check success before using its token.

The new boolean release method confirms only HTTP 204. False means release was not confirmed;
it does not prove the server kept the seat. The existing void/Task checkin method is best effort
and does not throw on transport failure. An unconfirmed release relies on server session expiry;
never fabricate a local seat or treat a cache as floating authorization.

Shared floating vectors and real loopback connection failures are included in the SDK suite.
Heartbeat may retry network/5xx failures under the bounded policy below. Checkout and checkin are sent once.


## Device removal and usage reporting — SDK 2.1.1

`Deactivate(tenantSlug, licenseKey, activationId)` confirms device removal only on HTTP 204.
The activation ID identifies an existing activation of this license; obtain it through the
customer portal/admin activation list. The key stays in the POST body. The SDK attempts to remove
that key's local signed grace-cache entry when removal is attempted. This does not revoke
independently issued offline-activation tokens or make offline revocation immediate.

False means removal was not confirmed. This key-only call respects Portal policy: an OTP- or
account-protected portal requires its customer-facing flow. The SDK does not request or bypass
OTP/account authentication automatically. Network/HTTP failure returns false; no automatic retry.

`Meter` returns boolean confirmation of a recorded usage event. Supply the license key,
event name, integer quantity (default 1) and optional metadata object. Quantities <=0 normalize
to 1. Nested JSON values and explicitly empty metadata objects are preserved; omitted metadata
remains absent. Only a successful HTTP response with JSON `recorded: true` confirms recording;
malformed, missing or string boolean fields return false. No offline cache or automatic retries
are used. False does not prove the server did not record a request whose response was lost;
blind retries can duplicate billing usage.

## Transport configuration — SDK 2.1.1

Use `New(url, Options{Timeout: 10*time.Second, MaxRetries: &retries})`. A nil retry pointer means two; a pointer to zero disables retries. Zero timeout uses the default; negative timeout is rejected.

Default timeout is 10 seconds per attempt. Safe calls use up to two retries (three attempts),
with 250ms then 500ms backoff; `maxRetries` (idiomatic spelling varies) accepts 0–5 and zero disables retries.
Only validate, nonce/public-key GET and floating heartbeat may retry network/5xx failures.
Floating checkout, activation POST, metering, deactivation and checkin are never replayed automatically.
Activation's separate nonce GET may retry. No HTTP 3xx/4xx or malformed successful response retries.
SDK-owned transports disable redirects; configure the final HTTPS API URL directly.

Validate/activate preserve server error codes. Unclassified rejection is `HttpError`;
malformed successful license/nonce evidence is `InvalidResponse`; exhausted network/5xx
unavailability without a verified cache is `RequestFailed`. Known rejection and malformed
successful evidence never consult cached authorization. This does not loosen SDK 2 trusted-key,
signature, deadline or license/product/device verification. Optional DTO/schema edges can differ
by runtime; the shared contract covers the documented core fields. A timeout applies per attempt,
not to the complete multi-request operation; Python uses socket I/O timeouts and Unity delegates
to its adapter.


### Online offline-token status check

The optional server verification call uses `POST /api/v1/offline/verify` without an Admin
session. SDK 2.1.1 accompanies the tenant-scoped API verification repair. Tracked revoked
tokens and compromised signing keys are rejected; valid vendor self-issued tokens need no
server record. Offline signature checks cannot discover later server revocation until the
application reconnects, and retain the signed expiry deadline.
