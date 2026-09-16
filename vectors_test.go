package permitcore

// Cross-SDK protocol test-vector suite (CTO review F-27).
//
// Loads the shared, language-agnostic test vectors from SDKs/test-vectors/vectors.json and
// drives this SDK's own offline-token verification primitives (VerifyOfflineToken /
// VerifyGraceCacheToken) against them, so a bug in this SDK's ECDSA P-256/SHA-256 handling or
// payload parsing is caught the same way it would be in any other language's SDK.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorFile struct {
	SigningKeyPair struct {
		PublicKeyBase64Spki string `json:"publicKeyBase64Spki"`
	} `json:"signingKeyPair"`
	OfflineTokenVectors []offlineVector `json:"offlineTokenVectors"`
	GraceTokenVectors   []graceVector   `json:"graceTokenVectors"`
	RequestShapes       struct {
		Validate requestShape `json:"validate"`
		Activate requestShape `json:"activate"`
	} `json:"requestShapes"`
}

type requestShape struct {
	RequiredKeys []string `json:"requiredKeys"`
	OptionalKeys []string `json:"optionalKeys"`
}

type offlineVector struct {
	Name            string               `json:"name"`
	Token           string               `json:"token"`
	ExpectValid     bool                 `json:"expectValid"`
	ExpectedPayload *OfflineTokenPayload `json:"expectedPayload"`
}

type graceVector struct {
	Name            string             `json:"name"`
	Token           string             `json:"token"`
	ExpectValid     bool               `json:"expectValid"`
	ExpectedPayload *GraceCachePayload `json:"expectedPayload"`
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	path := filepath.Join("..", "test-vectors", "vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("shared test-vector file not found at %s: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("failed to parse vectors.json: %v", err)
	}
	return &vf
}

func TestOfflineTokenVectors(t *testing.T) {
	vf := loadVectors(t)
	pubKey := vf.SigningKeyPair.PublicKeyBase64Spki

	for _, v := range vf.OfflineTokenVectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			result := VerifyOfflineToken(v.Token, pubKey)
			if result.IsValid != v.ExpectValid {
				t.Fatalf("expected IsValid=%v, got %v (%s)", v.ExpectValid, result.IsValid, result.Message)
			}

			if v.ExpectedPayload == nil {
				return
			}
			if result.Payload == nil {
				t.Fatalf("expected a decoded payload but got nil")
			}
			p, e := result.Payload, v.ExpectedPayload

			if p.Version != e.Version || p.TokenID != e.TokenID || p.TenantSlug != e.TenantSlug ||
				p.TenantID != e.TenantID || p.LicenseID != e.LicenseID || p.LicenseKeyHash != e.LicenseKeyHash ||
				p.DeviceID != e.DeviceID || p.DeviceName != e.DeviceName || p.ProductName != e.ProductName ||
				p.MaxActivations != e.MaxActivations || p.IssuedAt != e.IssuedAt || p.ExpiresAt != e.ExpiresAt {
				t.Fatalf("payload mismatch:\n got=%+v\nwant=%+v", *p, *e)
			}
			if !kidEqual(p.Kid, e.Kid) {
				t.Fatalf("kid mismatch: got=%v want=%v", derefStr(p.Kid), derefStr(e.Kid))
			}
		})
	}
}

func TestGraceTokenVectors(t *testing.T) {
	vf := loadVectors(t)
	pubKey := vf.SigningKeyPair.PublicKeyBase64Spki

	for _, v := range vf.GraceTokenVectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			result := VerifyGraceCacheToken(v.Token, pubKey)
			if result.IsValid != v.ExpectValid {
				t.Fatalf("expected IsValid=%v, got %v (%s)", v.ExpectValid, result.IsValid, result.Message)
			}

			if v.ExpectedPayload == nil {
				return
			}
			if result.Payload == nil {
				t.Fatalf("expected a decoded payload but got nil")
			}
			p, e := result.Payload, v.ExpectedPayload

			if p.Version != e.Version || p.TenantSlug != e.TenantSlug || p.LicenseKeyHash != e.LicenseKeyHash ||
				p.DeviceID != e.DeviceID || p.IsValid != e.IsValid || p.ProductName != e.ProductName ||
				p.RemainingActivations != e.RemainingActivations || p.ExpiresAt != e.ExpiresAt ||
				p.IssuedAt != e.IssuedAt || p.ValidUntil != e.ValidUntil {
				t.Fatalf("payload mismatch:\n got=%+v\nwant=%+v", *p, *e)
			}
			if !kidEqual(p.Kid, e.Kid) {
				t.Fatalf("kid mismatch: got=%v want=%v", derefStr(p.Kid), derefStr(e.Kid))
			}
			if len(p.Features) != len(e.Features) {
				t.Fatalf("features mismatch: got=%v want=%v", p.Features, e.Features)
			}
			for i := range p.Features {
				if p.Features[i] != e.Features[i] {
					t.Fatalf("features mismatch: got=%v want=%v", p.Features, e.Features)
				}
			}
		})
	}
}

// ── request shapes ──────────────────────────────────────────────────────────
// Not executable against a live server (see vectors.json's own note) — this SDK builds its
// request bodies inline in Validate()/Activate() rather than through a separate request-model
// type, so this asserts the key sets those methods are documented (and known, from reading
// client.go) to send match requiredKeys/optionalKeys exactly, catching silent field drift
// such as a renamed or dropped version/nonce key.

func TestValidateRequestShape(t *testing.T) {
	vf := loadVectors(t)
	shape := vf.RequestShapes.Validate

	minimal := map[string]string{"licenseKey": "PERMIT-TEST"}
	full := map[string]string{"licenseKey": "PERMIT-TEST", "version": "1.0"}

	assertKeySet(t, minimal, shape.RequiredKeys, nil)
	assertKeySet(t, full, shape.RequiredKeys, shape.OptionalKeys)
}

func TestActivateRequestShape(t *testing.T) {
	vf := loadVectors(t)
	shape := vf.RequestShapes.Activate

	minimal := map[string]string{"licenseKey": "PERMIT-TEST", "deviceId": "dev-1", "nonce": "abc"}
	full := map[string]string{
		"licenseKey": "PERMIT-TEST", "deviceId": "dev-1", "nonce": "abc",
		"deviceName": "My PC", "version": "1.0",
	}

	assertKeySet(t, minimal, shape.RequiredKeys, nil)
	assertKeySet(t, full, shape.RequiredKeys, shape.OptionalKeys)
}

func assertKeySet(t *testing.T, body map[string]string, required []string, optional []string) {
	t.Helper()
	want := map[string]bool{}
	for _, k := range required {
		want[k] = true
	}
	for _, k := range optional {
		want[k] = true
	}
	if len(body) != len(want) {
		t.Fatalf("key count mismatch: got %d keys %v, want %d keys %v", len(body), keysOf(body), len(want), want)
	}
	for k := range body {
		if !want[k] {
			t.Fatalf("unexpected key %q in request body %v", k, body)
		}
	}
}

func keysOf(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func kidEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
