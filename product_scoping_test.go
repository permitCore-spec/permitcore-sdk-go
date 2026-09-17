package permitcore

// Product-scoping regression tests (opt-in expectedProductID param on Validate/Activate, plus
// the always-present ProductID field on the response — see README's "Product scoping" section).
//
// Real gap found live: /api/v1/validate and /api/v1/activate find a license purely by the key
// itself, so any active key belonging to a tenant validated/activated successfully regardless of
// which of the tenant's products it was actually issued for. Fix is opt-in: an
// "expectedProductId" field in the request, rejected with errorCode "WrongProduct" on mismatch;
// the response now always includes a "productId" field.
//
// This SDK builds requests via plain net/http (see client.go's get/post/do), with no injectable
// transport seam — httptest.NewServer (standard library, zero new dependency) is the idiomatic
// way to capture the outgoing request body without a real network call.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// startCapturingServer starts a throwaway HTTP server that records every request body it
// receives (keyed by path) and replies with whatever canned JSON `responses` has for that path.
// A request to a path not present in `responses` gets {"isValid": true} as a safe default (used
// for /api/v1/nonce during Activate's flow).
func startCapturingServer(t *testing.T, responses map[string]string) (*httptest.Server, map[string][]byte) {
	t.Helper()
	captured := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured[r.URL.Path] = body

		w.Header().Set("Content-Type", "application/json")
		if payload, ok := responses[r.URL.Path]; ok {
			_, _ = w.Write([]byte(payload))
			return
		}
		_, _ = w.Write([]byte(`{"isValid":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

func TestValidate_WithoutExpectedProductID_OmitsItFromRequestBody(t *testing.T) {
	srv, captured := startCapturingServer(t, map[string]string{
		"/api/v1/validate": `{"isValid":true,"productId":"11111111-1111-1111-1111-111111111111"}`,
	})

	c := New(srv.URL)
	c.Validate("PERMIT-TEST", "", "")

	body := captured["/api/v1/validate"]
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse captured request body: %v (%s)", err, body)
	}
	if _, ok := parsed["expectedProductId"]; ok {
		t.Fatalf("expected no expectedProductId key in request body, got %s", body)
	}
}

func TestValidate_WithExpectedProductID_IncludesItInRequestBody(t *testing.T) {
	srv, captured := startCapturingServer(t, map[string]string{
		"/api/v1/validate": `{"isValid":true,"productId":"11111111-1111-1111-1111-111111111111"}`,
	})

	c := New(srv.URL)
	c.Validate("PERMIT-TEST", "", "some-product-id")

	body := captured["/api/v1/validate"]
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse captured request body: %v (%s)", err, body)
	}
	if parsed["expectedProductId"] != "some-product-id" {
		t.Fatalf(`expected expectedProductId="some-product-id" in request body, got %s`, body)
	}
}

func TestActivate_WithoutExpectedProductID_OmitsItFromRequestBody(t *testing.T) {
	srv, captured := startCapturingServer(t, map[string]string{
		"/api/v1/nonce":    `{"nonce":"test-nonce"}`,
		"/api/v1/activate": `{"isValid":true,"productId":"22222222-2222-2222-2222-222222222222"}`,
	})

	c := New(srv.URL)
	c.Activate("PERMIT-TEST", "device-1", "Test Device", "", "")

	body := captured["/api/v1/activate"]
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse captured request body: %v (%s)", err, body)
	}
	if _, ok := parsed["expectedProductId"]; ok {
		t.Fatalf("expected no expectedProductId key in request body, got %s", body)
	}
}

func TestActivate_WithExpectedProductID_IncludesItInRequestBody(t *testing.T) {
	srv, captured := startCapturingServer(t, map[string]string{
		"/api/v1/nonce":    `{"nonce":"test-nonce"}`,
		"/api/v1/activate": `{"isValid":true,"productId":"22222222-2222-2222-2222-222222222222"}`,
	})

	c := New(srv.URL)
	c.Activate("PERMIT-TEST", "device-1", "Test Device", "", "some-product-id")

	body := captured["/api/v1/activate"]
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse captured request body: %v (%s)", err, body)
	}
	if parsed["expectedProductId"] != "some-product-id" {
		t.Fatalf(`expected expectedProductId="some-product-id" in request body, got %s`, body)
	}
}

func TestLicenseResult_UnmarshalsProductID(t *testing.T) {
	var result LicenseResult
	raw := []byte(`{"isValid":true,"productId":"11111111-1111-1111-1111-111111111111"}`)
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result.ProductID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("expected ProductID=%q, got %q", "11111111-1111-1111-1111-111111111111", result.ProductID)
	}
}

func TestLicenseResult_UnmarshalsWrongProductErrorCode(t *testing.T) {
	var result LicenseResult
	raw := []byte(`{"isValid":false,"errorCode":"WrongProduct","productId":"33333333-3333-3333-3333-333333333333","message":"This key was not issued for the requested product."}`)
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result.IsValid {
		t.Fatalf("expected IsValid=false, got true")
	}
	if result.ErrorCode != "WrongProduct" {
		t.Fatalf("expected ErrorCode=%q, got %q", "WrongProduct", result.ErrorCode)
	}
	if result.ProductID != "33333333-3333-3333-3333-333333333333" {
		t.Fatalf("expected ProductID=%q, got %q", "33333333-3333-3333-3333-333333333333", result.ProductID)
	}
}
