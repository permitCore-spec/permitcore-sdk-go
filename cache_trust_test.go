package permitcore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestCacheTrust(t *testing.T) {
	trusted, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public := func(k *ecdsa.PrivateKey) string {
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return base64.StdEncoding.EncodeToString(der)
	}
	sign := func(prefix string, payload map[string]any, signer *ecdsa.PrivateKey) string {
		body, _ := json.Marshal(payload)
		encoded := base64.RawURLEncoding.EncodeToString(body)
		hash := sha256.Sum256([]byte(encoded))
		r, s, _ := ecdsa.Sign(rand.Reader, signer, hash[:])
		raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		return prefix + "." + encoded + "." + base64.RawURLEncoding.EncodeToString(raw)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	client := New(server.URL, Options{TrustedPublicKeys: []string{public(trusted)}, CacheDirectory: t.TempDir(), DeviceID: " DEVICE "})
	proof := func() map[string]any {
		return map[string]any{
			"version": 1, "licenseKeySha256": proofHash("key"), "productId": "product", "isValid": true,
			"deviceId": "device", "deviceActivated": true, "nodeLocked": true, "validUntil": time.Now().Add(time.Hour).Format(time.RFC3339),
		}
	}
	store := func(token string, pin string) {
		data, _ := json.Marshal(map[string]string{"token": token, "public_key": pin})
		if err := os.WriteFile(client.cachePath("key"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("matching pinned context", func(t *testing.T) {
		store(sign(graceTokenPrefix, proof(), trusted), "")
		if !client.Validate("key", "", "product").IsValid || !client.Activate("key", "", "", "", "product").IsValid {
			t.Fatal("valid pinned proof rejected")
		}
	})
	for field, value := range map[string]any{"licenseKeySha256": "wrong", "productId": "other", "deviceId": "other", "deviceActivated": false, "validUntil": "bad", "version": 2, "isValid": "true"} {
		t.Run("reject "+field, func(t *testing.T) {
			p := proof()
			p[field] = value
			store(sign(graceTokenPrefix, p, trusted), "")
			if client.Validate("key", "", "product").IsValid || client.Activate("key", "", "", "", "product").IsValid {
				t.Fatal("incorrect context authorized")
			}
		})
	}
	t.Run("cache key is untrusted", func(t *testing.T) {
		store(sign(graceTokenPrefix, proof(), attacker), public(attacker))
		if client.Validate("key", "", "").IsValid {
			t.Fatal("cache key established trust")
		}
		store(sign(graceTokenPrefix, proof(), trusted), public(trusted))
		unpinned := New(server.URL, Options{CacheDirectory: client.cacheDirectory, DeviceID: "device"})
		if unpinned.Validate("key", "", "").IsValid {
			t.Fatal("missing pins authorized")
		}
		rotation := New(server.URL, Options{TrustedPublicKeys: []string{public(attacker), public(trusted)}, CacheDirectory: client.cacheDirectory, DeviceID: "device"})
		if !rotation.Validate("key", "", "").IsValid {
			t.Fatal("approved rotation key rejected")
		}
	})
	t.Run("manual cache reverifies original token", func(t *testing.T) {
		payload := map[string]any{"version": 1, "deviceId": "device", "productId": "product", "expiresAt": time.Now().Add(time.Hour).Format(time.RFC3339)}
		token := sign(offlineTokenPrefix, payload, trusted)
		if !client.ActivateOffline(token, "", "product").IsValid || !client.ValidateOffline("", "product").IsValid {
			t.Fatal("valid manual token rejected")
		}
		data, _ := os.ReadFile(client.offlinePath("device"))
		var entry map[string]any
		_ = json.Unmarshal(data, &entry)
		if len(entry) != 1 || entry["token"] != token {
			t.Fatal("original token not preserved")
		}
		if client.ValidateOffline("", "other").IsValid {
			t.Fatal("wrong product authorized")
		}
		forged, _ := json.Marshal(map[string]any{"isValid": true, "deviceId": "device", "expiresAt": payload["expiresAt"]})
		_ = os.WriteFile(client.offlinePath("device"), forged, 0600)
		if client.ValidateOffline("", "").IsValid {
			t.Fatal("decoded cache authorized")
		}
		payload["expiresAt"] = "bad"
		if client.ActivateOffline(sign(offlineTokenPrefix, payload, trusted), "", "").IsValid {
			t.Fatal("invalid expiry authorized")
		}
	})
}
