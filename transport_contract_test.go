package permitcore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedTransportContract(t *testing.T) {
	raw, err := os.ReadFile(testVectorPath("http-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Cases []struct {
			Name, Operation, Body, Location, NonceBody string
			Statuses, NonceStatuses                    []int
			MaxRetries                                 *int
			ExpectedRequests, ExpectedNonceRequests    int
			ExpectedSuccess, ExpectedOffline           bool
			ExpectedErrorCode                          string
		} `json:"transportCases"`
	}
	if err = json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	if len(contract.Cases) == 0 {
		t.Fatal("Missing transport vectors")
	}
	for _, v := range contract.Cases {
		t.Run(v.Name, func(t *testing.T) {
			var posts, nonces, redirects atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if r.URL.Path == "/redirect-target" {
					redirects.Add(1)
				}
				statuses, body, index := v.Statuses, v.Body, int32(0)
				if r.URL.Path == "/api/v1/nonce" {
					index = nonces.Add(1) - 1
					statuses = v.NonceStatuses
					if len(statuses) == 0 {
						statuses = []int{200}
					}
					body = v.NonceBody
					if body == "" {
						body = `{"nonce":"qa-nonce"}`
					}
				} else {
					index = posts.Add(1) - 1
				}
				if int(index) >= len(statuses) {
					index = int32(len(statuses) - 1)
				}
				if v.Location != "" {
					w.Header().Set("Location", v.Location)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(statuses[index])
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			c := New(server.URL, Options{DisableOfflineCache: true, MaxRetries: v.MaxRetries})
			var license *LicenseResult
			var floating *FloatingSession
			var success bool
			switch v.Operation {
			case "validate":
				license = c.Validate("QA-TRANSPORT-KEY", "", "")
			case "activate":
				license = c.Activate("QA-TRANSPORT-KEY", "qa-device", "", "", "")
			case "checkout":
				floating = c.Checkout("QA-TRANSPORT-KEY", "qa-device", "")
			case "heartbeat":
				floating = c.Heartbeat("qa-token")
			case "meter":
				success = c.Meter("QA-TRANSPORT-KEY", "qa_export", 1, nil)
			case "deactivate":
				success = c.Deactivate("qa-tenant", "QA-TRANSPORT-KEY", "11111111-2222-3333-4444-555555555555")
			case "checkin":
				success = c.TryCheckin("qa-token")
			default:
				t.Fatal("Unknown transport operation")
			}
			if license != nil {
				success = license.IsValid
				if license.ErrorCode != v.ExpectedErrorCode || license.IsOffline != v.ExpectedOffline {
					t.Errorf("License result: %+v", license)
				}
			}
			if floating != nil {
				success = floating.Success
			}
			if success != v.ExpectedSuccess {
				t.Errorf("success=%t want %t", success, v.ExpectedSuccess)
			}
			if posts.Load() != int32(v.ExpectedRequests) || nonces.Load() != int32(v.ExpectedNonceRequests) || redirects.Load() != 0 {
				t.Errorf("Requests posts=%d nonces=%d redirects=%d", posts.Load(), nonces.Load(), redirects.Load())
			}
		})
	}
}

func TestTransportConfigurationAndTimeout(t *testing.T) {
	c := New("https://sdk.example.invalid")
	if c.httpClient.Timeout != 10*time.Second || c.maxRetries != 2 {
		t.Fatal("Incorrect defaults")
	}
	for _, retries := range []int{-1, 6} {
		t.Run("invalid retries", func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("Expected rejected configuration")
				}
			}()
			New("https://sdk.example.invalid", Options{MaxRetries: &retries})
		})
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `{"isValid":true}`)
	}))
	defer server.Close()
	retries := 0
	c = New(server.URL, Options{DisableOfflineCache: true, Timeout: 100 * time.Millisecond, MaxRetries: &retries})
	result := c.Validate("QA-TRANSPORT-KEY", "", "")
	if result.IsValid || result.ErrorCode != "RequestFailed" || requests.Load() != 1 {
		t.Errorf("Timeout result=%+v requests=%d", result, requests.Load())
	}
}
