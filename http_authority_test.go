package permitcore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestSharedHTTPAuthority(t *testing.T) {
	raw, err := os.ReadFile(testVectorPath("http-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	type httpCase struct {
		TruncatedBody   bool   `json:"truncatedBody"`
		Status          int    `json:"status"`
		Body            string `json:"body"`
		ErrorCode       string `json:"errorCode"`
		ExpectedValid   bool   `json:"expectedValid"`
		ExpectedOffline bool   `json:"expectedOffline"`
	}
	var contract struct {
		Cases              []httpCase `json:"httpAuthority"`
		LicenseResponses   []httpCase `json:"httpLicenseResponses"`
		TransientResponses []httpCase `json:"httpTransientResponses"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	if len(contract.Cases) == 0 {
		t.Fatal("Shared HTTP cases missing")
	}
	for index, vector := range append(append(contract.Cases, contract.LicenseResponses...), contract.TransientResponses...) {
		for _, operation := range []string{"validate", "activate"} {
			t.Run(fmt.Sprintf("%s/%d/%d", operation, vector.Status, index), func(t *testing.T) {
				var posts atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("Content-Type", "application/json")
					if r.Method == http.MethodGet && r.URL.Path == "/api/v1/nonce" {
						_, _ = io.WriteString(w, `{"nonce":"qa-nonce"}`)
						return
					}
					if r.Method != http.MethodPost || r.URL.Path != "/api/v1/"+operation {
						t.Errorf("Unexpected request %s %s", r.Method, r.URL.Path)
					}
					posts.Add(1)
					if vector.TruncatedBody {
						w.Header().Set("Content-Length", strconv.Itoa(len(vector.Body)+32))
						w.Header().Set("Connection", "close")
					}
					w.WriteHeader(vector.Status)
					_, _ = io.WriteString(w, vector.Body)
				}))
				defer server.Close()
				client := New(server.URL, Options{DisableOfflineCache: true})
				var result *LicenseResult
				if operation == "validate" {
					result = client.Validate("QA-HTTP-REJECTED", "", "")
				} else {
					result = client.Activate("QA-HTTP-REJECTED", "qa-device", "", "", "")
				}
				expectedPosts := int32(1)
				if operation == "validate" && vector.Status >= 500 {
					expectedPosts = 3
				}
				if posts.Load() != expectedPosts {
					t.Errorf("POST count = %d, want %d", posts.Load(), expectedPosts)
				}
				if result.IsValid != vector.ExpectedValid || result.IsOffline != vector.ExpectedOffline || result.ErrorCode != vector.ErrorCode {
					t.Errorf("Rejected HTTP %d became valid=%t offline=%t errorCode=%q, want %t/%t/%q", vector.Status, result.IsValid, result.IsOffline, result.ErrorCode, vector.ExpectedValid, vector.ExpectedOffline, vector.ErrorCode)
				}
			})
		}
	}
}
