package permitcore

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestSharedFloatingContract(t *testing.T) {
	data, err := os.ReadFile(testVectorPath("http-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Cases []struct {
			Quantity int            `json:"quantity"`
			Meta     map[string]any `json:"meta"`
			Request  map[string]any `json:"request"`

			Name      string `json:"name"`
			Operation string `json:"operation"`
			Status    int    `json:"status"`
			Body      string `json:"body"`
			Success   bool   `json:"expectedSuccess"`
			Code      string `json:"expectedErrorCode"`
			Released  bool   `json:"expectedReleased"`
		} `json:"floatingCases"`
		OperationCases []struct {
			Quantity int            `json:"quantity"`
			Meta     map[string]any `json:"meta"`
			Request  map[string]any `json:"request"`

			Name      string `json:"name"`
			Operation string `json:"operation"`
			Status    int    `json:"status"`
			Body      string `json:"body"`
			Success   bool   `json:"expectedSuccess"`
			Code      string `json:"expectedErrorCode"`
			Released  bool   `json:"expectedReleased"`
		} `json:"operationCases"`
		Floating map[string]struct {
			Path string         `json:"path"`
			Body map[string]any `json:"body"`
		} `json:"operations"`
	}
	if json.Unmarshal(data, &contract) != nil {
		t.Fatal("invalid shared contract")
	}
	for _, v := range append(contract.Cases, contract.OperationCases...) {
		t.Run(v.Name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				raw, _ := io.ReadAll(r.Body)
				var body map[string]any
				if json.Unmarshal(raw, &body) != nil {
					t.Error("invalid request JSON")
				}
				if r.Method != "POST" || r.URL.RequestURI() != contract.Floating[v.Operation].Path {
					t.Errorf("unexpected wire request %s %s", r.Method, r.URL.RequestURI())
				}
				expected := contract.Floating[v.Operation].Body
				if v.Request != nil {
					expected = v.Request
				}
				if !reflect.DeepEqual(body, expected) {
					t.Errorf("wrong request body: %+v", body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(v.Status)
				_, _ = w.Write([]byte(v.Body))
			}))
			defer server.Close()
			client := New(server.URL, Options{DisableOfflineCache: true})
			if v.Operation == "meter" {
				if client.Meter("QA-METER-KEY", "qa_export", v.Quantity, v.Meta) != v.Released {
					t.Error("unexpected metering acknowledgement")
				}
				if requests != 1 {
					t.Error("wrong request count")
				}
			} else if v.Operation == "deactivate" {
				if client.Deactivate("qa-tenant", "QA-DEVICE-KEY", "11111111-2222-3333-4444-555555555555") != v.Released {
					t.Error("unexpected deactivation acknowledgement")
				}
				if requests != 1 {
					t.Errorf("request count %d", requests)
				}
			} else if v.Operation == "checkin" {
				if got := client.TryCheckin("qa-floating-token"); got != v.Released {
					t.Errorf("release=%t want %t", got, v.Released)
				}
				client.Checkin("qa-floating-token")
				if requests != 2 {
					t.Errorf("POST count %d want 2", requests)
				}
			} else {
				var result *FloatingSession
				if v.Operation == "checkout" {
					result = client.Checkout("QA-FLOAT-KEY", "qa-device", "QA desktop")
				} else {
					result = client.Heartbeat("qa-floating-token")
				}
				if result.Success != v.Success || result.ErrorCode != v.Code {
					t.Errorf("unexpected result: %+v", result)
				}
				if result.Success {
					if result.SessionToken != "qa-floating-token" || result.ExpiresAt == "" {
						t.Error("missing session evidence")
					}
				} else if result.SessionToken != "" || result.ExpiresAt != "" {
					t.Error("failed response leaked session credentials")
				}
				expectedRequests := 1
				if v.Operation == "heartbeat" && v.Status >= 500 {
					expectedRequests = 3
				}
				if requests != expectedRequests {
					t.Errorf("POST count %d want %d", requests, expectedRequests)
				}
			}
		})
	}
}

func TestFloatingConnectionResetFailsClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	defer func() { listener.Close(); <-done }()
	client := New("http://"+listener.Addr().String(), Options{DisableOfflineCache: true, Timeout: time.Second})
	for _, operation := range []string{"checkout", "heartbeat", "checkin", "deactivate", "meter"} {
		t.Run(operation, func(t *testing.T) {
			if operation == "meter" {
				if client.Meter("QA-METER-KEY", "qa_export", 1, nil) {
					t.Error("network failure confirmed usage")
				}
			} else if operation == "deactivate" {
				if client.Deactivate("qa-tenant", "QA-DEVICE-KEY", "11111111-2222-3333-4444-555555555555") {
					t.Error("network failure confirmed removal")
				}
			} else if operation == "checkin" {
				if client.TryCheckin("qa-floating-token") {
					t.Error("reset confirmed release")
				}
				client.Checkin("qa-floating-token")
				return
			}
			var result *FloatingSession
			if operation == "checkout" {
				result = client.Checkout("QA-FLOAT-KEY", "qa-device", "")
			} else {
				result = client.Heartbeat("qa-floating-token")
			}
			if result.Success || result.ErrorCode != "RequestFailed" || result.SessionToken != "" || result.ExpiresAt != "" {
				t.Errorf("reset granted credentials: %+v", result)
			}
		})
	}
}
