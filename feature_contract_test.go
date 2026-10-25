package permitcore

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSharedFeatureLookup(t *testing.T) {
	raw, err := os.ReadFile(testVectorPath("http-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Cases []struct {
			Name     string   `json:"name"`
			Features []string `json:"features"`
			Feature  string   `json:"feature"`
			Expected bool     `json:"expected"`
		} `json:"featureCases"`
	}
	if err = json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	for _, value := range contract.Cases {
		t.Run(value.Name, func(t *testing.T) {
			result := LicenseResult{Features: value.Features}
			if got := result.HasFeature(value.Feature); got != value.Expected {
				t.Errorf("feature=%t want %t", got, value.Expected)
			}
		})
	}
}
