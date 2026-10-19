package permitcore

import (
    "encoding/json"
    "testing"
)

func TestPaymentStatusAndGrace(t *testing.T) {
    var result LicenseResult
    if err := json.Unmarshal([]byte(`{"isValid":true,"paymentStatus":"past_due","isInGracePeriod":true}`), &result); err != nil { t.Fatal(err) }
    if !result.IsValid || result.PaymentStatus != "past_due" || !result.IsInGracePeriod { t.Fatalf("payment response lost: %+v", result) }
    var legacy LicenseResult
    if err := json.Unmarshal([]byte(`{"isValid":true}`), &legacy); err != nil { t.Fatal(err) }
    if legacy.PaymentStatus != "" || legacy.IsInGracePeriod { t.Fatal("legacy response changed") }
}
