// PermitCore Go SDK Tester
// Run: go run ./tester
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	permitcore "github.com/permitCore-spec/permitcore-sdk-go"
)

var (
	apiURL     string
	licenseKey string
	reader     = bufio.NewReader(os.Stdin)
)

const (
	colReset  = "\033[0m"
	colGreen  = "\033[92m"
	colRed    = "\033[91m"
	colYellow = "\033[93m"
	colDim    = "\033[90m"
	colCyan   = "\033[36m"
)

func ok(msg string)   { fmt.Println(colGreen + msg + colReset) }
func fail(msg string) { fmt.Println(colRed + msg + colReset) }
func warn(msg string) { fmt.Println(colYellow + msg + colReset) }
func dim(msg string)  { fmt.Println(colDim + msg + colReset) }

func banner() {
	fmt.Println("\033[95m")
	fmt.Println("  ╔══════════════════════════════════════╗")
	fmt.Println("  ║    PermitCore  ·  Go SDK Tester      ║")
	fmt.Println("  ╚══════════════════════════════════════╝")
	fmt.Println(colReset)
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}

func prompt(label string) string {
	fmt.Print(label)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func pressEnter() {
	fmt.Print("\n  Press Enter to continue...")
	_, _ = reader.ReadString('\n')
}

func printResult(r *permitcore.LicenseResult) {
	fmt.Println()
	if r.IsValid {
		ok("  ✓  LICENSE VALID")
	} else {
		fail("  ✗  LICENSE INVALID")
	}
	if r.IsOffline {
		warn("  ⚡ Offline mode (served from local cache)")
	}

	printField := func(label, val string) {
		if val != "" {
			fmt.Printf("  %-24s %s\n", label, val)
		}
	}
	printField("Product", r.ProductName)
	printField("Message", r.Message)
	if r.RemainingActivations != nil {
		printField("Remaining activations", fmt.Sprintf("%d", *r.RemainingActivations))
	}
	printField("Expires at", r.ExpiresAt)
	if r.IsTrial {
		days := 0
		if r.TrialDaysRemaining != nil {
			days = *r.TrialDaysRemaining
		}
		printField("Trial", fmt.Sprintf("Yes (%d days remaining)", days))
	}
	if r.NodeLocked {
		printField("Node-locked", "Yes")
	}
	if len(r.Features) > 0 {
		printField("Features", strings.Join(r.Features, ", "))
	}
	if len(r.CustomFields) > 0 {
		fmt.Println("  Custom fields:")
		for k, v := range r.CustomFields {
			fmt.Printf("    %s: %s\n", k, v)
		}
	}
}

func ready() bool {
	if apiURL == "" {
		warn("  Set API URL first (option 1).")
		return false
	}
	if licenseKey == "" {
		warn("  Set License Key first (option 2).")
		return false
	}
	return true
}

func main() {
	for {
		clearScreen()
		banner()

		urlDisplay, urlColor := "(not set)", colDim
		if apiURL != "" {
			urlDisplay, urlColor = apiURL, colCyan
		}
		keyDisplay, keyColor := "(not set)", colDim
		if licenseKey != "" {
			keyDisplay, keyColor = licenseKey, colYellow
		}

		fmt.Printf("  API URL    : %s%s%s\n", urlColor, urlDisplay, colReset)
		fmt.Printf("  License    : %s%s%s\n", keyColor, keyDisplay, colReset)
		fmt.Println()
		fmt.Println("  [1]  Set API URL")
		fmt.Println("  [2]  Set License Key")
		fmt.Println("  [3]  Validate")
		fmt.Println("  [4]  Activate  (this machine)")
		fmt.Println("  [5]  Test offline cache  (simulate no server)")
		fmt.Println("  [6]  Checkout floating seat")
		fmt.Println("  [7]  Show Hardware ID")
		fmt.Println("  [Q]  Quit")
		fmt.Println()

		choice := strings.ToUpper(prompt("  Choice: "))
		fmt.Println()

		switch choice {
		case "1":
			apiURL = prompt("  API URL (e.g. http://localhost:5127): ")

		case "2":
			licenseKey = prompt("  License Key (PERMIT-XXXX-...): ")

		case "3":
			if !ready() {
				pressEnter()
				continue
			}
			fmt.Println("  Validating...")
			r := permitcore.New(apiURL).Validate(licenseKey, "")
			printResult(r)
			pressEnter()

		case "4":
			if !ready() {
				pressEnter()
				continue
			}
			hwid := permitcore.GetHardwareID()
			if len(hwid) > 12 {
				fmt.Printf("  HWID: %s…\n", hwid[:12])
			}
			fmt.Println("  Activating...")
			host, _ := os.Hostname()
			r := permitcore.New(apiURL).Activate(licenseKey, "", host, "")
			printResult(r)
			pressEnter()

		case "5":
			if licenseKey == "" {
				warn("  Set License Key first (option 2).")
				pressEnter()
				continue
			}
			fmt.Println("  Loading from offline cache (no server contact)...")
			c := permitcore.New("http://0.0.0.0:1", permitcore.Options{Timeout: 1 * time.Second})
			r := c.Validate(licenseKey, "")
			printResult(r)
			if !r.IsOffline && !r.IsValid {
				warn("  No offline cache found. Validate/Activate first to seed the cache.")
			}
			pressEnter()

		case "6":
			if !ready() {
				pressEnter()
				continue
			}
			fmt.Println("  Checking out floating seat...")
			c := permitcore.New(apiURL)
			s := c.Checkout(licenseKey, "", "")
			if s.Success {
				ok("  Checked out! Session: " + s.SessionToken)
				ok("  Expires: " + s.ExpiresAt)
				prompt("\n  Press Enter to check back in (return seat)... ")
				c.Checkin(s.SessionToken)
				ok("  Checked in — seat returned.")
			} else {
				fail("  Checkout failed: " + s.Message)
			}
			pressEnter()

		case "7":
			hwid := permitcore.GetHardwareID()
			ok("  Hardware ID: " + hwid)
			dim("  (This is the device fingerprint used during Activate)")
			pressEnter()

		case "Q":
			fmt.Println("  Bye!")
			return

		default:
			warn("  Unknown option.")
			pressEnter()
		}
	}
}
