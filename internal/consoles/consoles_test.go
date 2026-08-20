package consoles

import (
	"strings"
	"testing"

	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// TestAnOpengearBecomesARackOfLines is the feature: one appliance in, a
// numbered rack out, with the arithmetic done once rather than forty-eight
// times by hand.
func TestAnOpengearBecomesARackOfLines(t *testing.T) {
	plan, err := Build(Params{
		ProfileID: "opengear",
		Hostname:  "console-01.example.com",
		Protocol:  sessions.ProtocolSSH,
		Lines:     48,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(plan.Lines) != 48 {
		t.Fatalf("got %d lines, want 48", len(plan.Lines))
	}

	first, last := plan.Lines[0], plan.Lines[47]
	if first.Number != 1 || first.Port != 3001 {
		t.Errorf("first line = %d on port %d, want 1 on 3001", first.Number, first.Port)
	}
	if last.Number != 48 || last.Port != 3048 {
		t.Errorf("last line = %d on port %d, want 48 on 3048", last.Number, last.Port)
	}
}

// TestLineNumbersArePaddedSoTheRackSortsLikeARack.
//
// The tree sorts by name. Unpadded, line 10 lands between line 1 and line 2,
// which on a rack diagram is nonsense and in an incident is worse.
func TestLineNumbersArePaddedSoTheRackSortsLikeARack(t *testing.T) {
	plan, err := Build(Params{
		ProfileID: "opengear", Hostname: "con1",
		Protocol: sessions.ProtocolTelnet, Lines: 48,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := plan.Lines[0].Name; got != "con1 line 01" {
		t.Errorf("first name = %q, want a padded number", got)
	}
	if got := plan.Lines[47].Name; got != "con1 line 48" {
		t.Errorf("last name = %q", got)
	}

	// A small appliance is not padded to a width it does not need.
	small, err := Build(Params{
		ProfileID: "opengear", Hostname: "con1",
		Protocol: sessions.ProtocolTelnet, Lines: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := small.Lines[0].Name; got != "con1 line 1" {
		t.Errorf("an eight-port appliance gave %q, want no padding", got)
	}
}

// TestTheCycladesProfileCountsFromZero, which is the whole reason FirstLine
// is a field rather than an assumption.
func TestTheCycladesProfileCountsFromZero(t *testing.T) {
	plan, err := Build(Params{
		ProfileID: "cyclades", Hostname: "acs",
		Protocol: sessions.ProtocolTelnet, Lines: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Lines[0].Port != 7001 {
		t.Errorf("the first line is port %d, want 7001", plan.Lines[0].Port)
	}
}

// TestAVendorWithoutAPortRangeSaysSoRatherThanGuessing.
//
// A profile that is nearly right is worse than no profile: it produces fifty
// connections that look correct and are not.
func TestAVendorWithoutAPortRangeSaysSoRatherThanGuessing(t *testing.T) {
	_, err := Build(Params{
		ProfileID: "cyclades", Hostname: "acs",
		Protocol: sessions.ProtocolSSH, Lines: 4,
	})
	if err == nil {
		t.Fatal("a profile with no documented SSH range must not invent one")
	}
	if !strings.Contains(err.Error(), "base port") {
		t.Errorf("the error does not say what to do: %v", err)
	}
}

// TestACustomBasePortOverridesTheProfile, because these are defaults and
// every one of these appliances lets somebody change them.
func TestACustomBasePortOverridesTheProfile(t *testing.T) {
	plan, err := Build(Params{
		ProfileID: "custom", Hostname: "con1",
		Protocol: sessions.ProtocolTelnet, BasePort: 9000, Lines: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Lines[0].Port != 9001 || plan.Lines[1].Port != 9002 {
		t.Errorf("ports = %d, %d, want 9001 and 9002",
			plan.Lines[0].Port, plan.Lines[1].Port)
	}
}

// TestTelnetIsFlaggedInThePlan. Somebody generating fifty connections should
// be told once, before writing them, that all fifty will send the password in
// the clear.
func TestTelnetIsFlaggedInThePlan(t *testing.T) {
	plan, err := Build(Params{
		ProfileID: "opengear", Hostname: "con1",
		Protocol: sessions.ProtocolTelnet, Lines: 2, CredentialID: "c1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Warnings) == 0 {
		t.Fatal("generating fifty telnet connections warned about nothing")
	}
	if !strings.Contains(strings.Join(plan.Warnings, " "), "clear") {
		t.Errorf("the warning does not say what the cost is: %v", plan.Warnings)
	}
}

// TestARangeThatRunsOffTheEndOfThePortsIsRefused.
func TestARangeThatRunsOffTheEndOfThePortsIsRefused(t *testing.T) {
	_, err := Build(Params{
		ProfileID: "custom", Hostname: "con1",
		Protocol: sessions.ProtocolTelnet, BasePort: 65500, Lines: 512,
	})
	if err == nil {
		t.Fatal("a range past 65535 must be refused rather than wrapped")
	}
}

// TestTheGeneratedConnectionsCarryTheSharedLogin.
//
// A console server has one login for all of its lines, which is the other
// half of the tedium this removes.
func TestTheGeneratedConnectionsCarryTheSharedLogin(t *testing.T) {
	plan, err := Build(Params{
		ProfileID: "opengear", Hostname: "con1",
		Protocol: sessions.ProtocolSSH, Lines: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	params := plan.SessionParams("owner", "folder", "root", "cred-1")
	if len(params) != 3 {
		t.Fatalf("got %d connections", len(params))
	}
	for _, p := range params {
		if p.Username != "root" || p.CredentialID != "cred-1" {
			t.Errorf("a generated connection lost its login: %+v", p)
		}
		if p.FolderID != "folder" || p.OwnerID != "owner" {
			t.Errorf("a generated connection landed in the wrong place: %+v", p)
		}
		if p.Hostname != "con1" {
			t.Errorf("hostname = %q, want the appliance", p.Hostname)
		}
	}
	if params[0].Port != 3001 || params[2].Port != 3003 {
		t.Errorf("ports = %d..%d", params[0].Port, params[2].Port)
	}
}

// TestBadInputIsRefusedBeforeAnythingIsPlanned.
func TestBadInputIsRefusedBeforeAnythingIsPlanned(t *testing.T) {
	cases := map[string]Params{
		"no profile":  {Hostname: "c", Lines: 4},
		"no hostname": {ProfileID: "opengear", Lines: 4},
		"no lines":    {ProfileID: "opengear", Hostname: "c"},
		"too many":    {ProfileID: "opengear", Hostname: "c", Lines: MaxLines + 1},
		"serial":      {ProfileID: "opengear", Hostname: "c", Lines: 4, Protocol: sessions.ProtocolSerial},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(params); err == nil {
				t.Error("must be refused")
			}
		})
	}
}
