package snippets

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

func fixture(t *testing.T) (*Store, *store.DB, string) {
	t.Helper()

	db := storetest.New(t)
	userID := uuid.Must(uuid.NewV7()).String()

	if _, err := db.Exec(context.Background(),
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		userID, userID+"@example.com", userID+"@example.com",
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	return NewStore(db), db, userID
}

func TestParametersAreFoundInOrderOfAppearance(t *testing.T) {
	body := "interface {{interface}}\ndescription {{description}}\nswitchport access vlan {{vlan}}\nno shutdown"

	got := ParametersIn(body)
	want := []string{"interface", "description", "vlan"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parameter %d = %q, want %q — a dialog whose fields are "+
				"in a different order from the command is confusing", i, got[i], want[i])
		}
	}
}

func TestARepeatedParameterIsAskedOnce(t *testing.T) {
	got := ParametersIn("hostname {{name}}\nsnmp-server location {{name}}")
	if len(got) != 1 || got[0] != "name" {
		t.Fatalf("got %v, want one question", got)
	}
}

// TestRenderLeavesAMissingValueAsItWas.
//
// Sending `show interface ` to a switch because a field was blank produces an
// error nobody can interpret. Sending `show interface {{interface}}` produces
// one anybody can.
func TestRenderLeavesAMissingValueAsItWas(t *testing.T) {
	body := "show interface {{interface}} | include {{filter}}"

	got := Render(body, map[string]string{"interface": "Gi0/1"})
	if !strings.Contains(got, "Gi0/1") {
		t.Errorf("the value was not substituted: %q", got)
	}
	if !strings.Contains(got, "{{filter}}") {
		t.Errorf("a missing value became an empty string: %q", got)
	}
}

// TestAValueIsNotRescanned. A value containing something that looks like a
// placeholder is text, not another substitution.
func TestAValueIsNotRescanned(t *testing.T) {
	got := Render("echo {{a}}", map[string]string{"a": "{{b}}", "b": "surprise"})
	if got != "echo {{b}}" {
		t.Errorf("got %q — a substituted value was scanned again", got)
	}
}

func TestSnippetsRoundTrip(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	created, err := s.Create(ctx, CreateParams{
		OwnerID: userID, Name: "Describe a port",
		Description: "Sets the description on an access port",
		Body:        "interface {{interface}}\ndescription {{description}}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Parameters) != 2 {
		t.Errorf("parameters = %v", created.Parameters)
	}

	got, err := s.Get(ctx, userID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Describe a port" || got.Body != created.Body {
		t.Errorf("did not round-trip: %+v", got)
	}
	if len(got.Parameters) != 2 || got.Parameters[0] != "interface" {
		t.Errorf("parameters did not round-trip: %v", got.Parameters)
	}
}

// TestTheParameterListFollowsTheBody. Stored rather than re-derived on read,
// so the two must not be allowed to drift.
func TestTheParameterListFollowsTheBody(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	created, err := s.Create(ctx, CreateParams{
		OwnerID: userID, Name: "One", Body: "show interface {{interface}}",
	})
	if err != nil {
		t.Fatal(err)
	}

	body := "show version"
	updated, err := s.Update(ctx, userID, created.ID, UpdateParams{Body: &body})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Parameters) != 0 {
		t.Errorf("parameters = %v, want none after the body lost them", updated.Parameters)
	}

	reread, err := s.Get(ctx, userID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reread.Parameters) != 0 {
		t.Errorf("the stored list disagrees with the body: %v", reread.Parameters)
	}
}

// TestTwoSnippetsCannotShareAName, because the interface picks them by name
// and an ambiguous list is worse than a rejected save.
func TestTwoSnippetsCannotShareAName(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, CreateParams{
		OwnerID: userID, Name: "Save config", Body: "write memory",
	}); err != nil {
		t.Fatal(err)
	}

	_, err := s.Create(ctx, CreateParams{
		OwnerID: userID, Name: "Save config", Body: "copy run start",
	})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err = %v, want a duplicate", err)
	}
}

// TestSnippetsBelongToOnePerson.
func TestSnippetsBelongToOnePerson(t *testing.T) {
	s, db, alice := fixture(t)
	ctx := context.Background()

	bob := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		bob, "bob@example.com", "bob@example.com",
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	created, err := s.Create(ctx, CreateParams{
		OwnerID: alice, Name: "Alice's", Body: "write memory",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Get(ctx, bob, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob read alice's snippet: %v", err)
	}
	if err := s.Delete(ctx, bob, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob deleted alice's snippet: %v", err)
	}

	// And it is still there.
	if _, err := s.Get(ctx, alice, created.ID); err != nil {
		t.Errorf("alice lost her snippet: %v", err)
	}

	mine, err := s.ListForOwner(ctx, bob, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 0 {
		t.Errorf("bob's list has %d of alice's snippets", len(mine))
	}
}

func TestValidationRefusesTheObviousMistakes(t *testing.T) {
	cases := map[string][2]string{
		"no name":       {"", "write memory"},
		"no body":       {"Empty", ""},
		"body too long": {"Long", strings.Repeat("x", MaxBodyBytes+1)},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Validate(pair[0], pair[1]); err == nil {
				t.Error("must be refused")
			}
		})
	}

	var many strings.Builder
	for i := range MaxParameters + 1 {
		fmt := "{{p" + string(rune('a'+i)) + "}} "
		many.WriteString(fmt)
	}
	if err := Validate("Many", many.String()); err == nil {
		t.Error("a snippet asking more questions than the limit must be refused")
	}

	if err := Validate("Fine", "show interface {{interface}}"); err != nil {
		t.Errorf("an ordinary snippet must be valid: %v", err)
	}
}
