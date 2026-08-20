package api

import (
	"net/http"
	"testing"
)

// The saved-connection tree's HTTP surface, where the errors a person can
// actually cause have to arrive as something they can act on.
// TestARefusedJumpChainIsA400NotA500. New error types default to "something
// went wrong on our side" unless someone maps them, which is both a lie and
// useless to the person who typed the thing.
func TestARefusedJumpChainIsA400NotA500(t *testing.T) {
	h := signedInWithVault(t)

	_, bastion := h.post("/api/tree/sessions", map[string]any{
		"name": "bastion", "hostname": "10.0.0.1",
	})
	bastionID, _ := bastion["id"].(string)

	cases := map[string]struct {
		chain []string
		code  string
	}{
		"a host that does not exist": {
			chain: []string{"01920000-0000-7000-8000-000000000000"},
			code:  "jump_host_not_found",
		},
		"the same host twice": {
			chain: []string{bastionID, bastionID},
			code:  "jump_chain_invalid",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp, body := h.post("/api/tree/sessions", map[string]any{
				"name": "target-" + name, "hostname": "10.0.0.9", "jump_chain": tc.chain,
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("= %d, want 400: %v", resp.StatusCode, body)
			}
			failure, _ := body["error"].(map[string]any)
			if got, _ := failure["code"].(string); got != tc.code {
				t.Errorf("code = %q, want %q", got, tc.code)
			}
		})
	}
}

// TestDeletingABastionInUseNamesWhatUsesIt.
func TestDeletingABastionInUseNamesWhatUsesIt(t *testing.T) {
	h := signedInWithVault(t)

	_, bastion := h.post("/api/tree/sessions", map[string]any{
		"name": "bastion", "hostname": "10.0.0.1",
	})
	bastionID, _ := bastion["id"].(string)

	if resp, body := h.post("/api/tree/sessions", map[string]any{
		"name": "core-sw-01", "hostname": "10.0.1.1", "jump_chain": []string{bastionID},
	}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the target = %d: %v", resp.StatusCode, body)
	}

	resp, body := h.do(http.MethodDelete, "/api/tree/sessions/"+bastionID, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("= %d, want 409: %v", resp.StatusCode, body)
	}

	failure, _ := body["error"].(map[string]any)
	if got, _ := failure["code"].(string); got != "jump_host_in_use" {
		t.Errorf("code = %q", got)
	}
	usedBy, _ := failure["used_by"].([]any)
	if len(usedBy) != 1 || usedBy[0] != "core-sw-01" {
		t.Errorf("used_by = %v, want [core-sw-01]", usedBy)
	}
}
