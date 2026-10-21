package securecrt

import (
	"reflect"
	"testing"
)

func TestResolveIdentityReadsSecureCRTPaths(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Identity
	}{
		{"", Identity{}},
		{
			`C:\Users\alice\Documents\Identity`,
			Identity{Raw: `C:\Users\alice\Documents\Identity`, Names: []string{"Identity", "Identity.ppk"}},
		},
		{
			// Named by its public half, with a path variable and an option.
			`${VDS_USER_DATA_PATH}\Identity.pub::rawkey`,
			Identity{Raw: `${VDS_USER_DATA_PATH}\Identity.pub::rawkey`, Names: []string{"Identity", "Identity.ppk"}},
		},
		{
			`${VDS_CONFIG_PATH}\Keys\router_rsa`,
			Identity{Raw: `${VDS_CONFIG_PATH}\Keys\router_rsa`, Relative: "Keys/router_rsa",
				Names: []string{"router_rsa", "router_rsa.ppk"}},
		},
		{
			"~/.ssh/id_ed25519",
			Identity{Raw: "~/.ssh/id_ed25519", Names: []string{"id_ed25519", "id_ed25519.ppk"}},
		},
		{
			// A PuTTY key keeps its own name; there is no further fallback.
			`D:\keys\lab.ppk`,
			Identity{Raw: `D:\keys\lab.ppk`, Names: []string{"lab.ppk"}},
		},
		{
			"pkcs11::prov=C:\\Windows\\System32\\eTPKCS11.dll::cert",
			Identity{Raw: "pkcs11::prov=C:\\Windows\\System32\\eTPKCS11.dll::cert", Hardware: true},
		},
		{
			// A key file whose name merely starts like a token locator.
			`C:\keys\capital_key`,
			Identity{Raw: `C:\keys\capital_key`, Names: []string{"capital_key", "capital_key.ppk"}},
		},
		{
			// A network share.
			`\\files01\keys\ops_rsa.pub`,
			Identity{Raw: `\\files01\keys\ops_rsa.pub`, Names: []string{"ops_rsa", "ops_rsa.ppk"}},
		},
	} {
		if got := ResolveIdentity(tc.raw); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ResolveIdentity(%q)\n got %+v\nwant %+v", tc.raw, got, tc.want)
		}
	}
}
