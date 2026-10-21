package securecrt

import (
	"path"
	"strings"
)

// Identity is where a session's private key was, as far as the upload can
// tell.
//
// SecureCRT stores a key by path, never by content: a session says
// "Identity Filename V2" and the key itself sits wherever the user kept it —
// by default as Identity and Identity.pub in Documents (Windows) or ~/.ssh,
// which is outside the Config folder people zip. So resolving an identity
// means turning SecureCRT's path into names worth looking for in whatever
// was uploaded beside the configuration.
type Identity struct {
	// Raw is the value exactly as SecureCRT stored it, for messages.
	Raw string

	// Relative is the path under the Config folder, when SecureCRT recorded
	// one through ${VDS_CONFIG_PATH}. Empty otherwise.
	Relative string

	// Names are the file names to look for, most likely first: the private
	// key's own name and, as SecureCRT itself falls back to since 8.7, the
	// same name with .ppk.
	Names []string

	// Hardware is a smart card or token (PKCS#11, or a Windows certificate
	// store): there is no file, and nothing that can be copied.
	Hardware bool
}

// ResolveIdentity reads one "Identity Filename V2" value.
//
// The value may carry SecureCRT's path variables (${VDS_CONFIG_PATH},
// ${VDS_USER_DATA_PATH}, ${VDS_SSH_DATA_PATH}, ${VDS_INSTALL_PATH}), Windows
// or POSIX separators, a "::rawkey" style suffix, and may name either half of
// the pair — the .pub or the private key — because SecureCRT finds one from
// the other by name. An empty value resolves to the zero Identity.
func ResolveIdentity(raw string) Identity {
	raw = strings.TrimSpace(raw)
	id := Identity{Raw: raw}
	if raw == "" {
		return id
	}

	// A token locator is "pkcs11::prov=…" or "pkcs11key::prov=…" (or a CAPI
	// equivalent); a key file that merely starts with those letters is not.
	lower := strings.ToLower(raw)
	if (strings.HasPrefix(lower, "pkcs11") || strings.HasPrefix(lower, "capi")) &&
		strings.Contains(lower, "::") {
		id.Hardware = true
		return id
	}

	// "::rawkey" and friends are options on the path, not part of it. A
	// Windows drive letter has a single colon, so it is left alone.
	if i := strings.Index(raw, "::"); i >= 0 {
		raw = raw[:i]
	}

	clean := strings.ReplaceAll(raw, `\`, "/")
	const configVar = "${VDS_CONFIG_PATH}"
	if strings.HasPrefix(strings.ToUpper(clean), configVar) {
		id.Relative = strings.TrimPrefix(path.Clean("/"+clean[len(configVar):]), "/")
	}

	base := path.Base(clean)
	if base == "." || base == "/" || base == "" {
		return id
	}
	// Named by its public half: the private key is the same name without it.
	if strings.EqualFold(path.Ext(base), ".pub") {
		base = strings.TrimSuffix(base, path.Ext(base))
	}

	id.Names = []string{base}
	if path.Ext(base) == "" {
		id.Names = append(id.Names, base+".ppk")
	}
	if id.Relative != "" && !strings.EqualFold(path.Base(id.Relative), base) {
		id.Relative = path.Join(path.Dir(id.Relative), base)
	}
	return id
}
