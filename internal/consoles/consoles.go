// Package consoles turns a console server into a tree of connections.
//
// A console server is a box with a serial port per device and a network
// interface, and reaching line 12 means connecting to a port number derived
// from 12. There is no new protocol here — it is telnet or SSH, both of which
// this system already speaks — so what this package provides is the
// arithmetic and the tedium: one 48-port appliance becomes forty-eight saved
// connections, named, in a folder, with the right port on each.
//
// That is the whole feature, and it is worth having because the alternative
// is somebody creating forty-eight connections by hand and getting three of
// them wrong in a way nobody notices until an outage.
//
// # On the vendor defaults below
//
// These are the conventions the named appliances ship with, and they are
// defaults rather than laws: they are configurable on every one of these
// devices, and a rack that somebody set up in 2016 may well not match. So the
// base port is editable in the interface, the plan shows the resulting port
// on every line before anything is written, and the documentation says to
// check one against the device before creating fifty.
package consoles

import (
	"fmt"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// MaxLines bounds one generation.
//
// Large appliances stack to a few hundred ports; a thousand is beyond any of
// them and is the number at which somebody has typed a wrong figure into a
// form rather than described their rack.
const MaxLines = 512

// Profile is one vendor's port numbering.
type Profile struct {
	// ID is the stable identifier used by the API.
	ID string `json:"id"`

	// Name is what the interface shows.
	Name string `json:"name"`

	// TelnetBase and SSHBase are added to the line number to get the port.
	// Zero means the vendor does not offer that access method this way.
	TelnetBase int `json:"telnet_base"`
	SSHBase    int `json:"ssh_base"`

	// FirstLine is the number of the first physical port, which is 1 on
	// everything here — but stating it beats assuming it, and a device
	// numbered from 0 only needs a profile rather than a special case.
	FirstLine int `json:"first_line"`

	// Note is shown beside the choice, because the difference between these
	// profiles is exactly the sort of thing worth reading once.
	Note string `json:"note"`
}

// Profiles are the appliances people actually have.
//
// Deliberately short. A profile that is nearly right is worse than no
// profile, because it produces fifty connections that look correct and are
// not, so this lists the conventions that are widely documented and leaves
// everything else to the custom option — which is not a lesser choice, it is
// the same form with the numbers typed in.
func Profiles() []Profile {
	return []Profile{
		{
			ID: "opengear", Name: "Opengear",
			TelnetBase: 2000, SSHBase: 3000, FirstLine: 1,
			Note: "Telnet on 2000 + line, SSH on 3000 + line. Raw TCP is " +
				"usually 4000 + line if you need it.",
		},
		{
			ID: "lantronix", Name: "Lantronix SLC / SLB",
			TelnetBase: 2000, SSHBase: 3000, FirstLine: 1,
			Note: "Telnet on 2000 + line, SSH on 3000 + line.",
		},
		{
			ID: "cyclades", Name: "Avocent ACS / Cyclades",
			TelnetBase: 7001, SSHBase: 0, FirstLine: 0,
			Note: "Telnet on 7001 + line counted from zero, so line 1 is 7001. " +
				"SSH on these is usually reached as user:port rather than by " +
				"port number, which this cannot generate.",
		},
		{
			ID: "digi", Name: "Digi",
			TelnetBase: 2000, SSHBase: 0, FirstLine: 1,
			Note: "Telnet on 2000 + line. Raw TCP is usually 2100 + line.",
		},
		{
			ID: "custom", Name: "Something else",
			TelnetBase: 0, SSHBase: 0, FirstLine: 1,
			Note: "Type the base port from the appliance's own documentation.",
		},
	}
}

// ProfileByID finds a profile.
func ProfileByID(id string) (Profile, bool) {
	for _, profile := range Profiles() {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

// Params describe a console server to generate connections for.
type Params struct {
	// ProfileID names the vendor convention, or "custom".
	ProfileID string

	// Hostname is the appliance itself.
	Hostname string

	// Protocol is how to reach the lines: ssh or telnet.
	Protocol sessions.Protocol

	// BasePort overrides the profile's. Required for "custom".
	BasePort int

	// FirstLine and Lines describe the range: Lines ports starting at
	// FirstLine.
	FirstLine int
	Lines     int

	// NamePattern names each connection. %h is the appliance's hostname and
	// %n the line number; anything else is used as written.
	//
	// The line number is padded with zeroes to the width of the highest one,
	// so a 48-port appliance gives "line 01" through "line 48". Not
	// decoration: the tree sorts by name, and unpadded numbers put line 10
	// between line 1 and line 2, which on a rack diagram is nonsense.
	NamePattern string

	// Username and CredentialID are put on every generated connection, since
	// a console server has one login for all of its lines.
	Username     string
	CredentialID string

	// FolderID is where they go.
	FolderID string
}

// DefaultNamePattern is what the interface offers.
const DefaultNamePattern = "%h line %n"

// Line is one connection the plan would create.
type Line struct {
	Number int    `json:"line"`
	Name   string `json:"name"`
	Port   int    `json:"port"`
}

// Plan is what would be written, shown before anything is.
//
// The same shape as an import's preview and for the same reason: nothing here
// is written until somebody has seen what would happen. Fifty connections
// with a base port that was right for the last rack is a mistake worth
// catching on screen rather than in an outage.
type Plan struct {
	Profile  Profile           `json:"profile"`
	Protocol sessions.Protocol `json:"protocol"`
	Hostname string            `json:"hostname"`
	Lines    []Line            `json:"lines"`
	Warnings []string          `json:"warnings,omitempty"`
}

// Build works out what would be created, without creating it.
func Build(p Params) (Plan, error) {
	profile, ok := ProfileByID(p.ProfileID)
	if !ok {
		return Plan{}, fmt.Errorf("consoles: unknown profile %q", p.ProfileID)
	}

	if strings.TrimSpace(p.Hostname) == "" {
		return Plan{}, fmt.Errorf("consoles: the console server's address is required")
	}
	if p.Protocol == "" {
		p.Protocol = sessions.ProtocolSSH
	}
	switch p.Protocol {
	case sessions.ProtocolSSH, sessions.ProtocolTelnet:
	default:
		return Plan{}, fmt.Errorf(
			"consoles: a console server's lines are reached over ssh or telnet, not %s",
			p.Protocol)
	}

	base := p.BasePort
	if base == 0 {
		switch p.Protocol {
		case sessions.ProtocolTelnet:
			base = profile.TelnetBase
		default:
			base = profile.SSHBase
		}
	}
	if base == 0 {
		return Plan{}, fmt.Errorf(
			"consoles: %s does not have a documented %s port range here — "+
				"type the base port from the appliance's own documentation",
			profile.Name, p.Protocol)
	}

	if p.Lines < 1 {
		return Plan{}, fmt.Errorf("consoles: how many lines does it have?")
	}
	if p.Lines > MaxLines {
		return Plan{}, fmt.Errorf(
			"consoles: %d lines is more than the %d this will generate at once",
			p.Lines, MaxLines)
	}

	first := p.FirstLine
	if first == 0 {
		first = profile.FirstLine
	}

	pattern := p.NamePattern
	if strings.TrimSpace(pattern) == "" {
		pattern = DefaultNamePattern
	}

	plan := Plan{
		Profile:  profile,
		Protocol: p.Protocol,
		Hostname: p.Hostname,
		Lines:    make([]Line, 0, p.Lines),
	}

	// The width of the highest line number, for padding.
	width := len(fmt.Sprint(first + p.Lines - 1))

	for i := range p.Lines {
		number := first + i
		port := base + number

		if port < 1 || port > 65535 {
			return Plan{}, fmt.Errorf(
				"consoles: line %d would be port %d, which is not a port",
				number, port)
		}

		plan.Lines = append(plan.Lines, Line{
			Number: number,
			Name:   expandName(pattern, p.Hostname, number, width),
			Port:   port,
		})
	}

	if p.Protocol == sessions.ProtocolTelnet {
		plan.Warnings = append(plan.Warnings,
			"These lines will be reached over telnet, which sends everything "+
				"including the password in the clear. Most console servers also "+
				"offer SSH.")
	}
	if p.CredentialID == "" {
		plan.Warnings = append(plan.Warnings,
			"No credential was chosen, so each connection will ask for one. A "+
				"console server normally has a single login for all of its lines.")
	}

	return plan, nil
}

// expandName renders one connection's name, padding the line number.
func expandName(pattern, hostname string, line, width int) string {
	out := strings.ReplaceAll(pattern, "%h", hostname)
	return strings.ReplaceAll(out, "%n", fmt.Sprintf("%0*d", width, line))
}

// SessionParams turns a plan into the connections to create.
func (p Plan) SessionParams(ownerID, folderID, username, credentialID string) []sessions.CreateSessionParams {
	out := make([]sessions.CreateSessionParams, 0, len(p.Lines))
	for _, line := range p.Lines {
		out = append(out, sessions.CreateSessionParams{
			OwnerID:      ownerID,
			FolderID:     folderID,
			Name:         line.Name,
			Protocol:     p.Protocol,
			Hostname:     p.Hostname,
			Port:         line.Port,
			Username:     username,
			CredentialID: credentialID,
		})
	}
	return out
}
