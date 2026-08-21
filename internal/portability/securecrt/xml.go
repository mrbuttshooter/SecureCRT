package securecrt

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
)

// SecureCRT's other export format.
//
// Tools → Export Settings writes the entire configuration as one XML file —
// the official backup path, and for plenty of people the only artefact they
// can produce: zipping %APPDATA% is exactly the kind of thing a locked-down
// corporate desktop forbids while the File menu still works.
//
// The XML carries the same keys as the INI files, nested instead of flat:
// sessions live under <key name="Sessions">, folders are keys containing
// keys, and a session is a key carrying the familiar "Protocol Name",
// "Hostname", "Password V2" values. So this reader does the minimum
// honest thing: it walks the tree, synthesises the same File structure the
// INI parser produces, and hands each one to the same ReadSession — one set
// of session semantics, two containers.

// xmlNode is any element under a <key>: we care about its name attribute,
// its text, and its children.
type xmlNode struct {
	XMLName xml.Name
	Name    string    `xml:"name,attr"`
	Value   string    `xml:",chardata"`
	Nodes   []xmlNode `xml:",any"`
}

// IsSecureCRTXML sniffs an upload for the export format.
func IsSecureCRTXML(data []byte) bool {
	head := data
	if len(head) > 512 {
		head = head[:512]
	}
	return bytes.Contains(head, []byte("<VanDyke"))
}

// ReadXML reads an exported settings file.
func ReadXML(data []byte, opts ReadOptions) (Result, error) {
	var root xmlNode
	if err := xml.Unmarshal(data, &root); err != nil {
		return Result{}, fmt.Errorf("securecrt: parse the settings XML: %w", err)
	}

	var result Result

	sessions := findKey(root.Nodes, "Sessions")
	if sessions == nil {
		result.Warnings = append(result.Warnings,
			"The XML has no Sessions section. Export settings from the same "+
				"SecureCRT that holds your connections.")
		return result, nil
	}

	walkXMLSessions(*sessions, nil, opts, &result)
	return result, nil
}

// walkXMLSessions descends the Sessions tree, folders as path.
func walkXMLSessions(node xmlNode, folders []string, opts ReadOptions, result *Result) {
	for _, child := range node.Nodes {
		if child.XMLName.Local != "key" {
			continue
		}

		if isSessionKey(child) {
			file := fileFromXMLKey(child)
			relative := joinPath(folders, child.Name)
			session := ReadSession(file, relative+".ini", opts)
			// ReadSession names the session from the filename; the XML key
			// name is authoritative and needs no .ini surgery.
			session.Name = child.Name
			session.Path = relative

			// The Default session is settings, not a place: no hostname, and
			// importing it would manufacture a broken connection named
			// "Default" at the root of everybody's tree.
			if session.Hostname == "" && session.Name == "Default" {
				continue
			}
			result.Sessions = append(result.Sessions, session)
			continue
		}

		// A fresh slice per branch: append(folders, ...) reuses the parent's
		// backing array, and siblings sharing it silently rewrite each
		// other's paths — sessions land in the wrong folders.
		branch := make([]string, 0, len(folders)+1)
		branch = append(branch, folders...)
		branch = append(branch, child.Name)
		walkXMLSessions(child, branch, opts, result)
	}
}

// isSessionKey tells a session from a folder: sessions carry a protocol.
func isSessionKey(node xmlNode) bool {
	for _, child := range node.Nodes {
		if child.XMLName.Local == "string" && child.Name == "Protocol Name" {
			return true
		}
	}
	return false
}

// fileFromXMLKey rebuilds the INI parser's File from a session key, so both
// formats flow through one ReadSession.
func fileFromXMLKey(node xmlNode) *File {
	file := &File{byKey: map[string]Entry{}}
	add := func(entry Entry) {
		file.Entries = append(file.Entries, entry)
		if _, exists := file.byKey[entry.Key]; !exists {
			file.byKey[entry.Key] = entry
		}
	}
	for _, child := range node.Nodes {
		switch child.XMLName.Local {
		case "string":
			add(Entry{Type: "S", Key: child.Name, Value: child.Value})
		case "dword":
			// The XML writes decimal; File.Number parses hex first, because
			// the INI format writes hex. Re-encode so 22 stays port 22
			// rather than becoming 0x22.
			value := child.Value
			if n, err := strconv.ParseUint(child.Value, 10, 32); err == nil {
				value = fmt.Sprintf("%08X", n)
			}
			add(Entry{Type: "D", Key: child.Name, Value: value})
		case "binary":
			add(Entry{Type: "B", Key: child.Name, Value: child.Value})
		}
	}
	return file
}

func findKey(nodes []xmlNode, name string) *xmlNode {
	for i := range nodes {
		if nodes[i].XMLName.Local == "key" && nodes[i].Name == name {
			return &nodes[i]
		}
	}
	return nil
}

func joinPath(folders []string, name string) string {
	out := ""
	for _, f := range folders {
		out += f + "/"
	}
	return out + name
}
