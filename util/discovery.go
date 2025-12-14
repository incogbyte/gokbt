package util

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// DiscoverRealmFromLDAP tries to fetch the defaultNamingContext from the DC
// and converts it to an uppercase realm (DC=example,DC=com -> EXAMPLE.COM).
// Returns empty string on failure so callers can fall back gracefully.
func DiscoverRealmFromLDAP(dc string) (string, error) {
	if dc == "" {
		return "", fmt.Errorf("domain controller not specified")
	}
	addr := dc
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:389", dc)
	}

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", addr), ldap.DialWithDialer(defaultDialer()))
	if err != nil {
		return "", fmt.Errorf("ldap dial failed: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind("", ""); err != nil {
		// anonymous bind may fail depending on policy
		return "", fmt.Errorf("ldap anonymous bind failed: %w", err)
	}

	req := ldap.NewSearchRequest(
		"", // RootDSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("ldap search failed: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("ldap search returned no entries")
	}
	dn := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if dn == "" {
		return "", fmt.Errorf("defaultNamingContext not found")
	}
	return strings.ToUpper(dnToRealm(dn)), nil
}

func dnToRealm(dn string) string {
	parts := []string{}
	for _, part := range strings.Split(dn, ",") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(p), "DC=") && len(p) > 3 {
			parts = append(parts, p[3:])
		}
	}
	return strings.Join(parts, ".")
}

func defaultDialer() *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second}
}

