package util

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type PasswordPolicy struct {
	BadPwdCount        int
	LockoutThreshold   int
	LockoutDuration    int
	LockoutObservationWindow int
	LastBadPwdAttempt  time.Time
	mu                 sync.Mutex
}

type DomainPasswordPolicy struct {
	LockoutThreshold   int
	LockoutObservationWindow int
	LockoutDuration    int
}

var userPasswordPolicies = make(map[string]*PasswordPolicy)
var userPasswordPoliciesMu sync.Mutex

func GetDomainPasswordPolicy(dc string) (*DomainPasswordPolicy, error) {
	if dc == "" {
		return nil, fmt.Errorf("domain controller not specified")
	}
	addr := dc
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:389", dc)
	}

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", addr), ldap.DialWithDialer(defaultDialer()))
	if err != nil {
		return nil, fmt.Errorf("ldap dial failed: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind("", ""); err != nil {
		return nil, fmt.Errorf("ldap anonymous bind failed: %w", err)
	}

	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search failed: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("ldap search returned no entries")
	}
	baseDN := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		return nil, fmt.Errorf("defaultNamingContext not found")
	}

	domainDN := fmt.Sprintf("CN=Default Domain Policy,CN=System,%s", baseDN)
	req2 := ldap.NewSearchRequest(
		domainDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"lockoutThreshold", "lockoutDuration", "lockoutObservationWindow"},
		nil,
	)

	res2, err := conn.Search(req2)
	if err != nil {
		domainDN = fmt.Sprintf("CN=Default Domain Policy,CN=System,%s", baseDN)
		req2.BaseDN = domainDN
		res2, err = conn.Search(req2)
		if err != nil {
			return &DomainPasswordPolicy{
				LockoutThreshold:           0,
				LockoutObservationWindow:   0,
				LockoutDuration:            0,
			}, nil
		}
	}

	policy := &DomainPasswordPolicy{
		LockoutThreshold:           0,
		LockoutObservationWindow:   0,
		LockoutDuration:            0,
	}

	if len(res2.Entries) > 0 {
		entry := res2.Entries[0]
		if attr := entry.GetAttributeValue("lockoutThreshold"); attr != "" {
			if val := parseInt(attr); val > 0 {
				policy.LockoutThreshold = val
			}
		}
		if attr := entry.GetAttributeValue("lockoutDuration"); attr != "" {
			if val := parseInt(attr); val > 0 {
				policy.LockoutDuration = val
			}
		}
		if attr := entry.GetAttributeValue("lockoutObservationWindow"); attr != "" {
			if val := parseInt(attr); val > 0 {
				policy.LockoutObservationWindow = val
			}
		}
	}

	return policy, nil
}

func GetUserBadPwdCount(dc string, username string, baseDN string) (int, time.Time, error) {
	if dc == "" || username == "" || baseDN == "" {
		return 0, time.Time{}, fmt.Errorf("missing required parameters")
	}
	addr := dc
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:389", dc)
	}

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", addr), ldap.DialWithDialer(defaultDialer()))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("ldap dial failed: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind("", ""); err != nil {
		return 0, time.Time{}, fmt.Errorf("ldap anonymous bind failed: %w", err)
	}

	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(username))
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"badPwdCount", "badPasswordTime"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("ldap search failed: %w", err)
	}
	if len(res.Entries) == 0 {
		return 0, time.Time{}, fmt.Errorf("user not found")
	}

	entry := res.Entries[0]
	badPwdCount := 0
	if attr := entry.GetAttributeValue("badPwdCount"); attr != "" {
		badPwdCount = parseInt(attr)
	}

	badPasswordTime := time.Time{}
	if attr := entry.GetAttributeValue("badPasswordTime"); attr != "" {
		if val := parseInt64(attr); val > 0 {
			badPasswordTime = time.Unix(0, val*int64(100*time.Nanosecond))
		}
	}

	return badPwdCount, badPasswordTime, nil
}

func CanAttemptLogin(username string, policy *DomainPasswordPolicy) bool {
	if policy == nil || policy.LockoutThreshold == 0 {
		return true
	}

	userPasswordPoliciesMu.Lock()
	defer userPasswordPoliciesMu.Unlock()

	userPolicy, exists := userPasswordPolicies[username]
	if !exists {
		userPolicy = &PasswordPolicy{
			BadPwdCount: 0,
			LastBadPwdAttempt: time.Time{},
		}
		userPasswordPolicies[username] = userPolicy
	}

	now := time.Now()
	if !userPolicy.LastBadPwdAttempt.IsZero() {
		windowDuration := time.Duration(policy.LockoutObservationWindow) * time.Minute
		if windowDuration > 0 {
			elapsed := now.Sub(userPolicy.LastBadPwdAttempt)
			if elapsed > windowDuration {
				userPolicy.BadPwdCount = 0
			}
		}
	}

	if userPolicy.BadPwdCount >= policy.LockoutThreshold {
		return false
	}

	return true
}

func RecordFailedLogin(username string, policy *DomainPasswordPolicy) {
	if policy == nil {
		return
	}

	userPasswordPoliciesMu.Lock()
	defer userPasswordPoliciesMu.Unlock()

	userPolicy, exists := userPasswordPolicies[username]
	if !exists {
		userPolicy = &PasswordPolicy{
			BadPwdCount: 0,
			LastBadPwdAttempt: time.Time{},
		}
		userPasswordPolicies[username] = userPolicy
	}

	now := time.Now()
	windowDuration := time.Duration(policy.LockoutObservationWindow) * time.Minute
	if windowDuration > 0 {
		elapsed := now.Sub(userPolicy.LastBadPwdAttempt)
		if elapsed > windowDuration {
			userPolicy.BadPwdCount = 0
		}
	}

	userPolicy.BadPwdCount++
	userPolicy.LastBadPwdAttempt = now
}

func RecordSuccessfulLogin(username string) {
	userPasswordPoliciesMu.Lock()
	defer userPasswordPoliciesMu.Unlock()

	if userPolicy, exists := userPasswordPolicies[username]; exists {
		userPolicy.BadPwdCount = 0
		userPolicy.LastBadPwdAttempt = time.Time{}
	}
}

func parseInt(s string) int {
	var val int
	fmt.Sscanf(s, "%d", &val)
	return val
}

func parseInt64(s string) int64 {
	var val int64
	fmt.Sscanf(s, "%d", &val)
	return val
}

