package cmd

import (
	"context"
	"os"
	"sync"

	"github.com/op/go-logging"
	"github.com/incogbyte/gokbt/session"
	"github.com/incogbyte/gokbt/util"
	"github.com/spf13/cobra"
)

var (
	domain           string
	realm            string
	domainController string
	logFileName      string
	verbose          bool
	safe             bool
	delay            int
	jitter           int
	threads          int
	stopOnSuccess    bool
	userAsPass       = false

	downgrade   bool
	hashFileName string
	autoRealm    bool
	kdcDelaysRaw string
	silent        bool
	stopOnSuccessFlag bool
	
	maxFailures      int
	lockoutThreshold int
	outputValidFile  string
	resumeFile       string
	showProgress     bool
	passHash         string
	checkPasswordPolicy bool

	logger           util.Logger
	kSession         session.KerbruteSession
	domainPolicy     *util.DomainPasswordPolicy

	ctx         context.Context
	cancel      context.CancelFunc
	counter     int32
	successes   int32
	consecutiveFailures int32
	
	cancelOnce sync.Once
	
	userAttempts     map[string]int
	userAttemptsMu   sync.Mutex
)

func setupSession(cmd *cobra.Command, args []string) {
	cancelOnce = sync.Once{}
	ctx, cancel = context.WithCancel(context.Background())
	consecutiveFailures = 0
	userAttempts = make(map[string]int)

	if delay != 0 {
		threads = 1
	}

	logger = util.NewLogger(verbose, logFileName)
	if silent && !verbose {
		logging.SetLevel(logging.NOTICE, "")
	}
	kdcDelays, err := util.ParseKdcDelays(kdcDelaysRaw)
	if err != nil {
		logger.Log.Errorf("Invalid --kdc-delays: %v", err)
		os.Exit(1)
	}
	stopOnSuccess = stopOnSuccessFlag
	kOptions := session.KerbruteSessionOptions{
		Domain:           domain,
		Realm:            realm,
		AutoRealm:        autoRealm,
		DomainController: domainController,
		Verbose:          verbose,
		SafeMode:         safe,
		HashFilename:     hashFileName,
		Downgrade:        downgrade,
		KdcDelays:        kdcDelays,
	}
	k, err := session.NewKerbruteSession(kOptions)
	if err != nil {
		logger.Log.Error(err)
		os.Exit(1)
	}
	kSession = k

	if checkPasswordPolicy && domainController != "" {
		if policy, err := util.GetDomainPasswordPolicy(domainController); err == nil {
			domainPolicy = policy
			if !silent {
				logger.Log.Infof("Password policy: lockout threshold=%d, observation window=%d minutes", 
					policy.LockoutThreshold, policy.LockoutObservationWindow)
			}
		} else {
			logger.Log.Warningf("Failed to retrieve password policy: %v", err)
		}
	}

	if !silent {
		logger.Log.Info("Using KDC(s):")
		for _, v := range kSession.Kdcs {
			logger.Log.Infof("\t%s\n", v)
		}
		if delay != 0 {
			logger.Log.Infof("Delay set. Using single thread and delaying %dms between attempts\n", delay)
		}
		if passHash != "" {
			logger.Log.Info("Using Pass the Hash mode")
		}
	}
}
