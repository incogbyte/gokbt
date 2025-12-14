package cmd

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/incogbyte/gokbt/util"
)

func safeCancel() {
	cancelOnce.Do(func() {
		cancel()
	})
}

func makeSprayWorker(ctx context.Context, usernames <-chan string, wg *sync.WaitGroup, password string, userAsPass bool) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case username, ok := <-usernames:
			if !ok {
				return
			}
			if userAsPass {
				testLogin(ctx, username, username)
			} else {
				testLogin(ctx, username, password)
			}
		}
	}
}

func makeBruteWorker(ctx context.Context, passwords <-chan string, wg *sync.WaitGroup, username string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case password, ok := <-passwords:
			if !ok {
				return
			}
			testLogin(ctx, username, password)
		}
	}
}

func makeEnumWorker(ctx context.Context, usernames <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case username, ok := <-usernames:
			if !ok {
				return
			}
			testUsername(ctx, username)
		}
	}
}

func makeBruteComboWorker(ctx context.Context, combos <-chan [2]string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case combo, ok := <-combos:
			if !ok {
				return
			}
			testLogin(ctx, combo[0], combo[1])
		}
	}
}

var validOutputWriter *util.ValidOutputFile
var progressBar *util.ProgressBar

func testLogin(ctx context.Context, username string, password string) {
	if lockoutThreshold > 0 {
		userAttemptsMu.Lock()
		attempts := userAttempts[username]
		if attempts >= lockoutThreshold {
			userAttemptsMu.Unlock()
			logger.Log.Debugf("[!] Skipping %s - lockout threshold reached (%d attempts)", username, attempts)
			return
		}
		userAttempts[username] = attempts + 1
		userAttemptsMu.Unlock()
	}

	if domainPolicy != nil {
		if !util.CanAttemptLogin(username, domainPolicy) {
			logger.Log.Debugf("[!] Skipping %s - would exceed password policy lockout threshold", username)
			return
		}
	}

	atomic.AddInt32(&counter, 1)
	if progressBar != nil {
		progressBar.Increment()
	}
	
	var ok bool
	var err error
	login := fmt.Sprintf("%v@%v:%v", username, domain, password)
	
	if passHash != "" {
		ok, err = kSession.TestLoginWithHash(username, passHash)
	} else {
		ok, err = kSession.TestLogin(username, password)
	}
	
	if ok {
		atomic.AddInt32(&successes, 1)
		atomic.StoreInt32(&consecutiveFailures, 0)
		
		if progressBar != nil {
			progressBar.IncrementSuccess()
		}
		
		if err != nil {
			logger.Log.Noticef("[+] VALID LOGIN WITH ERROR:\t %s\t (%s)", login, err)
		} else {
			logger.Log.Noticef("[+] VALID LOGIN:\t %s", login)
		}
		
		if validOutputWriter != nil {
			validOutputWriter.Write(login)
		}
		
		if stopOnSuccess {
			safeCancel()
		}
		
		if domainPolicy != nil {
			util.RecordSuccessfulLogin(username)
		}
	} else {
		if domainPolicy != nil {
			util.RecordFailedLogin(username, domainPolicy)
		}
		
		failures := atomic.AddInt32(&consecutiveFailures, 1)
		if maxFailures > 0 && int(failures) >= maxFailures {
			logger.Log.Errorf("[!] Max consecutive failures (%d) reached, aborting...", maxFailures)
			safeCancel()
			return
		}
		
		// This is to determine if the error is "okay" or if we should abort everything
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", login, errorString)
			safeCancel()
		} else {
			logger.Log.Debugf("[!] %v - %v", login, errorString)
		}
	}
}

func testUsername(ctx context.Context, username string) {
	atomic.AddInt32(&counter, 1)
	if progressBar != nil {
		progressBar.Increment()
	}
	
	usernamefull := fmt.Sprintf("%v@%v", username, domain)
	valid, err := kSession.TestUsername(username)
	if valid {
		atomic.AddInt32(&successes, 1)
		atomic.StoreInt32(&consecutiveFailures, 0)
		
		if progressBar != nil {
			progressBar.IncrementSuccess()
		}
		
		if err != nil {
			logger.Log.Noticef("[+] VALID USERNAME WITH ERROR:\t %s\t (%s)", username, err)
		} else {
			logger.Log.Noticef("[+] VALID USERNAME:\t %s", usernamefull)
		}
		
		if validOutputWriter != nil {
			validOutputWriter.Write(usernamefull)
		}
		
		if stopOnSuccess {
			safeCancel()
		}

	} else if err != nil {
		failures := atomic.AddInt32(&consecutiveFailures, 1)
		if maxFailures > 0 && int(failures) >= maxFailures {
			logger.Log.Errorf("[!] Max consecutive failures (%d) reached, aborting...", maxFailures)
			safeCancel()
			return
		}
		
		// This is to determine if the error is "okay" or if we should abort everything
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", usernamefull, errorString)
			safeCancel()
		} else {
			logger.Log.Debugf("[!] %v - %v", usernamefull, errorString)
		}
	} else {
		logger.Log.Debug("[!] Unknown behavior - %v", usernamefull)
	}
}
