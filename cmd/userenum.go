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

var userEnumCommand = &cobra.Command{
	Use:   "userenum [flags] <username_wordlist>",
	Short: "Enumerate valid domain usernames via Kerberos",
	Long: `Will enumerate valid usernames from a list by constructing AS-REQs to requesting a TGT from the KDC.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
Valid usernames will be displayed on stdout.`,
	Args:   cobra.ExactArgs(1),
	PreRun: setupSession,
	Run:    userEnum,
}

func init() {
	rootCmd.AddCommand(userEnumCommand)
}

func userEnum(cmd *cobra.Command, args []string) {
	usernamelist := args[0]
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
	progressBar = util.NewProgressBar(lineCount, showProgress && lineCount > 0, "UserEnum")
	progressBar.Start()

	var localResumeState *util.ResumeState
	if resumeFile != "" {
		if rs, err := util.LoadResumeState(resumeFile); err == nil {
			localResumeState = rs
			logger.Log.Infof("Resuming from %s, skipping %d already processed", resumeFile, len(rs.Processed))
		} else {
			localResumeState = util.NewResumeState(resumeFile, "userenum", usernamelist)
		}
	}

	for i := 0; i < threads; i++ {
		go makeEnumWorker(ctx, usersChan, &wg)
	}

	start := time.Now()

	go func() {
		defer close(usersChan)
		for scanner.Scan() {
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

			if localResumeState != nil && localResumeState.IsProcessed(username) {
				continue
			}

			time.Sleep(util.JitterDelay(delay, jitter))
			select {
			case usersChan <- username:
				if localResumeState != nil {
					localResumeState.MarkProcessed(username)
				}
			case <-ctx.Done():
			}
		}
		if err := scanner.Err(); err != nil {
			logger.Log.Errorf("Error reading file: %s", err.Error())
		}
	}()
	
	wg.Wait()
	progressBar.Stop()

	if localResumeState != nil {
		if err := localResumeState.Save(); err != nil {
			logger.Log.Errorf("Failed to save resume state: %v", err)
		}
	}

	finalCount := atomic.LoadInt32(&counter)
	finalSuccess := atomic.LoadInt32(&successes)
	logger.Log.Infof("Done! Tested %d usernames (%d valid) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())
	logger.Log.Infof("Input stats: total=%d blanks=%d invalid=%d deduped=%d sent=%d", total, blanks, invalid, deduped, len(seen))

	if err := kSession.Close(); err != nil {
		logger.Log.Errorf("Error closing session: %s", err.Error())
	}
}
