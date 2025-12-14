package cmd

import (
	"fmt"
	"os"

	"github.com/incogbyte/gokbt/util"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gokbt",
	Short: "A tool to perform various bruteforce attacks against Windows Kerberos",
	Long: `This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if !silent {
			util.PrintBanner()
		}
	}
	rootCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "The full domain to use (e.g. contoso.com)")
	rootCmd.PersistentFlags().StringVar(&realm, "realm", "", "Optional Kerberos realm override (defaults to uppercased domain)")
	rootCmd.PersistentFlags().StringVar(&domainController, "dc", "", "The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS")
	rootCmd.PersistentFlags().BoolVar(&autoRealm, "auto-realm", false, "Attempt to discover realm via LDAP before running (requires --dc)")
	rootCmd.PersistentFlags().StringVar(&kdcDelaysRaw, "kdc-delays", "", "Per-KDC delay in ms, comma-separated (host:port=delay,...)")
	rootCmd.PersistentFlags().StringVarP(&logFileName, "output", "o", "", "File to write logs to. Optional.")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Log failures and errors")
	rootCmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "Hide banner and info/debug logs; only show findings/errors")
	rootCmd.PersistentFlags().BoolVar(&stopOnSuccessFlag, "stop-on-success", false, "Stop after first successful username/login")
	rootCmd.PersistentFlags().BoolVar(&stopOnSuccessFlag, "sts", false, "Alias for --stop-on-success")
	rootCmd.PersistentFlags().BoolVar(&safe, "safe", false, "Safe mode. Will abort if any user comes back as locked out. Default: FALSE")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 10, "Threads to use")
	rootCmd.PersistentFlags().IntVarP(&delay, "delay", "", 0, "Delay in millisecond between each attempt. Will always use single thread if set")
	rootCmd.PersistentFlags().IntVar(&jitter, "jitter", 0, "Random jitter in ms to add/subtract from delay (e.g. --delay 100 --jitter 50 = 50-150ms)")
	rootCmd.PersistentFlags().BoolVar(&downgrade, "downgrade", false, "Force downgraded encryption type (arcfour-hmac-md5)")
	rootCmd.PersistentFlags().StringVar(&hashFileName, "hash-file", "", "File to save AS-REP hashes to (if any captured), otherwise just logged")
	rootCmd.PersistentFlags().IntVar(&maxFailures, "max-failures", 0, "Abort after N consecutive failures (0 = disabled)")
	rootCmd.PersistentFlags().IntVar(&lockoutThreshold, "lockout-threshold", 0, "Stop testing a user after N attempts (0 = disabled)")
	rootCmd.PersistentFlags().StringVar(&outputValidFile, "output-valid", "", "File to save valid usernames/credentials")
	rootCmd.PersistentFlags().StringVar(&resumeFile, "resume", "", "Resume file to save/load progress")
	rootCmd.PersistentFlags().BoolVar(&showProgress, "progress", false, "Show progress bar")
	rootCmd.PersistentFlags().StringVar(&passHash, "pass-the-hash", "", "Use NTLM hash instead of password (format: hex hash) [WIP - Work In Progress]")
	rootCmd.PersistentFlags().BoolVar(&checkPasswordPolicy, "check-password-policy", false, "Check AD password policy before attempting login (requires --dc)")
	if delay != 0 {
		threads = 1
	}

}
