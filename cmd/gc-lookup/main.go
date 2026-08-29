// Command gc-lookup is a CLI for the GetContact lookup protocol — a faithful
// port of gtc.py (github.com/xdreizein666/getcontact-cli). Credentials are
// stored at $GTC_CONFIG_DIR/credentials.json (default ~/.config/gtc/) exactly
// like the Python reference.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/oyi77/gc-lookup/internal/client"
)

// newClient is a function variable so tests can substitute a client whose
// transport serves synthetic protocol responses (no network).
var newClient = client.New

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "search":
		cmdSearch(os.Args[2:])
	case "subscription":
		cmdSubscription(os.Args[2:])
	case "refresh-code":
		cmdRefreshCode(os.Args[2:])
	case "verify-code":
		cmdVerifyCode(os.Args[2:])
	case "register":
		cmdRegister(os.Args[2:])
	case "cred", "creds":
		cmdCred(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "gc-lookup: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gc-lookup — GetContact lookup CLI (port of gtc.py)

Usage:
  gc-lookup search [--source profile|tags] [--account NAME] [--rotate] <phone>
  gc-lookup subscription [--account NAME] [--rotate]
  gc-lookup refresh-code [--account NAME]
  gc-lookup verify-code <code> [--account NAME]
  gc-lookup register [--name desc] <phone>
  gc-lookup cred list|use <name>|remove <name>|path
  gc-lookup help

Credentials are stored in %s (override with $GTC_CONFIG_DIR).
`, credFilePath())
}

// --- credential store ------------------------------------------------------

func configDir() string {
	if d := os.Getenv("GTC_CONFIG_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "gtc")
}

func credFilePath() string { return filepath.Join(configDir(), "credentials.json") }

func loadStore() (*client.Store, error) {
	data, err := os.ReadFile(credFilePath())
	if os.IsNotExist(err) {
		return &client.Store{Credentials: map[string]client.Credential{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s client.Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", credFilePath(), err)
	}
	if s.Credentials == nil {
		s.Credentials = map[string]client.Credential{}
	}
	return &s, nil
}

func saveStore(s *client.Store) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(credFilePath(), data, 0o600)
}

func activeCred(s *client.Store) (client.Credential, error) {
	if s.Active == "" {
		return client.Credential{}, fmt.Errorf("no active credential: run 'gc-lookup register' or 'gc-lookup cred use <name>'")
	}
	cred, ok := s.Credentials[s.Active]
	if !ok {
		return client.Credential{}, fmt.Errorf("active credential %q not found in store", s.Active)
	}
	return cred, nil
}

// credForAccount resolves the credential to use: an explicit --account name,
// else the active credential.
func credForAccount(s *client.Store, account string) (client.Credential, error) {
	if account == "" {
		return activeCred(s)
	}
	cred, ok := s.Credentials[account]
	if !ok {
		return client.Credential{}, fmt.Errorf("no credential named %q (stored: %v)", account, sortedNames(s))
	}
	return cred, nil
}

func sortedNames(s *client.Store) []string {
	names := make([]string, 0, len(s.Credentials))
	for n := range s.Credentials {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func without(names []string, exclude string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != exclude {
			out = append(out, n)
		}
	}
	return out
}

// rotationOrder returns the credentials to try in order: active first, then the
// rest alphabetically. Each entry carries the account name for reporting.
func rotationOrder(s *client.Store) []string {
	names := sortedNames(s)
	if s.Active != "" {
		names = append([]string{s.Active}, without(names, s.Active)...)
	}
	return names
}

func printSearchResult(res *client.SearchResult, source string) {
	if source == "tags" {
		printJSON(res.Tags)
	} else {
		printJSON(res.Profile)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gc-lookup: %v\n", err)
	os.Exit(1)
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(fmt.Errorf("marshal result: %w", err))
	}
	fmt.Println(string(b))
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// --- commands --------------------------------------------------------------

func cmdSearch(args []string) {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	source := fs.String("source", "profile", "result to show: profile|tags")
	account := fs.String("account", "", "credential name (default: active)")
	rotate := fs.Bool("rotate", false, "try each credential in rotation until one succeeds")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gc-lookup search [--source profile|tags] [--account NAME] [--rotate] <phone>")
		os.Exit(2)
	}
	if *source != "profile" && *source != "tags" {
		fmt.Fprintf(os.Stderr, "gc-lookup: invalid --source %q (want profile|tags)\n", *source)
		os.Exit(2)
	}
	s, err := loadStore()
	if err != nil {
		fatal(err)
	}
	phone := fs.Arg(0)

	if *rotate {
		searchRotate(s, phone, *source)
		return
	}

	cred, err := credForAccount(s, *account)
	if err != nil {
		fatal(err)
	}
	res, err := newClient(cred).Search(phone, *source)
	if err != nil {
		fatal(err)
	}
	printSearchResult(res, *source)
}

// searchRotate tries every stored credential until one succeeds, reporting the
// account that produced the result. This spreads quota across accounts.
func searchRotate(s *client.Store, phone, source string) {
	names := rotationOrder(s)
	if len(names) == 0 {
		fatal(fmt.Errorf("no credentials stored: run 'gc-lookup register' or 'gc-lookup cred use <name>'"))
	}
	var lastErr error
	for _, name := range names {
		cred := s.Credentials[name]
		res, err := newClient(cred).Search(phone, source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gc-lookup: account %q failed: %v\n", name, err)
			lastErr = err
			continue
		}
		fmt.Fprintf(os.Stderr, "gc-lookup: result from account %q\n", name)
		printSearchResult(res, source)
		return
	}
	fatal(lastErr)
}

func cmdSubscription(args []string) {
	fs := flag.NewFlagSet("subscription", flag.ContinueOnError)
	account := fs.String("account", "", "credential name (default: active)")
	rotate := fs.Bool("rotate", false, "show quota for every stored credential")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	s, err := loadStore()
	if err != nil {
		fatal(err)
	}

	if *rotate {
		names := rotationOrder(s)
		if len(names) == 0 {
			fatal(fmt.Errorf("no credentials stored"))
		}
		for _, name := range names {
			info, err := newClient(s.Credentials[name]).Subscription()
			if err != nil {
				fmt.Fprintf(os.Stderr, "gc-lookup: %s: %v\n", name, err)
				continue
			}
			printQuota(name, info)
		}
		return
	}

	cred, err := credForAccount(s, *account)
	if err != nil {
		fatal(err)
	}
	name := *account
	if name == "" {
		name = s.Active
	}
	info, err := newClient(cred).Subscription()
	if err != nil {
		fatal(err)
	}
	printQuota(name, info)
}

func printQuota(name string, info *client.SubscriptionInfo) {
	fmt.Printf("%s: search %d/%d, numberDetail %d/%d", name,
		info.Search.RemainingCount, info.Search.Limit, info.NumberDetail.RemainingCount, info.NumberDetail.Limit)
	if info.RenewDate != "" {
		fmt.Printf(", renew %s", info.RenewDate)
	}
	fmt.Println()
}

func cmdRefreshCode(args []string) {
	fs := flag.NewFlagSet("refresh-code", flag.ContinueOnError)
	account := fs.String("account", "", "credential name (default: active)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	s, err := loadStore()
	if err != nil {
		fatal(err)
	}
	cred, err := credForAccount(s, *account)
	if err != nil {
		fatal(err)
	}
	parsed, err := newClient(cred).RefreshCode()
	if err != nil {
		fatal(err)
	}
	printJSON(parsed)
}

func cmdVerifyCode(args []string) {
	fs := flag.NewFlagSet("verify-code", flag.ContinueOnError)
	account := fs.String("account", "", "credential name (default: active)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gc-lookup verify-code <code>")
		os.Exit(2)
	}
	s, err := loadStore()
	if err != nil {
		fatal(err)
	}
	cred, err := credForAccount(s, *account)
	if err != nil {
		fatal(err)
	}
	if err := newClient(cred).VerifyCode(fs.Arg(0)); err != nil {
		fatal(err)
	}
	fmt.Println("code accepted")
}

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	name := fs.String("name", "", "credential description (default: phone number)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gc-lookup register [--name desc] <phone>")
		os.Exit(2)
	}
	phone := fs.Arg(0)
	desc := *name
	if desc == "" {
		desc = phone
	}
	cred, err := newClient(client.Credential{}).Register(phone, desc)
	if err != nil {
		fatal(err)
	}
	s, err := loadStore()
	if err != nil {
		fatal(err)
	}
	if _, exists := s.Credentials[desc]; exists {
		fmt.Fprintf(os.Stderr, "gc-lookup: warning: overwriting existing credential %q\n", desc)
	}
	s.Credentials[desc] = cred
	s.Active = desc
	if err := saveStore(s); err != nil {
		fatal(err)
	}
	fmt.Printf("registered %s as %q (stored, now active)\n", phone, desc)
}

func cmdCred(args []string) {
	if len(args) == 0 {
		credUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		s, err := loadStore()
		if err != nil {
			fatal(err)
		}
		if len(s.Credentials) == 0 {
			fmt.Println("no credentials stored")
			return
		}
		names := make([]string, 0, len(s.Credentials))
		for n := range s.Credentials {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			mark := " "
			if n == s.Active {
				mark = "*"
			}
			c := s.Credentials[n]
			fmt.Printf("%s %-24s phone=%s token=%s… finalKey=%s…\n",
				mark, n, c.PhoneNumber, short(c.Token), short(c.FinalKey))
		}
	case "use":
		if len(args) != 2 {
			credUsage()
			os.Exit(2)
		}
		s, err := loadStore()
		if err != nil {
			fatal(err)
		}
		if _, ok := s.Credentials[args[1]]; !ok {
			fatal(fmt.Errorf("no credential named %q", args[1]))
		}
		s.Active = args[1]
		if err := saveStore(s); err != nil {
			fatal(err)
		}
		fmt.Printf("active credential: %s\n", args[1])
	case "remove":
		if len(args) != 2 {
			credUsage()
			os.Exit(2)
		}
		s, err := loadStore()
		if err != nil {
			fatal(err)
		}
		if _, ok := s.Credentials[args[1]]; !ok {
			fatal(fmt.Errorf("no credential named %q", args[1]))
		}
		delete(s.Credentials, args[1])
		if s.Active == args[1] {
			s.Active = ""
		}
		if err := saveStore(s); err != nil {
			fatal(err)
		}
		fmt.Printf("removed credential %q\n", args[1])
	case "path":
		fmt.Println(credFilePath())
	default:
		credUsage()
		os.Exit(2)
	}
}

func credUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  gc-lookup cred list
  gc-lookup cred use <name>
  gc-lookup cred remove <name>
  gc-lookup cred path`)
}
