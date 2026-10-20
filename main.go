package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Package struct {
	Name        string   `json:"name"`
	Epoch       string   `json:"epoch"`
	Version     string   `json:"version"`
	Release     string   `json:"release"`
	Arch        string   `json:"arch"`
	InstallTime int64    `json:"install_time"`
	Size        int64    `json:"size_bytes"`
	Vendor      string   `json:"vendor"`
	Packager    string   `json:"packager"`
	License     string   `json:"license"`
	URL         string   `json:"url"`
	Summary     string   `json:"summary"`
	Signature   string   `json:"signature"`
	SourceRPM   string   `json:"source_rpm"`
	BuildTime   int64    `json:"build_time"`
	Group       string   `json:"group"`
	Categories  []string `json:"categories,omitempty"`
}

type Repository struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	File           string `json:"file"`
	BaseURL        string `json:"baseurl,omitempty"`
	Metalink       string `json:"metalink,omitempty"`
	Mirrorlist     string `json:"mirrorlist,omitempty"`
	GPGCheck       string `json:"gpgcheck,omitempty"`
	RepoGPGCheck   string `json:"repo_gpgcheck,omitempty"`
	GPGKey         string `json:"gpgkey,omitempty"`
	ModuleHotfixes string `json:"module_hotfixes,omitempty"`
	Priority       string `json:"priority,omitempty"`
	Exclude        string `json:"exclude,omitempty"`
}

type Transaction struct {
	Time    string `json:"time"`
	Action  string `json:"action"`
	Package string `json:"package"`
	Source  string `json:"source"`
}

type Finding struct {
	Code    string `json:"code"`
	Level   string `json:"level"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

type CommandResult struct {
	Name       string `json:"name"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
}

type SystemInfo struct {
	Hostname     string            `json:"hostname"`
	OSRelease    map[string]string `json:"os_release"`
	Kernel       string            `json:"kernel"`
	RPMVersion   string            `json:"rpm_version"`
	DNFVersion   string            `json:"dnf_version"`
	Architecture string            `json:"architecture"`
}

type Report struct {
	Schema       int             `json:"schema"`
	GeneratedAt  string          `json:"generated_at"`
	System       SystemInfo      `json:"system"`
	Packages     []Package       `json:"packages"`
	Repositories []Repository    `json:"repositories"`
	Transactions []Transaction   `json:"transactions"`
	Findings     []Finding       `json:"findings"`
	Commands     []CommandResult `json:"commands"`
	Summary      Summary         `json:"summary"`
}

type Summary struct {
	Packages            int            `json:"packages"`
	Repositories        int            `json:"repositories"`
	EnabledRepos        int            `json:"enabled_repositories"`
	Transactions        int            `json:"transactions"`
	Findings            int            `json:"findings"`
	WarningCount        int            `json:"warnings"`
	InfoCount           int            `json:"information"`
	TotalInstalledBytes int64          `json:"total_installed_bytes"`
	ByArch              map[string]int `json:"by_arch"`
	ByVendor            map[string]int `json:"by_vendor"`
	ByCategory          map[string]int `json:"by_category"`
}

type Options struct {
	Format              string
	Output              string
	PackageFilter       string
	VendorFilter        string
	CategoryFilter      string
	LevelFilter         string
	RepoDir             string
	DNFLog              string
	Timeout             time.Duration
	MaxTransactions     int
	MaxFindings         int
	Verify              bool
	CheckUpdates        bool
	DNFHistory          bool
	IncludePackages     bool
	IncludeRepos        bool
	IncludeTransactions bool
	Quiet               bool
	Strict              bool
	Compare             string
	SaveBaseline        string
}

type Auditor struct {
	Opt    Options
	Report Report
	mu     sync.Mutex
}

func main() {
	opts := parseOptions()
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	a := &Auditor{Opt: opts, Report: Report{Schema: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}}
	if err := a.Collect(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "rpm-auditor:", err)
		os.Exit(2)
	}
	if opts.SaveBaseline != "" {
		if err := saveBaseline(opts.SaveBaseline, a.Report.Packages); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if opts.Compare != "" {
		if err := a.compareBaseline(opts.Compare); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	a.Sort()
	a.Report.Summary = makeSummary(a.Report)
	if err := a.Write(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.Strict && a.Report.Summary.WarningCount > 0 {
		os.Exit(1)
	}
}

func parseOptions() Options {
	var o Options
	flag.StringVar(&o.Format, "format", "text", "text, json, csv, ndjson")
	flag.StringVar(&o.Output, "output", "", "write to file instead of stdout")
	flag.StringVar(&o.PackageFilter, "package", "", "package name substring")
	flag.StringVar(&o.VendorFilter, "vendor", "", "vendor substring")
	flag.StringVar(&o.CategoryFilter, "category", "", "category substring")
	flag.StringVar(&o.LevelFilter, "level", "", "finding severity filter")
	flag.StringVar(&o.RepoDir, "repo-dir", "/etc/yum.repos.d", "repository configuration directory")
	flag.StringVar(&o.DNFLog, "dnf-log", "/var/log/dnf.log", "DNF log file")
	flag.DurationVar(&o.Timeout, "timeout", 45*time.Second, "overall collection timeout")
	flag.IntVar(&o.MaxTransactions, "max-transactions", 100, "maximum parsed DNF log entries")
	flag.IntVar(&o.MaxFindings, "max-findings", 1000, "maximum retained findings")
	flag.BoolVar(&o.Verify, "verify", false, "run rpm -Va (may take time)")
	flag.BoolVar(&o.CheckUpdates, "check-updates", false, "run dnf check-update without installing")
	flag.BoolVar(&o.DNFHistory, "dnf-history", false, "run dnf history list")
	flag.BoolVar(&o.IncludePackages, "packages", true, "include package inventory")
	flag.BoolVar(&o.IncludeRepos, "repos", true, "include repository inventory")
	flag.BoolVar(&o.IncludeTransactions, "transactions", true, "include recent DNF log entries")
	flag.BoolVar(&o.Quiet, "quiet", false, "suppress collection diagnostics on stderr")
	flag.BoolVar(&o.Strict, "strict", false, "exit 1 when warning findings exist")
	flag.StringVar(&o.Compare, "compare", "", "compare package inventory against saved baseline")
	flag.StringVar(&o.SaveBaseline, "save-baseline", "", "save package inventory as JSON")
	flag.Parse()
	if o.Timeout <= 0 || o.MaxTransactions < 0 || o.MaxFindings < 0 {
		fmt.Fprintln(os.Stderr, "invalid numeric option")
		os.Exit(2)
	}
	switch o.Format {
	case "text", "json", "csv", "ndjson":
	default:
		fmt.Fprintln(os.Stderr, "unsupported format")
		os.Exit(2)
	}
	return o
}

func (a *Auditor) Collect(ctx context.Context) error {
	if _, err := exec.LookPath("rpm"); err != nil {
		return errors.New("rpm executable not found")
	}
	a.collectSystem(ctx)
	if a.Opt.IncludePackages {
		if err := a.collectPackages(ctx); err != nil {
			return err
		}
	}
	if a.Opt.IncludeRepos {
		a.collectRepos()
	}
	if a.Opt.IncludeTransactions {
		a.collectTransactions()
	}
	if a.Opt.Verify {
		a.collectVerification(ctx)
	}
	if a.Opt.CheckUpdates {
		a.collectUpdates(ctx)
	}
	if a.Opt.DNFHistory {
		a.collectHistory(ctx)
	}
	a.audit()
	return nil
}

func (a *Auditor) command(ctx context.Context, name string, args ...string) (string, error) {
	started := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	result := CommandResult{Name: name + " " + strings.Join(args, " "), DurationMS: time.Since(started).Milliseconds(), Output: truncate(string(out), 2000)}
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			result.ExitCode = ee.ExitCode()
		}
	}
	a.Report.Commands = append(a.Report.Commands, result)
	return string(out), err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func contains(s, needle string) bool {
	return needle == "" || strings.Contains(lower(s), lower(needle))
}
func atoi(s string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }
func (a *Auditor) finding(code, level, subject, message string) {
	if len(a.Report.Findings) >= a.Opt.MaxFindings {
		return
	}
	if a.Opt.LevelFilter != "" && !strings.EqualFold(level, a.Opt.LevelFilter) {
		return
	}
	a.Report.Findings = append(a.Report.Findings, Finding{code, level, subject, message})
}

func (a *Auditor) collectSystem(ctx context.Context) {
	host, _ := os.Hostname()
	a.Report.System.Hostname = host
	a.Report.System.OSRelease = readKeyValues("/etc/os-release")
	if s, err := a.command(ctx, "uname", "-r"); err == nil {
		a.Report.System.Kernel = strings.TrimSpace(s)
	}
	if s, err := a.command(ctx, "uname", "-m"); err == nil {
		a.Report.System.Architecture = strings.TrimSpace(s)
	}
	if s, err := a.command(ctx, "rpm", "--version"); err == nil {
		a.Report.System.RPMVersion = strings.TrimSpace(s)
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		if s, err := a.command(ctx, "dnf", "--version"); err == nil {
			a.Report.System.DNFVersion = firstLine(s)
		}
	}
}
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}
func readKeyValues(path string) map[string]string {
	result := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return result
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		p := strings.SplitN(line, "=", 2)
		result[p[0]] = strings.Trim(p[1], "\"'")
	}
	return result
}

func (a *Auditor) collectPackages(ctx context.Context) error {
	const sep = "\\t"
	format := "%{NAME}" + sep + "%{EPOCH}" + sep + "%{VERSION}" + sep + "%{RELEASE}" + sep + "%{ARCH}" + sep + "%{INSTALLTIME}" + sep + "%{SIZE}" + sep + "%{VENDOR}" + sep + "%{PACKAGER}" + sep + "%{LICENSE}" + sep + "%{URL}" + sep + "%{SUMMARY}" + sep + "%{SIGPGP:pgpsig}" + sep + "%{SOURCERPM}" + sep + "%{BUILDTIME}" + sep + "%{GROUP}\\n"
	out, err := a.command(ctx, "rpm", "-qa", "--qf", format)
	if err != nil {
		return fmt.Errorf("rpm query failed: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 16 {
			a.finding("PARSE_PACKAGE", "warning", "rpm", "unexpected query output field count")
			continue
		}
		p := Package{Name: fields[0], Epoch: fields[1], Version: fields[2], Release: fields[3], Arch: fields[4], InstallTime: atoi(fields[5]), Size: atoi(fields[6]), Vendor: fields[7], Packager: fields[8], License: fields[9], URL: fields[10], Summary: fields[11], Signature: fields[12], SourceRPM: fields[13], BuildTime: atoi(fields[14]), Group: fields[15]}
		if !contains(p.Name, a.Opt.PackageFilter) || !contains(p.Vendor, a.Opt.VendorFilter) {
			continue
		}
		p.Categories = classify(p)
		if a.Opt.CategoryFilter != "" && !categoryMatches(p.Categories, a.Opt.CategoryFilter) {
			continue
		}
		a.Report.Packages = append(a.Report.Packages, p)
	}
	return nil
}
func categoryMatches(cats []string, filter string) bool {
	for _, c := range cats {
		if contains(c, filter) {
			return true
		}
	}
	return false
}

func (a *Auditor) collectRepos() {
	entries, err := os.ReadDir(a.Opt.RepoDir)
	if err != nil {
		a.finding("REPO_DIR", "info", a.Opt.RepoDir, err.Error())
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".repo") {
			continue
		}
		path := filepath.Join(a.Opt.RepoDir, entry.Name())
		repos, err := parseRepoFile(path)
		if err != nil {
			a.finding("REPO_READ", "info", path, err.Error())
			continue
		}
		a.Report.Repositories = append(a.Report.Repositories, repos...)
	}
}
func parseRepoFile(path string) ([]Repository, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	result := []Repository{}
	var current *Repository
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if current != nil {
				result = append(result, *current)
			}
			current = &Repository{ID: strings.TrimSpace(line[1 : len(line)-1]), File: path, Enabled: true}
			continue
		}
		if current == nil || !strings.Contains(line, "=") {
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		key := lower(pair[0])
		value := strings.TrimSpace(pair[1])
		switch key {
		case "name":
			current.Name = value
		case "enabled":
			current.Enabled = value != "0" && lower(value) != "false"
		case "baseurl":
			current.BaseURL = value
		case "metalink":
			current.Metalink = value
		case "mirrorlist":
			current.Mirrorlist = value
		case "gpgcheck":
			current.GPGCheck = value
		case "repo_gpgcheck":
			current.RepoGPGCheck = value
		case "gpgkey":
			current.GPGKey = value
		case "module_hotfixes":
			current.ModuleHotfixes = value
		case "priority":
			current.Priority = value
		case "exclude":
			current.Exclude = value
		}
	}
	if current != nil {
		result = append(result, *current)
	}
	return result, sc.Err()
}

var transactionPattern = regexp.MustCompile(`(?i)(installed|upgraded|downgraded|erased|removed|reinstalled|install|upgrade|erase):?\s+([^\s,]+)`)

func (a *Auditor) collectTransactions() {
	f, err := os.Open(a.Opt.DNFLog)
	if err != nil {
		a.finding("DNF_LOG", "info", a.Opt.DNFLog, "log unavailable: "+err.Error())
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		match := transactionPattern.FindStringSubmatch(line)
		if len(match) < 3 {
			continue
		}
		stamp := ""
		if len(line) >= 19 {
			stamp = line[:19]
		}
		a.Report.Transactions = append(a.Report.Transactions, Transaction{Time: stamp, Action: lower(match[1]), Package: match[2], Source: a.Opt.DNFLog})
		if len(a.Report.Transactions) > a.Opt.MaxTransactions {
			a.Report.Transactions = a.Report.Transactions[1:]
		}
	}
	if err := sc.Err(); err != nil {
		a.finding("DNF_LOG_READ", "info", a.Opt.DNFLog, err.Error())
	}
}
func (a *Auditor) collectVerification(ctx context.Context) {
	out, err := a.command(ctx, "rpm", "-Va")
	if err != nil && ctx.Err() != nil {
		a.finding("VERIFY_TIMEOUT", "warning", "rpm -Va", ctx.Err().Error())
		return
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		count++
		if strings.Contains(line, "missing") {
			a.finding("VERIFY_MISSING", "warning", "rpm -Va", truncate(line, 350))
		} else {
			a.finding("VERIFY_CHANGED", "info", "rpm -Va", truncate(line, 350))
		}
	}
	if count > 0 {
		a.finding("VERIFY_COUNT", "info", "rpm -Va", fmt.Sprintf("%d verification output lines; configuration changes may be legitimate", count))
	}
}
func (a *Auditor) collectUpdates(ctx context.Context) {
	if _, err := exec.LookPath("dnf"); err != nil {
		return
	}
	out, err := a.command(ctx, "dnf", "-q", "check-update", "--refresh")
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 100 {
			a.finding("UPDATE_CHECK", "info", "dnf", err.Error())
			return
		}
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last metadata") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.Contains(fields[0], ".") {
			count++
		}
	}
	a.finding("AVAILABLE_UPDATES", "info", "dnf", fmt.Sprintf("approximately %d update entries reported", count))
}
func (a *Auditor) collectHistory(ctx context.Context) {
	if _, err := exec.LookPath("dnf"); err != nil {
		return
	}
	out, err := a.command(ctx, "dnf", "history", "list")
	if err != nil {
		a.finding("HISTORY", "info", "dnf", err.Error())
		return
	}
	a.finding("HISTORY", "info", "dnf", truncate(strings.TrimSpace(out), 500))
}

func (a *Auditor) audit() {
	for _, p := range a.Report.Packages {
		if p.Name == "" {
			a.finding("EMPTY_NAME", "warning", "package", "empty RPM name")
		}
		if p.Version == "" {
			a.finding("EMPTY_VERSION", "warning", p.Name, "missing version")
		}
		if p.Arch == "" {
			a.finding("EMPTY_ARCH", "warning", p.Name, "missing architecture")
		}
		if p.Vendor == "" || strings.EqualFold(p.Vendor, "(none)") {
			a.finding("NO_VENDOR", "info", p.Name, "vendor field unavailable")
		}
		if p.License == "" || strings.EqualFold(p.License, "(none)") {
			a.finding("NO_LICENSE", "info", p.Name, "license metadata unavailable")
		}
		if p.Signature == "" || strings.Contains(lower(p.Signature), "(none)") {
			a.finding("NO_SIGNATURE_METADATA", "info", p.Name, "PGP signature metadata not present in query; verify independently before drawing security conclusions")
		}
		if p.Size < 0 {
			a.finding("NEGATIVE_SIZE", "warning", p.Name, "negative installed size")
		}
		if p.InstallTime > time.Now().Add(24*time.Hour).Unix() {
			a.finding("FUTURE_INSTALL", "warning", p.Name, "install timestamp is in the future")
		}
		if p.BuildTime > time.Now().Add(24*time.Hour).Unix() {
			a.finding("FUTURE_BUILD", "warning", p.Name, "build timestamp is in the future")
		}
		if p.SourceRPM == "" && p.Arch != "noarch" {
			a.finding("SOURCE_RPM", "info", p.Name, "source RPM metadata absent")
		}
	}
	for _, r := range a.Report.Repositories {
		if !r.Enabled {
			continue
		}
		if r.BaseURL == "" && r.Metalink == "" && r.Mirrorlist == "" {
			a.finding("REPO_NO_URL", "warning", r.ID, "enabled repository has no source URL")
		}
		if r.GPGCheck == "0" {
			a.finding("REPO_GPG_DISABLED", "warning", r.ID, "package signature checking explicitly disabled")
		}
		if r.RepoGPGCheck == "0" {
			a.finding("REPO_METADATA_GPG", "info", r.ID, "repository metadata signature checking explicitly disabled")
		}
		if strings.HasPrefix(r.BaseURL, "http://") {
			a.finding("REPO_HTTP", "info", r.ID, "repository uses plain HTTP; assess transport and signature policy")
		}
		if r.GPGKey == "" {
			a.finding("REPO_KEY_UNSPECIFIED", "info", r.ID, "no gpgkey setting in this repository section; inherited settings may apply")
		}
		if r.Exclude != "" {
			a.finding("REPO_EXCLUDES", "info", r.ID, "repository excludes: "+truncate(r.Exclude, 160))
		}
	}
}

func makeSummary(r Report) Summary {
	s := Summary{Packages: len(r.Packages), Repositories: len(r.Repositories), Transactions: len(r.Transactions), Findings: len(r.Findings), ByArch: map[string]int{}, ByVendor: map[string]int{}, ByCategory: map[string]int{}}
	for _, p := range r.Packages {
		s.TotalInstalledBytes += p.Size
		s.ByArch[p.Arch]++
		s.ByVendor[p.Vendor]++
		for _, c := range p.Categories {
			s.ByCategory[c]++
		}
	}
	for _, repo := range r.Repositories {
		if repo.Enabled {
			s.EnabledRepos++
		}
	}
	for _, f := range r.Findings {
		if f.Level == "warning" {
			s.WarningCount++
		} else {
			s.InfoCount++
		}
	}
	return s
}
func (a *Auditor) Sort() {
	sort.Slice(a.Report.Packages, func(i, j int) bool { return a.Report.Packages[i].Name < a.Report.Packages[j].Name })
	sort.Slice(a.Report.Repositories, func(i, j int) bool { return a.Report.Repositories[i].ID < a.Report.Repositories[j].ID })
	sort.Slice(a.Report.Findings, func(i, j int) bool {
		p, q := a.Report.Findings[i], a.Report.Findings[j]
		if p.Level != q.Level {
			return p.Level < q.Level
		}
		if p.Code != q.Code {
			return p.Code < q.Code
		}
		return p.Subject < q.Subject
	})
}
func saveBaseline(path string, pkgs []Package) error {
	b, err := json.MarshalIndent(pkgs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func (a *Auditor) compareBaseline(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var old []Package
	if err := json.Unmarshal(data, &old); err != nil {
		return err
	}
	previous := map[string]Package{}
	current := map[string]Package{}
	for _, p := range old {
		previous[p.Name+"."+p.Arch] = p
	}
	for _, p := range a.Report.Packages {
		current[p.Name+"."+p.Arch] = p
	}
	for k, p := range current {
		before, ok := previous[k]
		if !ok {
			a.finding("BASELINE_ADDED", "info", k, "new installed package")
			continue
		}
		if before.Epoch != p.Epoch || before.Version != p.Version || before.Release != p.Release {
			a.finding("BASELINE_CHANGED", "info", k, fmt.Sprintf("%s-%s -> %s-%s", before.Version, before.Release, p.Version, p.Release))
		}
	}
	for k := range previous {
		if _, ok := current[k]; !ok {
			a.finding("BASELINE_REMOVED", "info", k, "package no longer installed")
		}
	}
	return nil
}

func (a *Auditor) Write() error {
	var w io.Writer = os.Stdout
	if a.Opt.Output != "" {
		f, err := os.Create(a.Opt.Output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	switch a.Opt.Format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(a.Report)
	case "csv":
		return a.writeCSV(w)
	case "ndjson":
		return a.writeNDJSON(w)
	default:
		return a.writeText(w)
	}
}
func (a *Auditor) writeCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"name", "epoch", "version", "release", "arch", "vendor", "license", "size_bytes", "install_time", "categories"}); err != nil {
		return err
	}
	for _, p := range a.Report.Packages {
		if err := cw.Write([]string{p.Name, p.Epoch, p.Version, p.Release, p.Arch, p.Vendor, p.License, strconv.FormatInt(p.Size, 10), strconv.FormatInt(p.InstallTime, 10), strings.Join(p.Categories, ";")}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
func (a *Auditor) writeNDJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	for _, p := range a.Report.Packages {
		if err := enc.Encode(map[string]any{"kind": "package", "data": p}); err != nil {
			return err
		}
	}
	for _, r := range a.Report.Repositories {
		if err := enc.Encode(map[string]any{"kind": "repository", "data": r}); err != nil {
			return err
		}
	}
	for _, t := range a.Report.Transactions {
		if err := enc.Encode(map[string]any{"kind": "transaction", "data": t}); err != nil {
			return err
		}
	}
	for _, f := range a.Report.Findings {
		if err := enc.Encode(map[string]any{"kind": "finding", "data": f}); err != nil {
			return err
		}
	}
	return enc.Encode(map[string]any{"kind": "summary", "data": a.Report.Summary})
}
func (a *Auditor) writeText(w io.Writer) error {
	s := a.Report.Summary
	_, err := fmt.Fprintf(w, "RPM AUDITOR | %s | %s\nPackages: %d  Repositories: %d (%d enabled)  Transactions: %d\nFindings: %d (%d warnings)  Installed bytes: %d\n\n", a.Report.System.Hostname, a.Report.GeneratedAt, s.Packages, s.Repositories, s.EnabledRepos, s.Transactions, s.Findings, s.WarningCount, s.TotalInstalledBytes)
	if err != nil {
		return err
	}
	if len(a.Report.Packages) > 0 {
		fmt.Fprintln(w, "PACKAGES")
		for _, p := range a.Report.Packages {
			fmt.Fprintf(w, "%-42s %-20s %-12s %s\n", truncate(p.Name, 42), truncate(p.Version+"-"+p.Release, 20), p.Arch, strings.Join(p.Categories, ","))
		}
		fmt.Fprintln(w)
	}
	if len(a.Report.Repositories) > 0 {
		fmt.Fprintln(w, "REPOSITORIES")
		for _, r := range a.Report.Repositories {
			fmt.Fprintf(w, "%-30s enabled=%-5t %s\n", r.ID, r.Enabled, r.Name)
		}
		fmt.Fprintln(w)
	}
	if len(a.Report.Transactions) > 0 {
		fmt.Fprintln(w, "RECENT LOG ENTRIES")
		for _, t := range a.Report.Transactions {
			fmt.Fprintf(w, "%s %-12s %s\n", t.Time, t.Action, t.Package)
		}
		fmt.Fprintln(w)
	}
	if len(a.Report.Findings) > 0 {
		fmt.Fprintln(w, "FINDINGS")
		for _, f := range a.Report.Findings {
			fmt.Fprintf(w, "[%s] %s %s: %s\n", f.Level, f.Code, f.Subject, f.Message)
		}
	}
	return nil
}

func inventoryFingerprint(packages []Package) string {
	h := sha256.New()
	sorted := append([]Package(nil), packages...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name+sorted[i].Arch < sorted[j].Name+sorted[j].Arch })
	for _, p := range sorted {
		io.WriteString(h, p.Name+"\x00"+p.Epoch+"\x00"+p.Version+"\x00"+p.Release+"\x00"+p.Arch+"\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}
func safeTrim(s string) string { return strings.TrimSpace(strings.Trim(s, "\x00")) }
func nonempty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
func splitFields(line string) []string { return strings.Fields(strings.TrimSpace(line)) }
func normalizeArch(s string) string    { return lower(strings.ReplaceAll(s, "-", "_")) }
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
func formatTime(epoch int64) string {
	if epoch <= 0 {
		return "unknown"
	}
	return time.Unix(epoch, 0).UTC().Format(time.RFC3339)
}
func parseDuration(s string) time.Duration { d, _ := time.ParseDuration(s); return d }
func hasAny(s string, values ...string) bool {
	for _, v := range values {
		if strings.Contains(lower(s), lower(v)) {
			return true
		}
	}
	return false
}
func sortedPackages(ps []Package) []Package {
	out := append([]Package(nil), ps...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func countArch(ps []Package, arch string) int {
	n := 0
	for _, p := range ps {
		if p.Arch == arch {
			n++
		}
	}
	return n
}
func sumSize(ps []Package) int64 {
	var n int64
	for _, p := range ps {
		n += p.Size
	}
	return n
}
func filterPackages(ps []Package, predicate func(Package) bool) []Package {
	out := []Package{}
	for _, p := range ps {
		if predicate(p) {
			out = append(out, p)
		}
	}
	return out
}
func uniqueStrings(values []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func repoIDs(rs []Repository) []string {
	ids := []string{}
	for _, r := range rs {
		ids = append(ids, r.ID)
	}
	return uniqueStrings(ids)
}
func packageNames(ps []Package) []string {
	names := []string{}
	for _, p := range ps {
		names = append(names, p.Name)
	}
	return uniqueStrings(names)
}
func severityRank(level string) int {
	switch level {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	}
	return 0
}
func copyReader(r io.Reader) ([]byte, error) {
	var b bytes.Buffer
	_, err := io.Copy(&b, r)
	return b.Bytes(), err
}

func classify(p Package) []string {
	result := make([]string, 0, 4)
	if categoryRule000(p) {
		result = append(result, "kernel")
	}
	if categoryRule001(p) {
		result = append(result, "bootloader")
	}
	if categoryRule002(p) {
		result = append(result, "init-system")
	}
	if categoryRule003(p) {
		result = append(result, "package-management")
	}
	if categoryRule004(p) {
		result = append(result, "selinux")
	}
	if categoryRule005(p) {
		result = append(result, "firewall")
	}
	if categoryRule006(p) {
		result = append(result, "ssh")
	}
	if categoryRule007(p) {
		result = append(result, "crypto")
	}
	if categoryRule008(p) {
		result = append(result, "certificates")
	}
	if categoryRule009(p) {
		result = append(result, "container-runtime")
	}
	if categoryRule010(p) {
		result = append(result, "container-network")
	}
	if categoryRule011(p) {
		result = append(result, "virtualization")
	}
	if categoryRule012(p) {
		result = append(result, "network-tools")
	}
	if categoryRule013(p) {
		result = append(result, "dns")
	}
	if categoryRule014(p) {
		result = append(result, "web-server")
	}
	if categoryRule015(p) {
		result = append(result, "reverse-proxy")
	}
	if categoryRule016(p) {
		result = append(result, "php")
	}
	if categoryRule017(p) {
		result = append(result, "python")
	}
	if categoryRule018(p) {
		result = append(result, "go")
	}
	if categoryRule019(p) {
		result = append(result, "rust")
	}
	if categoryRule020(p) {
		result = append(result, "compiler")
	}
	if categoryRule021(p) {
		result = append(result, "debugger")
	}
	if categoryRule022(p) {
		result = append(result, "java")
	}
	if categoryRule023(p) {
		result = append(result, "javascript")
	}
	if categoryRule024(p) {
		result = append(result, "perl")
	}
	if categoryRule025(p) {
		result = append(result, "ruby")
	}
	if categoryRule026(p) {
		result = append(result, "postgresql")
	}
	if categoryRule027(p) {
		result = append(result, "mariadb")
	}
	if categoryRule028(p) {
		result = append(result, "sqlite")
	}
	if categoryRule029(p) {
		result = append(result, "redis")
	}
	if categoryRule030(p) {
		result = append(result, "mongodb")
	}
	if categoryRule031(p) {
		result = append(result, "monitoring")
	}
	if categoryRule032(p) {
		result = append(result, "logging")
	}
	if categoryRule033(p) {
		result = append(result, "scheduler")
	}
	if categoryRule034(p) {
		result = append(result, "backup")
	}
	if categoryRule035(p) {
		result = append(result, "filesystem")
	}
	if categoryRule036(p) {
		result = append(result, "storage")
	}
	if categoryRule037(p) {
		result = append(result, "nfs")
	}
	if categoryRule038(p) {
		result = append(result, "samba")
	}
	if categoryRule039(p) {
		result = append(result, "iscsi")
	}
	if categoryRule040(p) {
		result = append(result, "printing")
	}
	if categoryRule041(p) {
		result = append(result, "mail")
	}
	if categoryRule042(p) {
		result = append(result, "time-sync")
	}
	if categoryRule043(p) {
		result = append(result, "authentication")
	}
	if categoryRule044(p) {
		result = append(result, "audit")
	}
	if categoryRule045(p) {
		result = append(result, "integrity")
	}
	if categoryRule046(p) {
		result = append(result, "hardware")
	}
	if categoryRule047(p) {
		result = append(result, "firmware")
	}
	if categoryRule048(p) {
		result = append(result, "compression")
	}
	if categoryRule049(p) {
		result = append(result, "archive")
	}
	if categoryRule050(p) {
		result = append(result, "shell")
	}
	if categoryRule051(p) {
		result = append(result, "terminal")
	}
	if categoryRule052(p) {
		result = append(result, "editor")
	}
	if categoryRule053(p) {
		result = append(result, "git")
	}
	if categoryRule054(p) {
		result = append(result, "http-client")
	}
	if categoryRule055(p) {
		result = append(result, "xml")
	}
	if categoryRule056(p) {
		result = append(result, "json")
	}
	if categoryRule057(p) {
		result = append(result, "yaml")
	}
	if categoryRule058(p) {
		result = append(result, "text-tools")
	}
	if categoryRule059(p) {
		result = append(result, "localization")
	}
	if categoryRule060(p) {
		result = append(result, "font")
	}
	if categoryRule061(p) {
		result = append(result, "graphics")
	}
	if categoryRule062(p) {
		result = append(result, "desktop")
	}
	if categoryRule063(p) {
		result = append(result, "wayland")
	}
	if categoryRule064(p) {
		result = append(result, "xorg")
	}
	if categoryRule065(p) {
		result = append(result, "audio")
	}
	if categoryRule066(p) {
		result = append(result, "bluetooth")
	}
	if categoryRule067(p) {
		result = append(result, "wifi")
	}
	if categoryRule068(p) {
		result = append(result, "network-manager")
	}
	if categoryRule069(p) {
		result = append(result, "vpn")
	}
	if categoryRule070(p) {
		result = append(result, "routing")
	}
	if categoryRule071(p) {
		result = append(result, "ldap")
	}
	if categoryRule072(p) {
		result = append(result, "kerberos")
	}
	if categoryRule073(p) {
		result = append(result, "sandbox")
	}
	if categoryRule074(p) {
		result = append(result, "flatpak")
	}
	if categoryRule075(p) {
		result = append(result, "snap")
	}
	if categoryRule076(p) {
		result = append(result, "cloud-init")
	}
	if categoryRule077(p) {
		result = append(result, "orchestration")
	}
	if categoryRule078(p) {
		result = append(result, "ansible")
	}
	if categoryRule079(p) {
		result = append(result, "terraform")
	}
	if categoryRule080(p) {
		result = append(result, "cockpit")
	}
	if categoryRule081(p) {
		result = append(result, "http-library")
	}
	if categoryRule082(p) {
		result = append(result, "sql-client")
	}
	if categoryRule083(p) {
		result = append(result, "pcap")
	}
	if categoryRule084(p) {
		result = append(result, "tracing")
	}
	if categoryRule085(p) {
		result = append(result, "benchmark")
	}
	if categoryRule086(p) {
		result = append(result, "security-scan")
	}
	if categoryRule087(p) {
		result = append(result, "sandbox-policy")
	}
	if categoryRule088(p) {
		result = append(result, "capabilities")
	}
	if categoryRule089(p) {
		result = append(result, "keyring")
	}
	if categoryRule090(p) {
		result = append(result, "usb")
	}
	if categoryRule091(p) {
		result = append(result, "pci")
	}
	if categoryRule092(p) {
		result = append(result, "power")
	}
	if categoryRule093(p) {
		result = append(result, "boot")
	}
	if categoryRule094(p) {
		result = append(result, "journaling")
	}
	if categoryRule095(p) {
		result = append(result, "metrics")
	}
	if categoryRule096(p) {
		result = append(result, "memory")
	}
	if categoryRule097(p) {
		result = append(result, "resource-control")
	}
	if categoryRule098(p) {
		result = append(result, "filesystem-encryption")
	}
	if categoryRule099(p) {
		result = append(result, "certificate-management")
	}
	if categoryRule100(p) {
		result = append(result, "ntfs")
	}
	if categoryRule101(p) {
		result = append(result, "exfat")
	}
	if categoryRule102(p) {
		result = append(result, "fat")
	}
	if categoryRule103(p) {
		result = append(result, "multipath")
	}
	if categoryRule104(p) {
		result = append(result, "raid")
	}
	if categoryRule105(p) {
		result = append(result, "package-signing")
	}
	if categoryRule106(p) {
		result = append(result, "build-system")
	}
	if categoryRule107(p) {
		result = append(result, "profiling")
	}
	if categoryRule108(p) {
		result = append(result, "http-testing")
	}
	if categoryRule109(p) {
		result = append(result, "sql-migration")
	}
	if categoryRule110(p) {
		result = append(result, "message-queue")
	}
	if categoryRule111(p) {
		result = append(result, "search-engine")
	}
	if categoryRule112(p) {
		result = append(result, "object-storage")
	}
	if categoryRule113(p) {
		result = append(result, "ceph")
	}
	if categoryRule114(p) {
		result = append(result, "cluster")
	}
	if categoryRule115(p) {
		result = append(result, "load-balancer")
	}
	if categoryRule116(p) {
		result = append(result, "filesystem-watch")
	}
	if categoryRule117(p) {
		result = append(result, "hostname")
	}
	if categoryRule118(p) {
		result = append(result, "locale")
	}
	if categoryRule119(p) {
		result = append(result, "manual-pages")
	}
	if categoryRule120(p) {
		result = append(result, "process-tools")
	}
	if categoryRule121(p) {
		result = append(result, "system-inspection")
	}
	if len(result) == 0 {
		result = append(result, "uncategorized")
	}
	return result
}

func categoryRule000(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"kernel", "kernel-core", "kernel-modules", "kernel-devel"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule001(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"grub2", "shim", "efibootmgr"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule002(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"systemd", "sysvinit", "openrc"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule003(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"rpm", "dnf", "libdnf", "hawkey", "createrepo"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule004(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"selinux", "policycoreutils", "setools", "setroubleshoot"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule005(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"firewalld", "nftables", "iptables"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule006(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"openssh", "dropbear"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule007(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"openssl", "gnutls", "nss", "libgcrypt", "libxcrypt"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule008(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"ca-certificates", "p11-kit", "trust"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule009(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"podman", "buildah", "skopeo", "crun", "runc", "conmon"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule010(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"netavark", "aardvark", "cni-plugins", "containernetworking"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule011(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"qemu", "libvirt", "virt-manager", "edk2", "ovmf"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule012(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"iproute", "iputils", "net-tools", "ethtool", "tcpdump"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule013(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"bind", "unbound", "dnsmasq", "systemd-resolved"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule014(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"httpd", "nginx", "lighttpd", "caddy"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule015(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"haproxy", "envoy", "traefik"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule016(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"php", "composer"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule017(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"python3", "python", "pyproject"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule018(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"golang", "go-toolset"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule019(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"rust", "cargo"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule020(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"gcc", "clang", "llvm", "binutils", "make", "cmake"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule021(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"gdb", "lldb", "strace", "ltrace", "perf"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule022(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"java", "openjdk", "maven", "gradle"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule023(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"nodejs", "npm", "yarn"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule024(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"perl", "cpan"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule025(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"ruby", "gem", "bundler"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule026(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"postgresql", "libpq"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule027(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"mariadb", "mysql"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule028(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"sqlite"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule029(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"redis", "valkey"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule030(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"mongodb", "mongosh"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule031(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"prometheus", "node-exporter", "grafana", "collectd", "telegraf"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule032(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"rsyslog", "syslog-ng", "journald", "logrotate"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule033(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"cronie", "at", "anacron"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule034(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"borg", "restic", "rsync", "bacula", "duplicity"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule035(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"xfsprogs", "e2fsprogs", "btrfs-progs", "zfs", "util-linux"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule036(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"lvm2", "mdadm", "multipath", "smartmontools", "nvme-cli"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule037(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"nfs-utils", "libnfs"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule038(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"samba", "cifs-utils"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule039(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"iscsi", "open-iscsi", "targetcli"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule040(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"cups", "ghostscript"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule041(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"postfix", "dovecot", "sendmail", "exim"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule042(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"chrony", "ntp", "timesync"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule043(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"sssd", "krb5", "openldap", "pam", "authselect"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule044(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"audit", "ausearch", "aureport"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule045(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"aide", "ima-evm", "fsverity"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule046(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"dmidecode", "hwdata", "fwupd", "lshw"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule047(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"microcode", "linux-firmware", "fwupd"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule048(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"gzip", "bzip2", "xz", "zstd", "lz4"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule049(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"tar", "unzip", "zip", "cpio"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule050(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"bash", "zsh", "fish", "dash"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule051(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"ncurses", "tmux", "screen", "readline"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule052(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"vim", "nano", "emacs", "neovim"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule053(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"git", "git-lfs", "git-core"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule054(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"curl", "wget", "libcurl"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule055(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"libxml", "xmlstarlet", "xslt"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule056(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"jq", "json-c", "rapidjson"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule057(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"libyaml", "yq", "python3-pyyaml"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule058(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"grep", "sed", "gawk", "coreutils", "diffutils"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule059(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"glibc-langpack", "langpacks", "icu"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule060(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"fontconfig", "freetype", "dejavu-fonts"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule061(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"mesa", "vulkan", "libdrm"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule062(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"gnome", "kde", "plasma", "cinnamon", "xfce"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule063(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"wayland", "weston", "wlroots"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule064(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"xorg-x11", "xwayland", "libx11"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule065(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"pipewire", "pulseaudio", "alsa"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule066(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"bluez", "bluetooth"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule067(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"wpa_supplicant", "iwd", "wireless-regdb"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule068(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"networkmanager", "nmstate"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule069(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"openvpn", "wireguard", "strongswan", "libreswan"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule070(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"frr", "bird", "quagga"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule071(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"openldap", "389-ds"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule072(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"krb5", "heimdal"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule073(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"bubblewrap", "flatpak", "firejail"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule074(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"flatpak", "xdg-desktop-portal"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule075(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"snapd", "snap-confine"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule076(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"cloud-init", "ignition", "afterburn"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule077(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"kubernetes", "kubelet", "kubectl", "cri-o"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule078(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"ansible", "ansible-core"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule079(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"terraform", "opentofu"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule080(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"cockpit"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule081(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"libnghttp2", "libnghttp3", "nghttp2"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule082(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"unixodbc", "libpq", "mariadb-connector"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule083(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"libpcap", "tcpdump", "wireshark"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule084(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"bpftrace", "bcc", "libbpf", "trace-cmd"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule085(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"fio", "sysbench", "stress-ng", "iperf"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule086(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"lynis", "clamav", "rkhunter", "chkrootkit"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule087(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"seccomp", "libseccomp"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule088(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"libcap", "libcap-ng"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule089(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"keyutils", "gnome-keyring"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule090(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"usbutils", "libusb", "usbguard"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule091(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"pciutils", "libpci"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule092(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"upower", "powertop", "tuned", "tlp"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule093(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"dracut", "plymouth", "kexec-tools"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule094(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"systemd-journal-remote", "journalbeat"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule095(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"pcp", "sysstat", "atop", "dstat"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule096(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"numactl", "memkind", "jemalloc", "tcmalloc"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule097(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"cgroup", "libcgroup", "systemd-oomd"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule098(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"cryptsetup", "clevis", "tang"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule099(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"certbot", "acme.sh", "step-cli"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule100(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"ntfs-3g", "ntfsprogs"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule101(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"exfatprogs", "exfat-utils"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule102(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"dosfstools", "mtools"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule103(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"device-mapper-multipath", "multipath-tools"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule104(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"mdadm", "dmraid"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule105(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"gnupg", "gpgme", "rpm-sign"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule106(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"meson", "ninja", "autoconf", "automake", "libtool"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule107(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"valgrind", "heaptrack", "gperftools"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule108(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"httpie", "ab", "wrk", "hey"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule109(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"flyway", "liquibase"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule110(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"rabbitmq", "activemq", "kafka"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule111(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"elasticsearch", "opensearch", "solr"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule112(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"minio", "ceph", "radosgw"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule113(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"ceph", "librados", "librbd"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule114(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"pacemaker", "corosync", "pcs"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule115(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"keepalived", "ipvsadm"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule116(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"inotify-tools", "fanotify"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule117(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"hostname", "hostnamectl"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule118(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"glibc-common", "glibc-locale-source"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule119(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"man-db", "man-pages", "info"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule120(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"procps-ng", "psmisc", "htop", "btop"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}

func categoryRule121(p Package) bool {
	name := lower(p.Name)
	if name == "" {
		return false
	}
	patterns := []string{"lsof", "util-linux", "lsblk", "lsusb"}
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if strings.HasPrefix(name, pattern+"-") {
			return true
		}
	}
	return false
}
