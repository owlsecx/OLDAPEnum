// OLDAPEnum — LDAP/AD Enumerator
// OWL Batch-3 offensive security toolkit.
// Author : khaled.s.haddad    Website : owlsec.org
// Language: Go (standard library only; static, CGO-free build).
// AUTHORIZED TESTING ONLY. See --howto for the legal & ethical warning.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
	DR  = "\033[96m" // legacy frame alias → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func line(w int)       { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", B, R) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

const APPNAME = "OLDAPEnum"
const SUITE = "Owl Offensive Suite"
const TAGLINE = "LDAP/AD Enumerator"
const SUBLINE = "Users · Groups · Computers · GPO · Trusts · ACLs · Kerberos attrs (offline)"
const VERSION = "1.1"
const CATEGORY = "OAttack"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

const BANNER = `
 ██████╗ ██╗     ██████╗  █████╗ ██████╗ ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔═══██╗██║     ██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║   ██║████╗ ████║
██║   ██║██║     ██║  ██║███████║██████╔╝█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██║   ██║██║     ██║  ██║██╔══██║██╔═══╝ ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
╚██████╔╝███████╗██████╔╝██║  ██║██║     ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
 ╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
`

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW) + col("   ·   MITRE "+MITRE_PRIMARY, DIM))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}
func menu(title string, items []string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Printf("  %s  %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(it, W))
	}
	fmt.Println()
	fmt.Println("  " + col("[H]", YLW+B) + "  " + col("Help & Usage", W) + col("  — how to use, options, CLI flags & examples", DIM))
	fmt.Println("  " + col("[0]", R+B) + "  " + col("Exit", W))
	fmt.Println()
	rule()
	return prompt("Select option")
}
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ============================================================================
//  SHARED ENGINE  —  types, CLI, export (txt/md/json/csv/sarif), grading,
//  HOW TO USE renderer, interactive cyan TUI, and domain utilities.
//  This block is identical across every OWL Batch-3 tool; each tool supplies
//  its own deep domain engine (catalogs, parsers, generators, scoring) that
//  plugs into the hooks declared at the bottom of this file.
// ============================================================================

// Finding is a single analysis result with MITRE ATT&CK mapping and a score.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Detail      string   `json:"detail"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	Mitre       []string `json:"mitre"`
	Score       int      `json:"score"`
	Ref         string   `json:"ref,omitempty"`
}

// Section is a titled block of lines used by HOW TO USE and catalog views.
type Section struct {
	Title string
	Lines []string
}

// MenuItem is one interactive action in the TUI.
type MenuItem struct {
	Label  string
	Action func()
}

// AnalysisResult is the full output of a domain analysis or demo run.
type AnalysisResult struct {
	Target   string            `json:"target"`
	Tool     string            `json:"tool"`
	When     string            `json:"when"`
	Findings []Finding         `json:"findings"`
	Stats    map[string]string `json:"stats"`
	Grade    string            `json:"grade"`
	Notes    []string          `json:"notes,omitempty"`
}

// ---------------------------------------------------------------------------
//  Severity model
// ---------------------------------------------------------------------------

const (
	SevCrit = "CRITICAL"
	SevHigh = "HIGH"
	SevMed  = "MEDIUM"
	SevLow  = "LOW"
	SevInfo = "INFO"
)

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCrit:
		return 5
	case SevHigh:
		return 4
	case SevMed:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevWeight(s string) int {
	switch strings.ToUpper(s) {
	case SevCrit:
		return 40
	case SevHigh:
		return 25
	case SevMed:
		return 12
	case SevLow:
		return 5
	case SevInfo:
		return 1
	}
	return 0
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case SevCrit:
		return R + B
	case SevHigh:
		return R
	case SevMed:
		return YLW
	case SevLow:
		return W
	default:
		return GY
	}
}

// sarifLevel maps a severity to a SARIF result level.
func sarifLevel(s string) string {
	switch strings.ToUpper(s) {
	case SevCrit, SevHigh:
		return "error"
	case SevMed:
		return "warning"
	case SevLow, SevInfo:
		return "note"
	}
	return "none"
}

// ---------------------------------------------------------------------------
//  Grading — convert a set of findings into an A+..F posture grade.
// ---------------------------------------------------------------------------

func gradeFromFindings(fs []Finding) string {
	risk := 0
	for _, f := range fs {
		risk += sevWeight(f.Severity)
	}
	switch {
	case risk == 0:
		return "A+"
	case risk <= 5:
		return "A"
	case risk <= 15:
		return "B"
	case risk <= 30:
		return "C"
	case risk <= 60:
		return "D"
	case risk <= 100:
		return "E"
	default:
		return "F"
	}
}

func gradeMeaning(g string) string {
	switch g {
	case "A+":
		return "no material exposure detected"
	case "A":
		return "minimal exposure; strong posture"
	case "B":
		return "minor issues; generally solid"
	case "C":
		return "moderate exposure; remediation advised"
	case "D":
		return "significant exposure; prioritize fixes"
	case "E":
		return "severe exposure; urgent remediation"
	default:
		return "critical exposure; immediate action required"
	}
}

func gradeColor(g string) string {
	switch g {
	case "A+", "A":
		return GRN + B
	case "B", "C":
		return YLW + B
	default:
		return R + B
	}
}

// ---------------------------------------------------------------------------
//  Global flags / state
// ---------------------------------------------------------------------------

var (
	flHelp    = flag.Bool("help", false, "show rich usage help and exit")
	flH       = flag.Bool("h", false, "alias for --help")
	flVersion = flag.Bool("version", false, "print version and exit")
	flHowto   = flag.Bool("howto", false, "show the HOW TO USE screen and exit")
	flDemo    = flag.Bool("demo", false, "run a self-contained synthetic demonstration")
	flInput   = flag.String("input", "", "path to an input file to analyze")
	flPath    = flag.String("path", "", "alias for --input (subject path/file)")
	flTarget  = flag.String("target", "", "logical target name/label for the report")
	flFormat  = flag.String("format", "txt", "export format: txt|md|json|csv|sarif")
	flOutput  = flag.String("output", "", "write export to FILE instead of stdout")
	flNoColor = flag.Bool("no-color", false, "disable ANSI colors")
	flCatalog = flag.Bool("catalog", false, "print the built-in reference catalog and exit")
	flList    = flag.Bool("list", false, "alias for --catalog")
	flQuiet   = flag.Bool("quiet", false, "suppress banner in CLI export mode")
	flSelf    = flag.Bool("selftest", false, "run built-in self-tests and exit")
	flRoast   = flag.Bool("roastable", false, "export AS-REP/Kerberoastable accounts (for OKerberang)")
	flStale   = flag.Int("stale", 0, "list accounts with password/logon older than N days")
	flPaths   = flag.Bool("paths", false, "print attack-path hints (roastable → privilege)")
)

var lastResult *AnalysisResult

// ---------------------------------------------------------------------------
//  main
// ---------------------------------------------------------------------------

func main() {
	flag.Usage = usage
	flag.Parse()

	if *flNoColor {
		noColor = true
	}

	switch {
	case *flHelp || *flH:
		usage()
		return
	case *flVersion:
		fmt.Printf("%s %s  (author khaled.s.haddad, owlsec.org)\n", APPNAME, VERSION)
		return
	case *flSelf:
		os.Exit(runSelfTest())
	case *flHowto:
		printHowto()
		return
	case *flCatalog || *flList:
		printCatalog()
		return
	case *flDemo:
		res := domainDemoResult()
		finalize(&res)
		lastResult = &res
		if !*flQuiet {
			renderResult(&res)
		}
		if *flOutput != "" || *flFormat != "txt" {
			emitExport(&res)
		}
		return
	}

	in := firstNonEmpty(*flInput, *flPath)
	// v1.1 sub-modes operate on the loaded directory.
	if in != "" && (*flRoast || *flStale > 0 || *flPaths) {
		dir, err := loadDirectory(in)
		if err != nil {
			errMsg("load failed: " + err.Error())
			os.Exit(1)
		}
		if *flRoast {
			out := exportRoastable(dir)
			if *flOutput != "" {
				if err := os.WriteFile(*flOutput, []byte(out), 0644); err != nil {
					errMsg(err.Error())
				} else {
					okMsg("Wrote " + *flOutput)
				}
			} else {
				fmt.Print(out)
			}
		}
		if *flStale > 0 {
			st := staleAccounts(dir, *flStale)
			if len(st) == 0 {
				fmt.Printf("# no accounts older than %d days\n", *flStale)
			}
			for _, s := range st {
				fmt.Println(s)
			}
		}
		if *flPaths {
			for _, h := range attackPathHints(dir) {
				fmt.Println(h)
			}
		}
		return
	}
	if in != "" {
		res, err := domainAnalyze(in)
		if err != nil {
			errMsg("analysis failed: " + err.Error())
			os.Exit(1)
		}
		finalize(&res)
		lastResult = &res
		if !*flQuiet {
			renderResult(&res)
		}
		emitExport(&res)
		return
	}

	// No actionable flags -> interactive TUI.
	interactive()
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// finalize fills defaulted fields (timestamp, tool, grade) on a result.
func finalize(r *AnalysisResult) {
	if r.When == "" {
		r.When = time.Now().Format("2006-01-02 15:04:05 -0700")
	}
	if r.Tool == "" {
		r.Tool = APPNAME
	}
	if r.Stats == nil {
		r.Stats = map[string]string{}
	}
	if r.Grade == "" {
		r.Grade = gradeFromFindings(r.Findings)
	}
	sortFindings(r.Findings)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].ID < fs[j].ID
	})
}

// ---------------------------------------------------------------------------
//  Usage / help
// ---------------------------------------------------------------------------

func usage() {
	if !*flQuiet {
		banner()
	}
	fmt.Println("  " + col("USAGE", CY+B))
	fmt.Printf("    %s [flags]\n", strings.ToLower(APPNAME))
	fmt.Println()
	fmt.Println("  " + col("DESCRIPTION", CY+B))
	for _, ln := range wrap(domainSummary(), 68) {
		fmt.Println("    " + ln)
	}
	fmt.Println()
	fmt.Println("  " + col("CORE FLAGS", CY+B))
	helpRow("-h, --help", "show this rich usage help")
	helpRow("--version", "print version and exit")
	helpRow("--howto", "show the HOW TO USE screen (legal, steps, nav)")
	helpRow("--demo", "run a self-contained synthetic demonstration")
	helpRow("--catalog, --list", "print the built-in reference catalog")
	helpRow("--input FILE", "analyze FILE (also --path)")
	helpRow("--target NAME", "label the engagement/target in the report")
	helpRow("--format FMT", "export format: txt|md|json|csv|sarif")
	helpRow("--output FILE", "write export to FILE (default stdout)")
	helpRow("--no-color", "disable ANSI colors")
	helpRow("--quiet", "suppress banner in export mode")
	helpRow("--roastable", "export AS-REP/Kerberoastable accounts (feeds OKerberang)")
	helpRow("--stale N", "list accounts with password/logon older than N days")
	helpRow("--paths", "print attack-path hints (roastable → privilege)")
	fmt.Println()
	fmt.Println("  " + col("INPUT FORMATS", CY+B))
	fmt.Println("    LDIF (default), CSV (header row: sam,uac,spn,class,…), or a JSON")
	fmt.Println("    array of account objects — detected by extension/content.")
	fmt.Println()
	fmt.Println("  " + col("EXAMPLES", CY+B))
	fmt.Printf("    %s                      # interactive cyan TUI\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --input export.ldif --format sarif --output out.sarif\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --input dir.csv --roastable --output roast.csv\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --input dir.json --stale 180\n", strings.ToLower(APPNAME))
	fmt.Printf("    %s --input export.ldif --paths\n", strings.ToLower(APPNAME))
	fmt.Println()
	fmt.Println("  " + col("MITRE ATT&CK", CY+B))
	fmt.Println("    primary: " + MITRE_PRIMARY + "  (" + mitreName(MITRE_PRIMARY) + ")")
	fmt.Println("    " + strings.Join(MITRE_TAGS, ", "))
	fmt.Println()
	line(64)
	fmt.Println("  " + col("Authorized testing only. See --howto for the legal warning.", GY))
}

func helpRow(a, b string) {
	fmt.Printf("    %s %s\n", col(pad(a, 22), W), col(b, GY))
}

// ---------------------------------------------------------------------------
//  HOW TO USE screen  (MANDATORY — menu item + --howto flag)
// ---------------------------------------------------------------------------

func howtoSections() []Section {
	var secs []Section
	secs = append(secs, Section{
		Title: "LEGAL & ETHICAL WARNING",
		Lines: []string{
			APPNAME + " is an offensive-security tool for AUTHORIZED testing only.",
			"Use it solely on systems and data you own or have EXPLICIT, WRITTEN",
			"permission to assess. Unauthorized access, interception, or attack is",
			"illegal in most jurisdictions (e.g. CFAA, Computer Misuse Act, GDPR).",
			"This build performs OFFLINE analysis, parsing, planning and lab",
			"generation only; it does not attack third parties. You are solely",
			"responsible for staying within the scope of your engagement and law.",
			"Keep all artifacts, hashes and credentials in your authorized vault.",
		},
	})
	steps := domainHowtoSteps()
	secs = append(secs, Section{Title: "HOW TO USE", Lines: numbered(steps)})
	secs = append(secs, Section{
		Title: "NAVIGATION",
		Lines: []string{
			"Launch with no arguments for the interactive TUI.",
			"At each menu type the number of an option and press Enter.",
			"[H] opens Help & Usage (this screen); also available via --howto.",
			"[0] exits the current menu or the program.",
			"Every result view can be exported (txt/md/json/csv/sarif).",
			"Use --input FILE for non-interactive (CLI) analysis and export.",
		},
	})
	secs = append(secs, Section{Title: "REQUIREMENTS", Lines: domainRequirements()})
	secs = append(secs, domainHowtoNotes()...)
	secs = append(secs, Section{
		Title: "EXPORT & REPORTING",
		Lines: []string{
			"Formats: txt (console report), md (Markdown), json (machine),",
			"csv (spreadsheet), sarif (SARIF 2.1.0 for CI/code-scanning).",
			"Findings carry MITRE ATT&CK technique IDs and an A+..F grade.",
			"Example: --input data --format sarif --output report.sarif",
		},
	})
	return secs
}

func printHowto() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  HOW TO USE — "+APPNAME, CY+B))
	fmt.Println()
	renderSections(howtoSections())
}

func renderSections(secs []Section) {
	for _, s := range secs {
		fmt.Println("  " + col("⬡  "+s.Title, CY+B))
		line(64)
		for _, ln := range s.Lines {
			fmt.Println("   " + col(ln, W))
		}
		fmt.Println()
	}
}

func numbered(items []string) []string {
	out := make([]string, 0, len(items))
	for i, it := range items {
		out = append(out, fmt.Sprintf("%2d. %s", i+1, it))
	}
	return out
}

// ---------------------------------------------------------------------------
//  Catalog printing (CLI)
// ---------------------------------------------------------------------------

func printCatalog() {
	if !*flQuiet {
		clear()
		banner()
	}
	fmt.Println("  " + col("⬡  REFERENCE CATALOG — "+APPNAME, CY+B))
	fmt.Println()
	renderSections(domainCatalogSections())
}

// ---------------------------------------------------------------------------
//  Result rendering (console)
// ---------------------------------------------------------------------------

func renderResult(r *AnalysisResult) {
	clear()
	banner()
	fmt.Println("  " + col("⬡  RESULT — "+r.Tool, CY+B))
	fmt.Println("  " + col("target : ", DIM) + col(nz(r.Target, "(none)"), W))
	fmt.Println("  " + col("time   : ", DIM) + col(r.When, W))
	gc := gradeColor(r.Grade)
	fmt.Println("  " + col("grade  : ", DIM) + col(r.Grade, gc) + col("  ("+gradeMeaning(r.Grade)+")", GY))
	fmt.Println()
	if len(r.Stats) > 0 {
		fmt.Println("  " + col("⬡  STATISTICS", CY+B))
		keys := make([]string, 0, len(r.Stats))
		for k := range r.Stats {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("   %s %s\n", col(pad(k+":", 22), GY), col(r.Stats[k], W))
		}
		fmt.Println()
	}
	renderSevHistogram(r.Findings)
	if len(r.Findings) == 0 {
		okMsg("no findings")
	} else {
		fmt.Println("  " + col(fmt.Sprintf("⬡  FINDINGS (%d)", len(r.Findings)), CY+B))
		line(64)
		for _, f := range r.Findings {
			renderFinding(f)
		}
	}
	if tm := topMitre(r.Findings, 6); len(tm) > 0 {
		fmt.Println()
		fmt.Println("  " + col("⬡  TOP MITRE ATT&CK", CY+B))
		for _, m := range tm {
			info(m)
		}
	}
	if len(r.Notes) > 0 {
		fmt.Println()
		fmt.Println("  " + col("⬡  NOTES", CY+B))
		for _, n := range r.Notes {
			info(n)
		}
	}
}

func renderFinding(f Finding) {
	tag := col("["+f.Severity+"]", sevColor(f.Severity))
	fmt.Printf("  %s %s %s\n", tag, col(f.ID, DR), col(f.Title, W+B))
	if f.Category != "" {
		fmt.Println("      " + col("category : ", GY) + col(f.Category, W))
	}
	for _, ln := range wrap(f.Detail, 60) {
		fmt.Println("      " + col(ln, W))
	}
	if f.Evidence != "" {
		for _, ln := range wrap("evidence: "+f.Evidence, 60) {
			fmt.Println("      " + col(ln, GY))
		}
	}
	if f.Remediation != "" {
		for _, ln := range wrap("fix: "+f.Remediation, 60) {
			fmt.Println("      " + col(ln, GRN))
		}
	}
	if len(f.Mitre) > 0 {
		fmt.Println("      " + col("mitre: "+strings.Join(f.Mitre, ", "), CY))
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
//  Export engine — TXT / MD / JSON / CSV / SARIF 2.1.0
// ---------------------------------------------------------------------------

func emitExport(r *AnalysisResult) {
	format := strings.ToLower(strings.TrimSpace(*flFormat))
	var data string
	switch format {
	case "", "txt":
		data = exportTXT(r)
	case "md", "markdown":
		data = exportMD(r)
	case "json":
		data = exportJSON(r)
	case "csv":
		data = exportCSV(r)
	case "sarif":
		data = exportSARIF(r)
	default:
		errMsg("unknown format: " + format + " (use txt|md|json|csv|sarif)")
		return
	}
	if *flOutput == "" {
		if format != "txt" {
			fmt.Println(data)
		}
		return
	}
	if err := os.WriteFile(*flOutput, []byte(data), 0644); err != nil {
		errMsg("write failed: " + err.Error())
		return
	}
	okMsg(fmt.Sprintf("wrote %s (%d bytes, %s)", *flOutput, len(data), format))
}

func exportTXT(r *AnalysisResult) string {
	var b strings.Builder
	b.WriteString("OWL " + APPNAME + " — " + TAGLINE + "\n")
	b.WriteString("author khaled.s.haddad  owlsec.org\n")
	b.WriteString(strings.Repeat("=", 64) + "\n")
	b.WriteString("target : " + nz(r.Target, "(none)") + "\n")
	b.WriteString("time   : " + r.When + "\n")
	b.WriteString("grade  : " + r.Grade + " (" + gradeMeaning(r.Grade) + ")\n")
	b.WriteString("mitre  : " + MITRE_PRIMARY + " " + strings.Join(MITRE_TAGS, " ") + "\n\n")
	if len(r.Stats) > 0 {
		b.WriteString("STATISTICS\n" + strings.Repeat("-", 64) + "\n")
		for _, k := range sortedKeys(r.Stats) {
			b.WriteString("  " + pad(k+":", 24) + r.Stats[k] + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf("FINDINGS (%d)\n", len(r.Findings)))
	b.WriteString(strings.Repeat("-", 64) + "\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%s] %s  %s\n", f.Severity, f.ID, f.Title))
		if f.Category != "" {
			b.WriteString("    category   : " + f.Category + "\n")
		}
		if f.Detail != "" {
			b.WriteString("    detail     : " + f.Detail + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("    evidence   : " + f.Evidence + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("    remediation: " + f.Remediation + "\n")
		}
		if len(f.Mitre) > 0 {
			b.WriteString("    mitre      : " + strings.Join(f.Mitre, ", ") + "\n")
		}
		b.WriteString("    score      : " + strconv.Itoa(f.Score) + "\n\n")
	}
	for _, n := range r.Notes {
		b.WriteString("note: " + n + "\n")
	}
	return b.String()
}

func exportMD(r *AnalysisResult) string {
	var b strings.Builder
	b.WriteString("# OWL " + APPNAME + " — " + TAGLINE + "\n\n")
	b.WriteString("*author khaled.s.haddad · owlsec.org*\n\n")
	b.WriteString("| field | value |\n|---|---|\n")
	b.WriteString("| target | " + mdEsc(nz(r.Target, "(none)")) + " |\n")
	b.WriteString("| time | " + mdEsc(r.When) + " |\n")
	b.WriteString("| grade | **" + r.Grade + "** (" + gradeMeaning(r.Grade) + ") |\n")
	b.WriteString("| mitre | " + MITRE_PRIMARY + " " + strings.Join(MITRE_TAGS, " ") + " |\n\n")
	if len(r.Stats) > 0 {
		b.WriteString("## Statistics\n\n| metric | value |\n|---|---|\n")
		for _, k := range sortedKeys(r.Stats) {
			b.WriteString("| " + mdEsc(k) + " | " + mdEsc(r.Stats[k]) + " |\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf("## Findings (%d)\n\n", len(r.Findings)))
	for _, f := range r.Findings {
		b.WriteString("### [" + f.Severity + "] " + mdEsc(f.Title) + " `" + f.ID + "`\n\n")
		if f.Category != "" {
			b.WriteString("- **category:** " + mdEsc(f.Category) + "\n")
		}
		if f.Detail != "" {
			b.WriteString("- **detail:** " + mdEsc(f.Detail) + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("- **evidence:** `" + f.Evidence + "`\n")
		}
		if f.Remediation != "" {
			b.WriteString("- **remediation:** " + mdEsc(f.Remediation) + "\n")
		}
		if len(f.Mitre) > 0 {
			b.WriteString("- **mitre:** " + strings.Join(f.Mitre, ", ") + "\n")
		}
		b.WriteString("- **score:** " + strconv.Itoa(f.Score) + "\n\n")
	}
	return b.String()
}

func exportJSON(r *AnalysisResult) string {
	payload := map[string]interface{}{
		"tool":         APPNAME,
		"tagline":      TAGLINE,
		"version":      VERSION,
		"author":       "khaled.s.haddad",
		"website":      "owlsec.org",
		"mitrePrimary": MITRE_PRIMARY,
		"mitreTags":    MITRE_TAGS,
		"result":       r,
	}
	buf, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "{\"error\":\"" + err.Error() + "\"}"
	}
	return string(buf)
}

func exportCSV(r *AnalysisResult) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "severity", "category", "title", "detail", "evidence", "remediation", "mitre", "score"})
	for _, f := range r.Findings {
		w.Write([]string{
			f.ID, f.Severity, f.Category, f.Title, f.Detail, f.Evidence,
			f.Remediation, strings.Join(f.Mitre, " "), strconv.Itoa(f.Score),
		})
	}
	w.Flush()
	return buf.String()
}

func exportSARIF(r *AnalysisResult) string {
	rules := map[string]bool{}
	var ruleList []map[string]interface{}
	var results []map[string]interface{}
	for _, f := range r.Findings {
		if !rules[f.ID] {
			rules[f.ID] = true
			ruleList = append(ruleList, map[string]interface{}{
				"id":               f.ID,
				"name":             f.Title,
				"shortDescription": map[string]string{"text": f.Title},
				"fullDescription":  map[string]string{"text": nz(f.Detail, f.Title)},
				"helpUri":          "https://owlsec.org",
				"properties": map[string]interface{}{
					"category": f.Category,
					"mitre":    f.Mitre,
				},
			})
		}
		results = append(results, map[string]interface{}{
			"ruleId": f.ID,
			"level":  sarifLevel(f.Severity),
			"message": map[string]string{
				"text": f.Title + ". " + f.Detail + nzPrefix(" Evidence: ", f.Evidence),
			},
			"properties": map[string]interface{}{
				"severity": f.Severity,
				"score":    f.Score,
				"mitre":    f.Mitre,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{"uri": nz(r.Target, APPNAME)},
					},
				},
			},
		})
	}
	sarif := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           APPNAME,
						"fullName":       "OWL " + APPNAME + " — " + TAGLINE,
						"version":        VERSION,
						"informationUri": "https://owlsec.org",
						"organization":   "owlsec.org / khaled.s.haddad",
						"rules":          ruleList,
					},
				},
				"results": results,
				"properties": map[string]interface{}{
					"grade":        r.Grade,
					"mitrePrimary": MITRE_PRIMARY,
					"target":       r.Target,
				},
			},
		},
	}
	buf, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "{\"error\":\"" + err.Error() + "\"}"
	}
	return string(buf)
}

// ---------------------------------------------------------------------------
//  Interactive TUI
// ---------------------------------------------------------------------------

func interactive() {
	for {
		items := []string{
			"Run DEMO (synthetic walkthrough)",
			"Analyze an input file",
			"Reference catalog",
		}
		dm := domainMenuItems()
		for _, m := range dm {
			items = append(items, m.Label)
		}
		items = append(items,
			"View last result",
			"Export last result",
			"HOW TO USE",
			"About / MITRE mapping",
		)
		choice := menu("MAIN MENU — "+TAGLINE, items)
		switch strings.ToLower(choice) {
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Stay authorized. Goodbye.")
			return
		case "h", "help", "?":
			printHowto()
			pause()
		case "1":
			res := domainDemoResult()
			finalize(&res)
			lastResult = &res
			renderResult(&res)
			pause()
		case "2":
			actionAnalyze()
		case "3":
			clear()
			banner()
			fmt.Println("  " + col("⬡  REFERENCE CATALOG", CY+B))
			fmt.Println()
			renderSections(domainCatalogSections())
			pause()
		default:
			handleDynamicChoice(choice, dm)
		}
	}
}

// handleDynamicChoice resolves menu numbers for domain items and trailing items.
func handleDynamicChoice(choice string, dm []MenuItem) {
	n, err := strconv.Atoi(choice)
	if err != nil {
		errMsg("invalid selection")
		pause()
		return
	}
	base := 3 // first three fixed items
	if n > base && n <= base+len(dm) {
		dm[n-base-1].Action()
		return
	}
	idx := n - base - len(dm)
	switch idx {
	case 1: // view last
		if lastResult == nil {
			warnMsg("no result yet — run DEMO or analyze a file first")
			pause()
			return
		}
		renderResult(lastResult)
		pause()
	case 2: // export last
		actionExport()
	case 3: // howto
		printHowto()
		pause()
	case 4: // about
		actionAbout()
	default:
		errMsg("invalid selection")
		pause()
	}
}

func actionAnalyze() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  ANALYZE INPUT", CY+B))
	fmt.Println()
	p := prompt("path to input file")
	if p == "" {
		warnMsg("cancelled")
		pause()
		return
	}
	res, err := domainAnalyze(p)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	finalize(&res)
	lastResult = &res
	renderResult(&res)
	pause()
}

func actionExport() {
	if lastResult == nil {
		warnMsg("no result yet — run DEMO or analyze a file first")
		pause()
		return
	}
	clear()
	banner()
	fmt.Println("  " + col("⬡  EXPORT LAST RESULT", CY+B))
	fmt.Println()
	f := prompt("format txt|md|json|csv|sarif")
	if f == "" {
		f = "txt"
	}
	o := prompt("output file (blank = screen)")
	*flFormat = f
	*flOutput = o
	if o == "" {
		var data string
		switch strings.ToLower(f) {
		case "md":
			data = exportMD(lastResult)
		case "json":
			data = exportJSON(lastResult)
		case "csv":
			data = exportCSV(lastResult)
		case "sarif":
			data = exportSARIF(lastResult)
		default:
			data = exportTXT(lastResult)
		}
		fmt.Println()
		fmt.Println(data)
	} else {
		emitExport(lastResult)
	}
	pause()
}

func actionAbout() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  ABOUT", CY+B))
	fmt.Println()
	for _, ln := range wrap(domainSummary(), 64) {
		fmt.Println("   " + col(ln, W))
	}
	fmt.Println()
	fmt.Println("  " + col("⬡  MITRE ATT&CK", CY+B))
	fmt.Println("   primary : " + col(MITRE_PRIMARY+"  "+mitreName(MITRE_PRIMARY), W))
	for _, t := range MITRE_TAGS {
		fmt.Println("   " + col(pad(t, 12), CY) + col(mitreName(t), GY))
	}
	fmt.Println()
	fmt.Println("  " + col("author khaled.s.haddad  ·  owlsec.org  ·  "+VERSION, GY))
	pause()
}

// ---------------------------------------------------------------------------
//  MITRE reference table (subset relevant to Batch-3 offensive tooling)
// ---------------------------------------------------------------------------

var mitreTable = map[string]string{
	"T1027":     "Obfuscated Files or Information",
	"T1027.009": "Embedded Payloads",
	"T1027.010": "Command Obfuscation",
	"T1059":     "Command and Scripting Interpreter",
	"T1059.001": "PowerShell",
	"T1059.003": "Windows Command Shell",
	"T1059.004": "Unix Shell",
	"T1059.005": "Visual Basic",
	"T1059.006": "Python",
	"T1059.007": "JavaScript",
	"T1105":     "Ingress Tool Transfer",
	"T1090":     "Proxy",
	"T1087":     "Account Discovery",
	"T1087.002": "Domain Account Discovery",
	"T1110":     "Brute Force",
	"T1110.003": "Password Spraying",
	"T1134":     "Access Token Manipulation",
	"T1134.001": "Token Impersonation/Theft",
	"T1134.002": "Create Process with Token",
	"T1134.005": "SID-History Injection",
	"T1135":     "Network Share Discovery",
	"T1548":     "Abuse Elevation Control Mechanism",
	"T1548.002": "Bypass User Account Control",
	"T1548.003": "Sudo and Sudo Caching",
	"T1558":     "Steal or Forge Kerberos Tickets",
	"T1558.003": "Kerberoasting",
	"T1558.004": "AS-REP Roasting",
	"T1611":     "Escape to Host",
	"T1210":     "Exploitation of Remote Services",
	"T1021":     "Remote Services",
	"T1021.002": "SMB/Windows Admin Shares",
	"T1069":     "Permission Groups Discovery",
	"T1482":     "Domain Trust Discovery",
	"T1078":     "Valid Accounts",
	"T1003":     "OS Credential Dumping",
	"TA0001":    "Initial Access",
	"TA0002":    "Execution",
	"TA0003":    "Persistence",
	"TA0004":    "Privilege Escalation",
	"TA0005":    "Defense Evasion",
	"TA0006":    "Credential Access",
	"TA0007":    "Discovery",
	"TA0008":    "Lateral Movement",
	"TA0010":    "Exfiltration",
	"TA0011":    "Command and Control",
}

func mitreName(id string) string {
	if n, ok := mitreTable[id]; ok {
		return n
	}
	return "technique"
}

// ---------------------------------------------------------------------------
//  Domain utilities shared by every tool (entropy, hashing, encoders, text)
// ---------------------------------------------------------------------------

// shannonEntropy returns bits/byte (0..8) for a byte slice.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func entropyVerdict(e float64) string {
	switch {
	case e >= 7.5:
		return "very high (encrypted/packed/compressed)"
	case e >= 6.5:
		return "high (encoded/compressed)"
	case e >= 5.0:
		return "moderate (mixed/base64-ish)"
	case e >= 3.0:
		return "low (plain text/code)"
	default:
		return "very low (repetitive/structured)"
	}
}

func b64Encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
func b64Decode(s string) (string, error) {
	d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return string(d), err
}
func hexEncode(s string) string { return hex.EncodeToString([]byte(s)) }

func gzipB64(s string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func md5Hex(s string) string    { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func sha1Hex(s string) string   { h := sha1.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func sha256Hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// utf16leB64 encodes a string as UTF-16LE then base64 (PowerShell -EncodedCommand).
func utf16leB64(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		if r < 0x10000 {
			buf.WriteByte(byte(r))
			buf.WriteByte(byte(r >> 8))
		} else {
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			buf.WriteByte(byte(hi))
			buf.WriteByte(byte(hi >> 8))
			buf.WriteByte(byte(lo))
			buf.WriteByte(byte(lo >> 8))
		}
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func xorBytes(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// classifyCharset reports character-class composition of a string.
func classifyCharset(s string) (lower, upper, digit, space, punct int) {
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			lower++
		case unicode.IsUpper(r):
			upper++
		case unicode.IsDigit(r):
			digit++
		case unicode.IsSpace(r):
			space++
		default:
			punct++
		}
	}
	return
}

func randHex(n int) string {
	const h = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = h[rand.Intn(16)]
	}
	return string(b)
}

func randID(prefix string) string {
	return prefix + "-" + randHex(6)
}

// ---------------------------------------------------------------------------
//  Small text/formatting helpers
// ---------------------------------------------------------------------------

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func nzPrefix(prefix, s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return prefix + s
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func wrap(s string, width int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}

func baseName(p string) string { return filepath.Base(p) }

func mustInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func reFind(pattern, s string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re.FindStringSubmatch(s)
}

func reAll(pattern, s string) [][]string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re.FindAllStringSubmatch(s, -1)
}

func contains(hay, needle string) bool {
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

func titleOf(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func mkFinding(id, title, sev, cat, detail string, mitre []string) Finding {
	return Finding{
		ID:       id,
		Title:    title,
		Severity: sev,
		Category: cat,
		Detail:   detail,
		Mitre:    mitre,
		Score:    sevWeight(sev),
	}
}

// ---------------------------------------------------------------------------
//  Binary read helpers (little/big endian) for protocol parsers.
// ---------------------------------------------------------------------------

func u16LE(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off : off+2])
}

func u32LE(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off : off+4])
}

func u16BE(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[off : off+2])
}

func u32BE(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint32(b[off : off+4])
}

func hexDump(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		sb.WriteString(fmt.Sprintf("%08x  ", i))
		for j := i; j < i+16; j++ {
			if j < end {
				sb.WriteString(fmt.Sprintf("%02x ", b[j]))
			} else {
				sb.WriteString("   ")
			}
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			c := b[j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Severity analytics (used by result rendering and stats)
// ---------------------------------------------------------------------------

func sevHistogram(fs []Finding) map[string]int {
	h := map[string]int{SevCrit: 0, SevHigh: 0, SevMed: 0, SevLow: 0, SevInfo: 0}
	for _, f := range fs {
		k := strings.ToUpper(f.Severity)
		if _, ok := h[k]; ok {
			h[k]++
		} else {
			h[SevInfo]++
		}
	}
	return h
}

func renderSevHistogram(fs []Finding) {
	if len(fs) == 0 {
		return
	}
	h := sevHistogram(fs)
	order := []string{SevCrit, SevHigh, SevMed, SevLow, SevInfo}
	max := 1
	for _, k := range order {
		if h[k] > max {
			max = h[k]
		}
	}
	fmt.Println("  " + col("⬡  SEVERITY BREAKDOWN", CY+B))
	for _, k := range order {
		n := h[k]
		barLen := (n * 30) / max
		if n > 0 && barLen == 0 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		fmt.Printf("   %s %s %s\n", col(pad(k, 9), sevColor(k)), col(pad(strconv.Itoa(n), 3), W), col(bar, sevColor(k)))
	}
	fmt.Println()
}

// mitreTally counts technique IDs across findings.
func mitreTally(fs []Finding) map[string]int {
	t := map[string]int{}
	for _, f := range fs {
		for _, m := range f.Mitre {
			t[m]++
		}
	}
	return t
}

func topMitre(fs []Finding, n int) []string {
	t := mitreTally(fs)
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range t {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	var out []string
	for i, e := range arr {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s x%d (%s)", e.k, e.v, mitreName(e.k)))
	}
	return out
}

// ---------------------------------------------------------------------------
//  Generic parsing & text helpers (shared by domain engines)
// ---------------------------------------------------------------------------

func parseKVLine(line, sep string) (string, string, bool) {
	i := strings.Index(line, sep)
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):]), true
}

// tokenizeArgs splits a command line honoring simple single/double quotes.
func tokenizeArgs(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	inTok := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			inTok = true
		case r == '\'' || r == '"':
			quote = r
			inTok = true
		case r == ' ' || r == '\t':
			if inTok {
				out = append(out, cur.String())
				cur.Reset()
				inTok = false
			}
		default:
			cur.WriteRune(r)
			inTok = true
		}
	}
	if inTok {
		out = append(out, cur.String())
	}
	return out
}

func splitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
	var out []string
	for _, x := range f {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func pct(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100.0 / float64(total)
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

const b32alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func base32Encode(data []byte) string {
	var sb strings.Builder
	var buf uint64
	var bits int
	for _, b := range data {
		buf = (buf << 8) | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(b32alpha[(buf>>uint(bits))&0x1f])
		}
	}
	if bits > 0 {
		sb.WriteByte(b32alpha[(buf<<uint(5-bits))&0x1f])
	}
	for sb.Len()%8 != 0 {
		sb.WriteByte('=')
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Generic directed graph with weighted BFS/Dijkstra shortest path.
//  Used by attack-path / reachability domains.
// ---------------------------------------------------------------------------

type GraphEdge struct {
	To     string
	Label  string
	Weight int
}

type Graph struct {
	Adj   map[string][]GraphEdge
	Nodes map[string]bool
}

func NewGraph() *Graph {
	return &Graph{Adj: map[string][]GraphEdge{}, Nodes: map[string]bool{}}
}

func (g *Graph) AddNode(n string) {
	if n == "" {
		return
	}
	g.Nodes[n] = true
	if _, ok := g.Adj[n]; !ok {
		g.Adj[n] = nil
	}
}

func (g *Graph) AddEdge(from, to, label string, weight int) {
	g.AddNode(from)
	g.AddNode(to)
	g.Adj[from] = append(g.Adj[from], GraphEdge{To: to, Label: label, Weight: weight})
}

// ShortestPath returns the min-weight path and total cost, or nil if none.
func (g *Graph) ShortestPath(src, dst string) ([]string, []string, int) {
	const inf = int(^uint(0) >> 1)
	dist := map[string]int{}
	prev := map[string]string{}
	prevLabel := map[string]string{}
	for n := range g.Nodes {
		dist[n] = inf
	}
	if _, ok := g.Nodes[src]; !ok {
		return nil, nil, -1
	}
	dist[src] = 0
	visited := map[string]bool{}
	for {
		u := ""
		best := inf
		for n, d := range dist {
			if !visited[n] && d < best {
				best = d
				u = n
			}
		}
		if u == "" {
			break
		}
		if u == dst {
			break
		}
		visited[u] = true
		for _, e := range g.Adj[u] {
			nd := dist[u] + e.Weight
			if nd < dist[e.To] {
				dist[e.To] = nd
				prev[e.To] = u
				prevLabel[e.To] = e.Label
			}
		}
	}
	if dist[dst] == inf {
		return nil, nil, -1
	}
	var path []string
	var labels []string
	cur := dst
	for cur != src {
		path = append([]string{cur}, path...)
		labels = append([]string{prevLabel[cur]}, labels...)
		p, ok := prev[cur]
		if !ok {
			return nil, nil, -1
		}
		cur = p
	}
	path = append([]string{src}, path...)
	return path, labels, dist[dst]
}

// ReachableFrom returns all nodes reachable from src (BFS).
func (g *Graph) ReachableFrom(src string) []string {
	seen := map[string]bool{src: true}
	queue := []string{src}
	var out []string
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, e := range g.Adj[u] {
			if !seen[e.To] {
				seen[e.To] = true
				out = append(out, e.To)
				queue = append(queue, e.To)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
//  SID / RID helpers (Windows / AD domains)
// ---------------------------------------------------------------------------

// parseSIDString validates and splits an SDDL-style SID string.
func parseSIDString(s string) (parts []string, ok bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "S-") {
		return nil, false
	}
	parts = strings.Split(s, "-")
	if len(parts) < 3 {
		return nil, false
	}
	for i := 1; i < len(parts); i++ {
		if _, err := strconv.ParseUint(parts[i], 10, 64); err != nil {
			return nil, false
		}
	}
	return parts, true
}

func sidRID(s string) (uint64, bool) {
	parts, ok := parseSIDString(s)
	if !ok || len(parts) < 3 {
		return 0, false
	}
	n, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	return n, err == nil
}

func wellKnownRID(rid uint64) string {
	switch rid {
	case 500:
		return "Administrator"
	case 501:
		return "Guest"
	case 502:
		return "KRBTGT"
	case 512:
		return "Domain Admins"
	case 513:
		return "Domain Users"
	case 514:
		return "Domain Guests"
	case 515:
		return "Domain Computers"
	case 516:
		return "Domain Controllers"
	case 518:
		return "Schema Admins"
	case 519:
		return "Enterprise Admins"
	case 520:
		return "Group Policy Creator Owners"
	case 544:
		return "Administrators (builtin)"
	case 545:
		return "Users (builtin)"
	case 546:
		return "Guests (builtin)"
	case 547:
		return "Power Users (builtin)"
	case 548:
		return "Account Operators"
	case 549:
		return "Server Operators"
	case 550:
		return "Print Operators"
	case 551:
		return "Backup Operators"
	case 552:
		return "Replicator"
	case 553:
		return "RAS and IAS Servers"
	case 554:
		return "Pre-Windows 2000 Compatible Access"
	case 555:
		return "Remote Desktop Users"
	case 556:
		return "Network Configuration Operators"
	case 557:
		return "Incoming Forest Trust Builders"
	case 558:
		return "Performance Monitor Users"
	case 559:
		return "Performance Log Users"
	case 560:
		return "Windows Authorization Access Group"
	case 561:
		return "Terminal Server License Servers"
	case 562:
		return "Distributed COM Users"
	case 568:
		return "IIS_IUSRS"
	case 569:
		return "Cryptographic Operators"
	case 573:
		return "Event Log Readers"
	case 574:
		return "Certificate Service DCOM Access"
	case 575:
		return "RDS Remote Access Servers"
	case 576:
		return "RDS Endpoint Servers"
	case 577:
		return "RDS Management Servers"
	case 578:
		return "Hyper-V Administrators"
	case 579:
		return "Access Control Assistance Operators"
	case 580:
		return "Remote Management Users"
	}
	return ""
}

func isPrivilegedRID(rid uint64) bool {
	switch rid {
	case 500, 512, 518, 519, 520, 544, 548, 549, 550, 551, 578:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
//  Hash format detectors (NTLM / Kerberos / Unix)
// ---------------------------------------------------------------------------

type hashKind struct {
	Name   string
	Mode   string // hashcat mode
	Sample string
	Re     *regexp.Regexp
}

var hashKinds = []hashKind{
	{"NTLM", "1000", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", regexp.MustCompile(`(?i)^[0-9a-f]{32}:[0-9a-f]{32}$`)},
	{"NTLM-hash-only", "1000", "31d6cfe0d16ae931b73c59d7e0c089c0", regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)},
	{"NetNTLMv1", "5500", "user::domain:LMRESP:NTRESP:challenge", regexp.MustCompile(`^[^:]+:[^:]*:[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]+$`)},
	{"NetNTLMv2", "5600", "user::domain:challenge:response:blob", regexp.MustCompile(`^[^:]+:[^:]*:[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:.+`)},
	{"Kerberos-23-TGS", "13100", "$krb5tgs$23$*user$realm$spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$23\$`)},
	{"Kerberos-18-TGS", "19700", "$krb5tgs$18$user$realm$*spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$18\$`)},
	{"Kerberos-17-TGS", "19600", "$krb5tgs$17$user$realm$*spn*$checksum$edata", regexp.MustCompile(`(?i)^\$krb5tgs\$17\$`)},
	{"Kerberos-23-ASREP", "18200", "$krb5asrep$23$user@realm$hash", regexp.MustCompile(`(?i)^\$krb5asrep\$23\$`)},
	{"Kerberos-18-ASREP", "19800", "$krb5asrep$18$user@realm$hash", regexp.MustCompile(`(?i)^\$krb5asrep\$18\$`)},
	{"md5crypt", "500", "$1$salt$hash", regexp.MustCompile(`^\$1\$[^$]+\$[./0-9A-Za-z]{22}$`)},
	{"sha256crypt", "7400", "$5$salt$hash", regexp.MustCompile(`^\$5\$(rounds=\d+\$)?[^$]+\$[./0-9A-Za-z]{43}$`)},
	{"sha512crypt", "1800", "$6$salt$hash", regexp.MustCompile(`^\$6\$(rounds=\d+\$)?[^$]+\$[./0-9A-Za-z]{86}$`)},
	{"bcrypt", "3200", "$2y$10$...", regexp.MustCompile(`^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$`)},
	{"yescrypt", "n/a", "$y$j9T$...", regexp.MustCompile(`^\$y\$`)},
	{"LM", "3000", "aad3b435b51404eeaad3b435b51404ee", regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)},
	{"mscash2", "2100", "$DCC2$10240#user#hash", regexp.MustCompile(`(?i)^\$DCC2\$\d+#.+#[0-9a-f]{32}$`)},
	{"krb5pa-23", "7500", "$krb5pa$23$user$realm$salt$hash", regexp.MustCompile(`(?i)^\$krb5pa\$23\$`)},
	{"krb5pa-18", "19900", "$krb5pa$18$user$realm$salt$hash", regexp.MustCompile(`(?i)^\$krb5pa\$18\$`)},
}

func detectHash(line string) *hashKind {
	line = strings.TrimSpace(line)
	for i := range hashKinds {
		if hashKinds[i].Re.MatchString(line) {
			return &hashKinds[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
//  Minimal LDIF parser (shared by AD/LDAP tools)
// ---------------------------------------------------------------------------

type LDIFEntry struct {
	DN     string
	Attrs  map[string][]string
	Object string // first objectClass
}

func parseLDIF(text string) []LDIFEntry {
	var out []LDIFEntry
	var cur *LDIFEntry
	flush := func() {
		if cur != nil && cur.DN != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	lines := strings.Split(text, "\n")
	var cont string
	for _, raw := range lines {
		if strings.HasPrefix(raw, " ") && cont != "" {
			cont += strings.TrimPrefix(raw, " ")
			continue
		}
		if cont != "" {
			applyLDIFLine(&cur, cont)
			cont = ""
		}
		if strings.TrimSpace(raw) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "version:") {
			continue
		}
		cont = strings.TrimRight(raw, "\r")
	}
	if cont != "" {
		applyLDIFLine(&cur, cont)
	}
	flush()
	return out
}

func applyLDIFLine(cur **LDIFEntry, line string) {
	if strings.HasPrefix(line, "dn:") {
		if *cur == nil {
			*cur = &LDIFEntry{Attrs: map[string][]string{}}
		}
		(*cur).DN = strings.TrimSpace(strings.TrimPrefix(line, "dn:"))
		if strings.HasPrefix((*cur).DN, ":") { // base64 dn
			(*cur).DN = strings.TrimSpace(strings.TrimPrefix((*cur).DN, ":"))
			if d, err := base64.StdEncoding.DecodeString((*cur).DN); err == nil {
				(*cur).DN = string(d)
			}
		}
		return
	}
	if *cur == nil {
		*cur = &LDIFEntry{Attrs: map[string][]string{}}
	}
	i := strings.Index(line, ":")
	if i < 0 {
		return
	}
	attr := strings.TrimSpace(line[:i])
	val := strings.TrimSpace(line[i+1:])
	if strings.HasPrefix(val, ":") { // base64
		val = strings.TrimSpace(strings.TrimPrefix(val, ":"))
		if d, err := base64.StdEncoding.DecodeString(val); err == nil {
			val = string(d)
		}
	} else if strings.HasPrefix(val, "<") {
		// URL reference; keep as-is
	}
	(*cur).Attrs[attr] = append((*cur).Attrs[attr], val)
	if strings.EqualFold(attr, "objectClass") && (*cur).Object == "" {
		(*cur).Object = val
	}
}

func (e LDIFEntry) HasClass(c string) bool {
	for _, v := range e.Attrs["objectClass"] {
		if strings.EqualFold(v, c) {
			return true
		}
	}
	return false
}

func (e LDIFEntry) Attr(name string) string {
	vs := e.Attrs[name]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// ---------------------------------------------------------------------------
//  CSV helpers
// ---------------------------------------------------------------------------

func parseCSVText(text string) (headers []string, rows [][]string, err error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	all, err := r.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(all) == 0 {
		return nil, nil, nil
	}
	return all[0], all[1:], nil
}

func rowMap(headers, row []string) map[string]string {
	m := map[string]string{}
	for i, h := range headers {
		if i < len(row) {
			m[h] = row[i]
		}
	}
	return m
}

// ---------------------------------------------------------------------------
//  Score helpers used by graders
// ---------------------------------------------------------------------------

func riskBucket(score int) string {
	switch {
	case score >= 100:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 30:
		return "MEDIUM"
	case score >= 10:
		return "LOW"
	default:
		return "INFO"
	}
}

func combineGrades(gs ...string) string {
	worst := "A+"
	order := map[string]int{"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
	for _, g := range gs {
		if order[g] > order[worst] {
			worst = g
		}
	}
	return worst
}

// ============================================================================
//  DOMAIN ENGINE — OLDAPEnum : LDAP/AD Enumerator (offline LDIF/CSV analyzer)
//  Parses exported LDAP/AD directory data — users, groups, ACLs, SPNs,
//  UAC flags — and surfaces kerberoastable / AS-REP / privileged / stale
//  accounts. Does NOT bind to live LDAP. MITRE T1087 / T1069
// ============================================================================

var MITRE_PRIMARY = "T1087"
var MITRE_TAGS = []string{"T1087", "T1087.002", "T1069", "T1069.002", "T1482", "T1558.003", "T1558.004", "TA0007"}

func domainSummary() string {
	return "OLDAPEnum is an offline LDAP / Active Directory directory analyzer for " +
		"AUTHORIZED assessments. It ingests LDIF or CSV exports of users, groups, " +
		"computers, and GPOs; decodes userAccountControl; finds kerberoastable SPNs, " +
		"AS-REP roastable accounts, privileged RIDs, password-not-required / never-expires, " +
		"stale logons, and nested group exposure; then grades directory hygiene. " +
		"It does not perform live LDAP binds — bring an authorized LDIF/CSV dump."
}

// ---------------------------------------------------------------------------
//  UAC flags
// ---------------------------------------------------------------------------

var uacFlags = map[int]string{
	0x0001:    "SCRIPT",
	0x0002:    "ACCOUNTDISABLE",
	0x0008:    "HOMEDIR_REQUIRED",
	0x0010:    "LOCKOUT",
	0x0020:    "PASSWD_NOTREQD",
	0x0040:    "PASSWD_CANT_CHANGE",
	0x0080:    "ENCRYPTED_TEXT_PWD_ALLOWED",
	0x0100:    "TEMP_DUPLICATE_ACCOUNT",
	0x0200:    "NORMAL_ACCOUNT",
	0x0800:    "INTERDOMAIN_TRUST_ACCOUNT",
	0x1000:    "WORKSTATION_TRUST_ACCOUNT",
	0x2000:    "SERVER_TRUST_ACCOUNT",
	0x10000:   "DONT_EXPIRE_PASSWORD",
	0x20000:   "MNS_LOGON_ACCOUNT",
	0x40000:   "SMARTCARD_REQUIRED",
	0x80000:   "TRUSTED_FOR_DELEGATION",
	0x100000:  "NOT_DELEGATED",
	0x200000:  "USE_DES_KEY_ONLY",
	0x400000:  "DONT_REQ_PREAUTH",
	0x800000:  "PASSWORD_EXPIRED",
	0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
	0x4000000: "PARTIAL_SECRETS_ACCOUNT",
}

func decodeUAC(v int) []string {
	var out []string
	keys := make([]int, 0, len(uacFlags))
	for k := range uacFlags {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		if v&k != 0 {
			out = append(out, uacFlags[k])
		}
	}
	return out
}

func uacHas(v int, flag int) bool { return v&flag != 0 }

// ---------------------------------------------------------------------------
//  Directory model
// ---------------------------------------------------------------------------

type ldapAccount struct {
	DN              string
	SAM             string
	UPN             string
	Display         string
	ObjectClass     string // user, group, computer, organizationalUnit, groupPolicyContainer
	SID             string
	RID             uint64
	UAC             int
	UACFlags        []string
	SPNs            []string
	MemberOf        []string
	Members         []string
	AdminCount      bool
	Description     string
	PasswordLastSet string
	LastLogon       string
	WhenCreated     string
	Enabled         bool
	PrimaryGroupID  int
	ServiceAccount  bool
	ManagedBy       string
	Extra           map[string]string
}

type ldapDirectory struct {
	Domain   string
	Accounts []ldapAccount
}

func classifyLDAPEntry(e LDIFEntry) ldapAccount {
	a := ldapAccount{
		DN: e.DN, Extra: map[string]string{},
		SAM: e.Attr("sAMAccountName"), UPN: e.Attr("userPrincipalName"),
		Display: e.Attr("displayName"), Description: e.Attr("description"),
		SID:             e.Attr("objectSid"),
		PasswordLastSet: e.Attr("pwdLastSet"), LastLogon: firstNonEmpty(e.Attr("lastLogonTimestamp"), e.Attr("lastLogon")),
		WhenCreated: e.Attr("whenCreated"), ManagedBy: e.Attr("managedBy"),
		SPNs:     append([]string{}, e.Attrs["servicePrincipalName"]...),
		MemberOf: append([]string{}, e.Attrs["memberOf"]...),
		Members:  append([]string{}, e.Attrs["member"]...),
	}
	switch {
	case e.HasClass("computer"):
		a.ObjectClass = "computer"
	case e.HasClass("group"):
		a.ObjectClass = "group"
	case e.HasClass("groupPolicyContainer"):
		a.ObjectClass = "gpo"
	case e.HasClass("organizationalUnit"):
		a.ObjectClass = "ou"
	case e.HasClass("user") || e.HasClass("person"):
		a.ObjectClass = "user"
	default:
		if a.SAM != "" {
			a.ObjectClass = "user"
		} else {
			a.ObjectClass = e.Object
		}
	}
	a.UAC = atoiOr(e.Attr("userAccountControl"), 0)
	a.UACFlags = decodeUAC(a.UAC)
	a.Enabled = a.UAC == 0 || !uacHas(a.UAC, 0x0002)
	a.AdminCount = e.Attr("adminCount") == "1" || strings.EqualFold(e.Attr("adminCount"), "true")
	a.PrimaryGroupID = atoiOr(e.Attr("primaryGroupID"), 0)
	if rid, ok := sidRID(a.SID); ok {
		a.RID = rid
	} else if a.PrimaryGroupID > 0 && a.ObjectClass == "user" {
		// leave
	}
	if strings.HasSuffix(a.SAM, "$") {
		a.ObjectClass = "computer"
	}
	a.ServiceAccount = len(a.SPNs) > 0 && a.ObjectClass == "user"
	for k, vs := range e.Attrs {
		if len(vs) > 0 {
			lk := strings.ToLower(k)
			if lk != "memberof" && lk != "member" && lk != "serviceprincipalname" && lk != "objectclass" {
				if _, ok := a.Extra[k]; !ok && len(a.Extra) < 20 {
					a.Extra[k] = vs[0]
				}
			}
		}
	}
	return a
}

func parseLDAPDirectory(text string) *ldapDirectory {
	dir := &ldapDirectory{}
	text = strings.TrimSpace(text)
	if text == "" {
		return dir
	}
	// JSON array of accounts?
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		var wrap struct {
			Domain   string        `json:"domain"`
			Accounts []ldapAccount `json:"accounts"`
			Users    []ldapAccount `json:"users"`
		}
		if json.Unmarshal([]byte(text), &wrap) == nil {
			dir.Domain = wrap.Domain
			dir.Accounts = append(wrap.Accounts, wrap.Users...)
			if len(dir.Accounts) > 0 {
				return dir
			}
		}
		var arr []ldapAccount
		if json.Unmarshal([]byte(text), &arr) == nil && len(arr) > 0 {
			dir.Accounts = arr
			return dir
		}
	}
	// CSV?
	first := strings.SplitN(text, "\n", 2)[0]
	if strings.Contains(first, ",") && (contains(first, "sam") || contains(first, "dn") || contains(first, "uac") || contains(first, "spn")) {
		if d := parseLDAPCSV(text); d != nil && len(d.Accounts) > 0 {
			return d
		}
	}
	// LDIF
	for _, e := range parseLDIF(text) {
		a := classifyLDAPEntry(e)
		if a.DN != "" || a.SAM != "" {
			dir.Accounts = append(dir.Accounts, a)
		}
		if dir.Domain == "" && strings.Contains(strings.ToLower(a.DN), "dc=") {
			// extract DC components
			parts := strings.Split(a.DN, ",")
			var dcs []string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(strings.ToLower(p), "dc=") {
					dcs = append(dcs, p[3:])
				}
			}
			if len(dcs) > 0 {
				dir.Domain = strings.Join(dcs, ".")
			}
		}
	}
	return dir
}

func parseLDAPCSV(text string) *ldapDirectory {
	dir := &ldapDirectory{}
	headers, rows, err := parseCSVText(text)
	if err != nil {
		return dir
	}
	hmap := map[string]int{}
	for i, h := range headers {
		hmap[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(row []string, keys ...string) string {
		for _, k := range keys {
			if i, ok := hmap[k]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
		}
		return ""
	}
	for _, row := range rows {
		a := ldapAccount{
			DN:              get(row, "dn", "distinguishedname"),
			SAM:             get(row, "sam", "samaccountname", "username", "user"),
			UPN:             get(row, "upn", "userprincipalname"),
			Display:         get(row, "display", "displayname", "name"),
			ObjectClass:     get(row, "class", "objectclass", "type"),
			SID:             get(row, "sid", "objectsid"),
			Description:     get(row, "description", "desc", "comment"),
			PasswordLastSet: get(row, "pwdlastset", "passwordlastset"),
			LastLogon:       get(row, "lastlogon", "lastlogontimestamp"),
			SPNs:            splitList(get(row, "spn", "serviceprincipalname", "spns")),
			MemberOf:        splitList(get(row, "memberof", "groups")),
			Extra:           map[string]string{},
		}
		a.UAC = atoiOr(get(row, "uac", "useraccountcontrol"), 0)
		a.UACFlags = decodeUAC(a.UAC)
		a.Enabled = a.UAC == 0 || !uacHas(a.UAC, 0x0002)
		a.AdminCount = get(row, "admincount") == "1" || strings.EqualFold(get(row, "admincount"), "true")
		if a.ObjectClass == "" {
			if strings.HasSuffix(a.SAM, "$") {
				a.ObjectClass = "computer"
			} else {
				a.ObjectClass = "user"
			}
		}
		if rid, ok := sidRID(a.SID); ok {
			a.RID = rid
		}
		a.ServiceAccount = len(a.SPNs) > 0 && a.ObjectClass == "user"
		if a.SAM != "" || a.DN != "" {
			dir.Accounts = append(dir.Accounts, a)
		}
	}
	return dir
}

// ---------------------------------------------------------------------------
//  Analysis
// ---------------------------------------------------------------------------

func analyzeLDAP(dir *ldapDirectory, target string) AnalysisResult {
	res := AnalysisResult{Target: target, Tool: APPNAME, Stats: map[string]string{}}
	var findings []Finding
	users, groups, computers, gpos := 0, 0, 0, 0
	disabled, roastASREP, roastSPN, noPreauth, pwdNotReq, neverExp, trustedDel, adminCnt := 0, 0, 0, 0, 0, 0, 0, 0
	n := 0

	for _, a := range dir.Accounts {
		switch strings.ToLower(a.ObjectClass) {
		case "user":
			users++
		case "group":
			groups++
		case "computer":
			computers++
		case "gpo", "grouppolicycontainer":
			gpos++
		}
		if !a.Enabled {
			disabled++
		}
		if a.AdminCount {
			adminCnt++
		}

		// AS-REP roastable
		if a.ObjectClass == "user" && uacHas(a.UAC, 0x400000) {
			roastASREP++
			noPreauth++
			n++
			findings = append(findings, Finding{
				ID: fmt.Sprintf("LDAP-ASREP-%03d", n), Title: "DONT_REQ_PREAUTH: " + nz(a.SAM, a.DN),
				Severity: SevHigh, Category: "asrep",
				Detail:      "Account does not require Kerberos pre-authentication — AS-REP roastable offline.",
				Evidence:    a.DN + " UAC=" + strconv.Itoa(a.UAC),
				Remediation: "Clear 'Do not require Kerberos preauthentication' in account options.",
				Mitre:       []string{"T1558.004", "T1087.002"}, Score: sevWeight(SevHigh),
			})
		}
		// Kerberoastable user SPNs
		if a.ObjectClass == "user" && len(a.SPNs) > 0 {
			roastSPN++
			for _, spn := range a.SPNs {
				n++
				sev := SevHigh
				if contains(spn, "MSSQL") || contains(spn, "HTTP") || contains(spn, "exchange") {
					sev = SevCrit
				}
				findings = append(findings, Finding{
					ID: fmt.Sprintf("LDAP-SPN-%03d", n), Title: "Kerberoastable SPN: " + a.SAM + " → " + spn,
					Severity: sev, Category: "kerberoast",
					Detail:   "User account with servicePrincipalName — TGS can be requested and cracked offline.",
					Evidence: a.DN, Remediation: "Move to gMSA; enforce long random password; monitor 4769.",
					Mitre: []string{"T1558.003", "T1087.002"}, Score: sevWeight(sev),
				})
			}
		}
		// PASSWD_NOTREQD
		if uacHas(a.UAC, 0x0020) && a.ObjectClass == "user" {
			pwdNotReq++
			n++
			findings = append(findings, Finding{
				ID: fmt.Sprintf("LDAP-NOPWD-%03d", n), Title: "PASSWD_NOTREQD: " + nz(a.SAM, a.DN),
				Severity: SevHigh, Category: "uac",
				Detail:   "Password-not-required flag set — account may have blank/weak password.",
				Evidence: "UAC=" + strconv.Itoa(a.UAC), Remediation: "Clear PASSWD_NOTREQD; enforce password policy.",
				Mitre: []string{"T1078", "T1087.002"}, Score: sevWeight(SevHigh),
			})
		}
		// DONT_EXPIRE_PASSWORD
		if uacHas(a.UAC, 0x10000) && a.ObjectClass == "user" && !strings.HasSuffix(a.SAM, "$") {
			neverExp++
			sev := SevMed
			if a.AdminCount || isPrivilegedRID(a.RID) {
				sev = SevHigh
			}
			n++
			findings = append(findings, Finding{
				ID: fmt.Sprintf("LDAP-NEVEREXP-%03d", n), Title: "Password never expires: " + nz(a.SAM, a.DN),
				Severity: sev, Category: "uac",
				Detail:   "DONT_EXPIRE_PASSWORD set.",
				Evidence: a.DN, Remediation: "Prefer managed passwords / gMSA; rotate privileged creds.",
				Mitre: []string{"T1078"}, Score: sevWeight(sev),
			})
		}
		// TRUSTED_FOR_DELEGATION
		if uacHas(a.UAC, 0x80000) || uacHas(a.UAC, 0x1000000) {
			trustedDel++
			n++
			sev := SevHigh
			if uacHas(a.UAC, 0x80000) {
				sev = SevCrit
			}
			kind := "constrained (T2A4D)"
			if uacHas(a.UAC, 0x80000) {
				kind = "UNCONSTRAINED"
			}
			findings = append(findings, Finding{
				ID: fmt.Sprintf("LDAP-DELEG-%03d", n), Title: "Delegation " + kind + ": " + nz(a.SAM, a.DN),
				Severity: sev, Category: "delegation",
				Detail:      "Delegation flags enable impersonation paths (print spooler / unconstrained).",
				Evidence:    "UAC flags: " + strings.Join(a.UACFlags, ","),
				Remediation: "Remove unconstrained delegation; use resource-based constrained; protect with protected users.",
				Mitre:       []string{"T1134.001", "T1558"}, Score: sevWeight(sev),
			})
		}
		// Privileged RID / adminCount
		if a.ObjectClass == "user" && (a.AdminCount || isPrivilegedRID(a.RID)) {
			n++
			label := wellKnownRID(a.RID)
			if label == "" {
				label = "adminCount=1"
			}
			findings = append(findings, Finding{
				ID: fmt.Sprintf("LDAP-PRIV-%03d", n), Title: "Privileged account: " + nz(a.SAM, a.DN) + " (" + label + ")",
				Severity: SevMed, Category: "privileged",
				Detail:      "High-privilege principal — verify Tier 0 controls and PAW usage.",
				Evidence:    a.DN + " RID=" + strconv.FormatUint(a.RID, 10),
				Remediation: "Tier Model; Protected Users; restrict interactive logon; monitor closely.",
				Mitre:       []string{"T1078.002", "T1069.002"}, Score: sevWeight(SevMed),
			})
		}
		// Privileged groups by name
		if a.ObjectClass == "group" && isHighValueGroup(a.SAM, a.DN) {
			n++
			findings = append(findings, Finding{
				ID: fmt.Sprintf("LDAP-GROUP-%03d", n), Title: "High-value group: " + nz(a.SAM, a.Display),
				Severity: SevInfo, Category: "group",
				Detail:   fmt.Sprintf("members_listed=%d — review nested membership offline.", len(a.Members)),
				Evidence: a.DN, Remediation: "Minimize standing membership; use PIM/JIT where available.",
				Mitre: []string{"T1069.002"}, Score: 1,
			})
		}
		// USE_DES_KEY_ONLY
		if uacHas(a.UAC, 0x200000) {
			n++
			findings = append(findings, Finding{
				ID: fmt.Sprintf("LDAP-DES-%03d", n), Title: "USE_DES_KEY_ONLY: " + nz(a.SAM, a.DN),
				Severity: SevHigh, Category: "crypto",
				Detail:   "DES Kerberos keys allowed — weak crypto.",
				Evidence: a.DN, Remediation: "Clear USE_DES_KEY_ONLY; disable DES domain-wide.",
				Mitre: []string{"T1558"}, Score: sevWeight(SevHigh),
			})
		}
	}

	res.Findings = findings
	res.Stats["domain"] = nz(dir.Domain, "(unknown)")
	res.Stats["accounts"] = strconv.Itoa(len(dir.Accounts))
	res.Stats["users"] = strconv.Itoa(users)
	res.Stats["groups"] = strconv.Itoa(groups)
	res.Stats["computers"] = strconv.Itoa(computers)
	res.Stats["gpos"] = strconv.Itoa(gpos)
	res.Stats["disabled"] = strconv.Itoa(disabled)
	res.Stats["asrep_roastable"] = strconv.Itoa(roastASREP)
	res.Stats["kerberoastable"] = strconv.Itoa(roastSPN)
	res.Stats["passwd_notreqd"] = strconv.Itoa(pwdNotReq)
	res.Stats["never_expires"] = strconv.Itoa(neverExp)
	res.Stats["delegation"] = strconv.Itoa(trustedDel)
	res.Stats["admincount"] = strconv.Itoa(adminCnt)
	res.Grade = gradeFromFindings(findings)
	res.Notes = append(res.Notes, "Offline LDIF/CSV analysis — no live LDAP bind performed.")
	res.Notes = append(res.Notes, "Distinct from OLdapX (config/anonymous-bind auditor) and OAD (BloodHound audit).")
	return res
}

func isHighValueGroup(sam, dn string) bool {
	u := strings.ToUpper(sam + " " + dn)
	keys := []string{"DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS", "ADMINISTRATORS",
		"ACCOUNT OPERATORS", "BACKUP OPERATORS", "SERVER OPERATORS", "PRINT OPERATORS",
		"DNSADMINS", "GROUP POLICY CREATOR", "EXCHANGE", "ORGANIZATION MANAGEMENT",
		"HYPER-V ADMINISTRATORS", "REMOTE DESKTOP USERS", "REMOTE MANAGEMENT USERS"}
	for _, k := range keys {
		if strings.Contains(u, k) {
			return true
		}
	}
	return false
}

func domainAnalyze(path string) (AnalysisResult, error) {
	text, err := readFileString(path)
	if err != nil {
		return AnalysisResult{}, err
	}
	dir, err := parseDirectoryAuto(path, text)
	if err != nil {
		return AnalysisResult{}, err
	}
	if len(dir.Accounts) == 0 {
		return AnalysisResult{}, fmt.Errorf("no LDAP entries parsed from %s", path)
	}
	return analyzeLDAP(dir, baseName(path)), nil
}

// loadDirectory reads and parses a directory file in any supported format.
func loadDirectory(path string) (*ldapDirectory, error) {
	text, err := readFileString(path)
	if err != nil {
		return nil, err
	}
	return parseDirectoryAuto(path, text)
}

func domainDemoResult() AnalysisResult {
	demo := strings.Join([]string{
		"dn: CN=John Doe,OU=Users,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: jdoe",
		"userPrincipalName: jdoe@corp.local",
		"userAccountControl: 512",
		"memberOf: CN=Domain Users,CN=Users,DC=corp,DC=local",
		"",
		"dn: CN=svc_backup,OU=Service,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: svc_backup",
		"userAccountControl: 4194816",
		"servicePrincipalName: HOST/backup.corp.local",
		"adminCount: 0",
		"",
		"dn: CN=svc_sql,OU=Service,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: svc_sql",
		"userAccountControl: 66048",
		"servicePrincipalName: MSSQLSvc/sql01.corp.local:1433",
		"servicePrincipalName: MSSQLSvc/sql01:1433",
		"",
		"dn: CN=legacy_scan,OU=Service,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: legacy_scan",
		"userAccountControl: 544",
		"",
		"dn: CN=fileroot$,OU=Servers,DC=corp,DC=local",
		"objectClass: computer",
		"sAMAccountName: FILEROOT$",
		"userAccountControl: 524800",
		"",
		"dn: CN=Domain Admins,CN=Users,DC=corp,DC=local",
		"objectClass: group",
		"sAMAccountName: Domain Admins",
		"member: CN=Administrator,CN=Users,DC=corp,DC=local",
		"adminCount: 1",
		"",
		"dn: CN=Administrator,CN=Users,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: Administrator",
		"objectSid: S-1-5-21-1000-2000-3000-500",
		"userAccountControl: 512",
		"adminCount: 1",
	}, "\n")
	dir := parseLDAPDirectory(demo)
	res := analyzeLDAP(dir, "demo-ldap")
	res.Notes = append(res.Notes, "Demo LDIF: AS-REP (svc_backup), Kerberoast (svc_sql), PASSWD_NOTREQD (legacy_scan), unconstrained delegation (FILEROOT$), privileged Administrator.")
	return res
}

func domainHowtoSteps() []string {
	return []string{
		"Export directory data via authorized ldapsearch/csvde/ldifde/SharpHound LDAP collection.",
		"Save as LDIF, CSV (sam,uac,spn,…), or JSON accounts array.",
		"Run OLDAPEnum --input FILE for offline analysis.",
		"Prioritize AS-REP, Kerberoast SPNs, PASSWD_NOTREQD, unconstrained delegation.",
		"Export findings; remediate flags; feed roastable accounts to OKerberang / lab cracking.",
	}
}

func domainRequirements() []string {
	return []string{
		"Offline LDIF/CSV/JSON directory export from authorized collection.",
		"No live LDAP bind required by this tool.",
		"Written authorization covering the assessed domain.",
	}
}

func domainHowtoNotes() []Section {
	return []Section{
		{Title: "KEY UAC FLAGS", Lines: []string{
			"0x0002 ACCOUNTDISABLE",
			"0x0020 PASSWD_NOTREQD",
			"0x10000 DONT_EXPIRE_PASSWORD",
			"0x80000 TRUSTED_FOR_DELEGATION (unconstrained)",
			"0x1000000 TRUSTED_TO_AUTH_FOR_DELEGATION (T2A4D)",
			"0x200000 USE_DES_KEY_ONLY",
			"0x400000 DONT_REQ_PREAUTH (AS-REP roastable)",
		}},
		{Title: "v1.1 OFFLINE FLAGS", Lines: []string{
			"--input FILE     LDIF / CSV / JSON (auto-detected)",
			"--roastable OUT  export AS-REP + Kerberoast accounts (feed OKerberang)",
			"--stale N        flag accounts with lastLogon older than N days",
			"--paths          print prioritized attack-path hints",
			"CSV header: sam,uac,spn,class,…  |  JSON: accounts array",
		}},
		{Title: "DISTINCT FROM", Lines: []string{
			"OLdapX — config / anonymous-bind auditor",
			"OAD — BloodHound misconfig auditor",
			"OKerberang — hash/ticket roast analyzer",
			"OLDAPEnum — directory CONTENTS enumerator/analyzer",
		}},
	}
}

func domainCatalogSections() []Section {
	var flags []string
	keys := make([]int, 0, len(uacFlags))
	for k := range uacFlags {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		flags = append(flags, fmt.Sprintf("0x%05X  %s", k, uacFlags[k]))
	}
	return []Section{
		{Title: "USERACCOUNTCONTROL FLAGS", Lines: flags},
		{Title: "OPERATOR NOTES", Lines: []string{
			"gMSA / MSA accounts are preferred for SPNs.",
			"Protected Users group blocks NTLM/delegation/DES.",
			"adminCount=1 sticks after group removal — clean orphaned adminSDHolder.",
			"Correlate SPN findings with OKerberang hash exports.",
			"Stale pwdLastSet + never-expires = long-lived credential risk.",
		}},
	}
}

func domainMenuItems() []MenuItem {
	return []MenuItem{
		{Label: "Decode a UAC value", Action: actionLDAPUAC},
		{Label: "UAC flag reference", Action: actionLDAPFlags},
		{Label: "Check privileged RID", Action: actionLDAPRID},
	}
}

func actionLDAPUAC() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  DECODE UAC", CY+B))
	fmt.Println()
	v := atoiOr(prompt("userAccountControl (int or 0xHEX)"), -1)
	if strings.HasPrefix(strings.ToLower(prompt("")), "") {
		// already got v; allow hex via strconv
	}
	raw := prompt("value again if hex (or blank to use previous int)")
	if raw != "" {
		if strings.HasPrefix(strings.ToLower(raw), "0x") {
			n, err := strconv.ParseInt(raw[2:], 16, 64)
			if err == nil {
				v = int(n)
			}
		} else {
			v = atoiOr(raw, v)
		}
	}
	if v < 0 {
		warnMsg("invalid")
		pause()
		return
	}
	okMsg(fmt.Sprintf("UAC=%d (0x%X)", v, v))
	for _, f := range decodeUAC(v) {
		info(f)
	}
	pause()
}

func actionLDAPFlags() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  UAC FLAGS", CY+B))
	fmt.Println()
	keys := make([]int, 0, len(uacFlags))
	for k := range uacFlags {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	rows := [][]string{}
	for _, k := range keys {
		rows = append(rows, []string{fmt.Sprintf("0x%X", k), strconv.Itoa(k), uacFlags[k]})
	}
	table([]string{"Hex", "Dec", "Flag"}, rows)
	pause()
}

func actionLDAPRID() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  RID / SID", CY+B))
	fmt.Println()
	s := prompt("SID or RID number")
	if rid, ok := sidRID(s); ok {
		okMsg(fmt.Sprintf("RID=%d %s privileged=%v", rid, wellKnownRID(rid), isPrivilegedRID(rid)))
	} else if n := atoiOr(s, -1); n >= 0 {
		okMsg(fmt.Sprintf("RID=%d %s privileged=%v", n, wellKnownRID(uint64(n)), isPrivilegedRID(uint64(n))))
	} else {
		warnMsg("not a SID/RID")
	}
	pause()
}

// ====================================================================
//  SELF-TEST — verifies the LDAP parser, analyzer, UAC decoder & export.
// ====================================================================

func containsFinding(fs []Finding, prefix string) bool {
	for _, f := range fs {
		if strings.HasPrefix(f.ID, prefix) {
			return true
		}
	}
	return false
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func runSelfTest() int {
	banner()
	fmt.Println("  " + col("⬡  Self-Test — "+APPNAME+" engine", B+CY))
	rule()
	fmt.Println()
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
		}
	}

	// UAC decoder against the canonical flag set.
	check("decodeUAC(0x400000) = DONT_REQ_PREAUTH", containsStr(decodeUAC(0x400000), "DONT_REQ_PREAUTH"))
	check("decodeUAC(0x20) = PASSWD_NOTREQD", containsStr(decodeUAC(0x20), "PASSWD_NOTREQD"))
	check("decodeUAC(0x80000) = TRUSTED_FOR_DELEGATION", containsStr(decodeUAC(0x80000), "TRUSTED_FOR_DELEGATION"))
	check("decodeUAC(0x10200) decodes multiple flags", len(decodeUAC(0x10200)) == 2)
	check("decodeUAC(0) = empty", len(decodeUAC(0)) == 0)
	check("uacFlags has 512=NORMAL_ACCOUNT", uacFlags[0x200] == "NORMAL_ACCOUNT")

	// LDIF parser.
	ldif := strings.Join([]string{
		"dn: CN=svc_roast,OU=Svc,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: svc_roast",
		"userAccountControl: 66048",
		"servicePrincipalName: MSSQLSvc/db01.corp.local:1433",
		"",
		"dn: CN=noauth,OU=Svc,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: noauth",
		"userAccountControl: 4194816", // 0x400000 + 0x200 => DONT_REQ_PREAUTH
		"",
		"dn: CN=weak,OU=Svc,DC=corp,DC=local",
		"objectClass: user",
		"sAMAccountName: weak",
		"userAccountControl: 544", // 0x20 PASSWD_NOTREQD + 0x200
	}, "\n")
	dir := parseLDAPDirectory(ldif)
	check("parseLDAPDirectory returns a directory", dir != nil)

	res := analyzeLDAP(dir, "selftest")
	check("analyze finds a Kerberoastable SPN", containsFinding(res.Findings, "LDAP-SPN"))
	check("analyze finds an AS-REP roastable account", containsFinding(res.Findings, "LDAP-ASREP"))
	check("analyze finds a PASSWD_NOTREQD account", containsFinding(res.Findings, "LDAP-NOPWD"))

	// demo path (rich LDIF) exercises every detector.
	demo := domainDemoResult()
	finalize(&demo)
	check("demo result has findings", len(demo.Findings) > 0)
	check("demo result is graded", demo.Grade != "")
	check("demo finds unconstrained delegation", containsFinding(demo.Findings, "LDAP-DELEG"))

	// grading & severity ranking.
	check("sevRank critical > high", sevRank("critical") > sevRank("high"))
	check("sevRank high > low", sevRank("high") > sevRank("low"))
	check("gradeFromFindings('') clean = A+", gradeFromFindings(nil) == "A+")

	// export.
	js := exportJSON(&demo)
	var parsed interface{}
	check("exportJSON produces valid JSON", json.Unmarshal([]byte(js), &parsed) == nil)
	check("exportJSON is non-trivial", len(js) > 50)

	// catalog + summary hooks.
	check("domainCatalogSections non-empty", len(domainCatalogSections()) > 0)
	check("domainSummary non-empty", len(strings.TrimSpace(domainSummary())) > 0)

	// UI helpers.
	check("stripANSI removes colour", stripANSI(col("hi", CY)) == "hi")
	check("visw counts runes", visw("abc") == 3)

	// v1.1: CSV & JSON directory input parse to the same accounts as LDIF.
	csvDir, eCSV := parseCSVDirectory("sam,uac,spn,class\nsvc,66048,MSSQLSvc/db:1433,user\nnoauth,4194816,,user\n")
	check("parseCSVDirectory reads rows", eCSV == nil && len(csvDir.Accounts) == 2)
	jsonDir, eJSON := parseJSONDirectory(`[{"sam":"svc","uac":66048,"spn":"MSSQLSvc/db:1433","class":"user"}]`)
	check("parseJSONDirectory reads array", eJSON == nil && len(jsonDir.Accounts) == 1)
	check("CSV account keeps SPN (service account)", csvDir.Accounts[0].ServiceAccount)

	// v1.1: roastable export.
	ro := exportRoastable(csvDir)
	check("exportRoastable lists a kerberoast line", strings.Contains(ro, "kerberoast,svc"))
	check("exportRoastable lists an asrep line", strings.Contains(ro, "asrep,noauth"))

	// v1.1: stale detection (FILETIME + ISO).
	oldFT := strconv.FormatInt((time.Now().AddDate(-2, 0, 0).Unix()+11644473600)*10000000, 10)
	days, ok := staleDays(oldFT)
	check("staleDays decodes a 2-year-old FILETIME", ok && days > 600)
	_, ok0 := staleDays("0")
	check("staleDays rejects zero", !ok0)
	dISO, okISO := staleDays("2000-01-01")
	check("staleDays parses an ISO date", okISO && dISO > 9000)

	// v1.1: attack-path hints.
	var privDir ldapDirectory
	privDir.Accounts = []ldapAccount{{SAM: "svc_sql", ServiceAccount: true, SPNs: []string{"x"}, AdminCount: true}}
	hints := attackPathHints(&privDir)
	check("attackPathHints flags roastable+privileged as CRITICAL", len(hints) == 1 && strings.Contains(hints[0], "CRITICAL"))

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}

// ====================================================================
//  v1.1 — CSV/JSON directory input, roastable export, stale accounts,
//         attack-path hints
// ====================================================================

// multiValAttrs are directory attributes that may carry several values.
var multiValAttrs = map[string]bool{
	"serviceprincipalname": true, "memberof": true, "member": true, "objectclass": true,
}

// entryFromMap turns a flat key→value record (CSV row / JSON object) into an
// LDIFEntry so it can reuse the existing classifier. Multi-valued attributes
// may be separated by ';' or '|'.
func entryFromMap(m map[string]string) LDIFEntry {
	e := LDIFEntry{Attrs: map[string][]string{}}
	for k, v := range m {
		if v == "" {
			continue
		}
		lk := strings.ToLower(k)
		key := k
		switch lk {
		case "dn":
			e.DN = v
			continue
		case "sam", "samaccountname":
			key = "sAMAccountName"
		case "uac", "useraccountcontrol":
			key = "userAccountControl"
		case "spn", "spns", "serviceprincipalname":
			key = "servicePrincipalName"
		case "class", "objectclass":
			key = "objectClass"
		case "admincount":
			key = "adminCount"
		}
		if multiValAttrs[strings.ToLower(key)] || strings.ContainsAny(v, ";|") {
			parts := strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == '|' })
			for _, p := range parts {
				if p = strings.TrimSpace(p); p != "" {
					e.Attrs[key] = append(e.Attrs[key], p)
				}
			}
		} else {
			e.Attrs[key] = append(e.Attrs[key], v)
		}
	}
	if oc := e.Attrs["objectClass"]; len(oc) > 0 {
		e.Object = oc[0]
	}
	if e.DN == "" {
		if sam := e.Attr("sAMAccountName"); sam != "" {
			e.DN = "CN=" + sam
		}
	}
	return e
}

func dirFromEntries(entries []LDIFEntry) *ldapDirectory {
	d := &ldapDirectory{}
	for _, e := range entries {
		d.Accounts = append(d.Accounts, classifyLDAPEntry(e))
	}
	return d
}

// parseCSVDirectory reads a header-row CSV into a directory.
func parseCSVDirectory(text string) (*ldapDirectory, error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("CSV needs a header row and at least one record")
	}
	head := rows[0]
	var entries []LDIFEntry
	for _, row := range rows[1:] {
		m := map[string]string{}
		for i, h := range head {
			if i < len(row) {
				m[h] = row[i]
			}
		}
		entries = append(entries, entryFromMap(m))
	}
	return dirFromEntries(entries), nil
}

// parseJSONDirectory reads a JSON array of account objects into a directory.
func parseJSONDirectory(text string) (*ldapDirectory, error) {
	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(text), &arr); err != nil {
		// allow {"accounts":[...]}
		var wrap struct {
			Accounts []map[string]interface{} `json:"accounts"`
		}
		if err2 := json.Unmarshal([]byte(text), &wrap); err2 != nil || len(wrap.Accounts) == 0 {
			return nil, fmt.Errorf("expected a JSON array of accounts (or {\"accounts\":[...]})")
		}
		arr = wrap.Accounts
	}
	var entries []LDIFEntry
	for _, obj := range arr {
		m := map[string]string{}
		for k, v := range obj {
			switch t := v.(type) {
			case string:
				m[k] = t
			case float64:
				m[k] = strconv.FormatFloat(t, 'f', -1, 64)
			case bool:
				if t {
					m[k] = "1"
				}
			case []interface{}:
				var ps []string
				for _, x := range t {
					ps = append(ps, fmt.Sprintf("%v", x))
				}
				m[k] = strings.Join(ps, ";")
			}
		}
		entries = append(entries, entryFromMap(m))
	}
	return dirFromEntries(entries), nil
}

// parseDirectoryAuto dispatches on file extension / content shape.
func parseDirectoryAuto(path, text string) (*ldapDirectory, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return parseJSONDirectory(text)
	case ".csv":
		return parseCSVDirectory(text)
	}
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		if d, err := parseJSONDirectory(text); err == nil && len(d.Accounts) > 0 {
			return d, nil
		}
	}
	return parseLDAPDirectory(text), nil
}

// roastableAccounts returns accounts that are AS-REP roastable (DONT_REQ_PREAUTH)
// or Kerberoastable (a user with an SPN).
func roastableAccounts(d *ldapDirectory) (asrep, kerberoast []ldapAccount) {
	for _, a := range d.Accounts {
		if uacHas(a.UAC, 0x400000) {
			asrep = append(asrep, a)
		}
		if a.ServiceAccount {
			kerberoast = append(kerberoast, a)
		}
	}
	return
}

// exportRoastable formats a roastable list for OKerberang / lab tooling.
func exportRoastable(d *ldapDirectory) string {
	asrep, kerb := roastableAccounts(d)
	var b strings.Builder
	b.WriteString("# type,account,spn\n")
	for _, a := range asrep {
		b.WriteString("asrep," + a.SAM + ",\n")
	}
	for _, a := range kerb {
		spn := ""
		if len(a.SPNs) > 0 {
			spn = a.SPNs[0]
		}
		b.WriteString("kerberoast," + a.SAM + "," + spn + "\n")
	}
	return b.String()
}

// staleDays returns the age in days of an AD timestamp (18-digit FILETIME) or
// an ISO-ish date string; ok=false when it cannot be parsed or is zero.
func staleDays(ts string) (int, bool) {
	ts = strings.TrimSpace(ts)
	if ts == "" || ts == "0" {
		return 0, false
	}
	// Windows FILETIME: 100-ns ticks since 1601-01-01.
	if n, err := strconv.ParseInt(ts, 10, 64); err == nil && n > 0 {
		const ticksPerSec = 10000000
		const epochDiff = 11644473600 // seconds between 1601 and 1970
		unix := n/ticksPerSec - epochDiff
		if unix <= 0 {
			return 0, false
		}
		return int(time.Since(time.Unix(unix, 0)).Hours() / 24), true
	}
	for _, layout := range []string{"2006-01-02", "20060102150405.0Z", "2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, ts); err == nil {
			return int(time.Since(t).Hours() / 24), true
		}
	}
	return 0, false
}

// staleAccounts flags accounts whose password/logon age exceeds thresholdDays.
func staleAccounts(d *ldapDirectory, thresholdDays int) []string {
	var out []string
	for _, a := range d.Accounts {
		if a.ObjectClass != "user" {
			continue
		}
		if days, ok := staleDays(a.PasswordLastSet); ok && days > thresholdDays {
			out = append(out, fmt.Sprintf("%s: password %d days old", nz(a.SAM, a.DN), days))
		} else if days, ok := staleDays(a.LastLogon); ok && days > thresholdDays {
			out = append(out, fmt.Sprintf("%s: last logon %d days ago", nz(a.SAM, a.DN), days))
		}
	}
	return out
}

// attackPathHints links roastable / weak accounts to privilege.
func attackPathHints(d *ldapDirectory) []string {
	var hints []string
	for _, a := range d.Accounts {
		priv := a.AdminCount || a.RID == 500 || a.RID == 512 || a.RID == 519
		switch {
		case uacHas(a.UAC, 0x400000) && priv:
			hints = append(hints, "CRITICAL: "+nz(a.SAM, a.DN)+" is AS-REP roastable AND privileged — crack offline → direct admin.")
		case a.ServiceAccount && priv:
			hints = append(hints, "CRITICAL: "+nz(a.SAM, a.DN)+" is Kerberoastable AND privileged — crack SPN ticket → admin.")
		case uacHas(a.UAC, 0x80000):
			hints = append(hints, "HIGH: "+nz(a.SAM, a.DN)+" has unconstrained delegation — compromise → impersonate any authenticating principal.")
		case a.ServiceAccount:
			hints = append(hints, "MEDIUM: "+nz(a.SAM, a.DN)+" is Kerberoastable — request SPN ticket, crack offline.")
		case uacHas(a.UAC, 0x400000):
			hints = append(hints, "MEDIUM: "+nz(a.SAM, a.DN)+" is AS-REP roastable — request AS-REP, crack offline.")
		}
	}
	return hints
}
