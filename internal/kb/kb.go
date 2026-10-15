// Package kb is the Website Load knowledge base: failure rules stored as
// YAML data (rules/kb/*.yaml), a strict loader with schema validation and a
// safety lint, and the engine that matches rules against an Observation
// and produces a verdict with evidence, ranked causes, server-specific fixes
// and honest "could not determine" items. Go code computes facts; all advice
// lives in the rule files. See the http-error-knowledge skill.
package kb

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"domaindoctor/rules"
)

// Enumerations used by the schema.
var (
	Layers      = []string{"dns", "cdn", "network", "tls", "server", "application", "content"}
	Severities  = []string{"fail", "warn", "info"}
	Likelihoods = []string{"high", "medium", "low"}
	// Targets a fix or snippet can apply to.
	Targets = []string{"any", "apache", "nginx", "litespeed", "iis", "caddy", "cloudflare", "cloudfront", "akamai",
		"fastly", "sucuri", "imperva", "bunny", "google-cdn", "azure-frontdoor", "wordpress", "php", "laravel", "nextjs", "registrar", "dns", "firewall", "browser"}
	// Template variables a verdict may use.
	TemplateVars = []string{"cdn", "server", "platform", "status", "host", "url", "cf_code", "error_kind"}
)

// Cond is one match condition; exactly one field is set.
type Cond struct {
	Status      []int       `yaml:"status,omitempty"`
	StatusRange string      `yaml:"status_range,omitempty"` // "500-599"
	ErrorKind   []string    `yaml:"error_kind,omitempty"`
	CDN         []string    `yaml:"cdn,omitempty"`
	Server      []string    `yaml:"server,omitempty"`
	Platform    []string    `yaml:"platform,omitempty"`
	Header      *HeaderCond `yaml:"header,omitempty"`
	Body        string      `yaml:"body,omitempty"` // regex on the response body sample
	Signal      string      `yaml:"signal,omitempty"`

	lo, hi int
	bodyRe *regexp.Regexp
}

type HeaderCond struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex,omitempty"`
	re    *regexp.Regexp
}

type Match struct {
	All  []Cond `yaml:"all"`
	Any  []Cond `yaml:"any,omitempty"`
	None []Cond `yaml:"none,omitempty"`
}

type Boost struct {
	When Cond    `yaml:"when"`
	Add  float64 `yaml:"add"`
	Why  string  `yaml:"why"`
}

type Confidence struct {
	Base   float64 `yaml:"base"`
	Boosts []Boost `yaml:"boosts,omitempty"`
}

type Cause struct {
	Text       string `yaml:"text" json:"text"`
	Likelihood string `yaml:"likelihood" json:"likelihood"`
}

type Fix struct {
	Step      string            `yaml:"step" json:"step"`
	Why       string            `yaml:"why,omitempty" json:"why,omitempty"`
	AppliesTo []string          `yaml:"applies_to,omitempty" json:"applies_to,omitempty"`
	Snippets  map[string]string `yaml:"snippets,omitempty" json:"snippets,omitempty"`
	Verify    string            `yaml:"verify" json:"verify"`
	Warning   string            `yaml:"warning,omitempty" json:"warning,omitempty"`
}

type Given struct {
	Status    int                 `yaml:"status"`
	ErrorKind string              `yaml:"error_kind"`
	CDN       string              `yaml:"cdn"`
	Server    string              `yaml:"server"`
	Platform  string              `yaml:"platform"`
	Headers   map[string][]string `yaml:"headers"`
	Body      string              `yaml:"body"`
	Signals   []string            `yaml:"signals"`
}

type Test struct {
	Name          string  `yaml:"name"`
	Given         Given   `yaml:"given"`
	Expect        string  `yaml:"expect"` // match | no_match
	MinConfidence float64 `yaml:"min_confidence,omitempty"`
}

type Rule struct {
	ID              string     `yaml:"id"`
	Title           string     `yaml:"title"`
	Layer           string     `yaml:"layer"`
	Severity        string     `yaml:"severity"`
	Priority        int        `yaml:"priority,omitempty"` // tie-breaker, lower first
	Group           string     `yaml:"group,omitempty"`    // only the best match per group is reported
	Match           Match      `yaml:"match"`
	Confidence      Confidence `yaml:"confidence"`
	Verdict         string     `yaml:"verdict"`
	Causes          []Cause    `yaml:"causes"`
	Fixes           []Fix      `yaml:"fixes"`
	CannotDetermine []string   `yaml:"cannot_determine"`
	Warnings        []string   `yaml:"warnings,omitempty"`
	Tests           []Test     `yaml:"tests"`

	File string `yaml:"-"`
}

var (
	idRe       = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_-]+)+$`)
	templateRe = regexp.MustCompile(`\{([a-z_]+)\}`)
	// Advice that must never be the (first) fix. A rule may mention one of
	// these only in a later fix that carries an explicit warning.
	unsafeAdvice = []*regexp.Regexp{
		regexp.MustCompile(`(?i)chmod\s+(-R\s+)?0?777`),
		regexp.MustCompile(`(?i)\b0?777\b`),
		regexp.MustCompile(`(?i)SecRuleEngine\s+Off`),
		regexp.MustCompile(`(?i)disable\s+(the\s+)?(firewall|waf|mod_?security|selinux|apparmor)`),
		regexp.MustCompile(`(?i)(InsecureSkipVerify|verify\s*=\s*false|--insecure\b|curl\s+-k\b|proxy_ssl_verify\s+off)`),
		regexp.MustCompile(`(?i)Options\s+\+?Indexes`),
	}
	// Absolutely banned, even with a warning.
	bannedAdvice = []*regexp.Regexp{regexp.MustCompile(`(?i)chmod\s+(-R\s+)?0?777`)}
)

func in(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// compile validates one condition and prepares its regexes.
func (c *Cond) compile() error {
	set := 0
	if len(c.Status) > 0 {
		set++
	}
	if c.StatusRange != "" {
		set++
		parts := strings.Split(c.StatusRange, "-")
		if len(parts) != 2 {
			return fmt.Errorf("bad status_range %q", c.StatusRange)
		}
		lo, e1 := strconv.Atoi(parts[0])
		hi, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil || lo > hi || lo < 100 || hi > 599 {
			return fmt.Errorf("bad status_range %q", c.StatusRange)
		}
		c.lo, c.hi = lo, hi
	}
	if len(c.ErrorKind) > 0 {
		set++
	}
	if len(c.CDN) > 0 {
		set++
	}
	if len(c.Server) > 0 {
		set++
	}
	if len(c.Platform) > 0 {
		set++
	}
	if c.Header != nil {
		set++
		if c.Header.Name == "" {
			return fmt.Errorf("header condition needs a name")
		}
		c.Header.Name = strings.ToLower(c.Header.Name)
		if c.Header.Regex != "" {
			re, err := regexp.Compile("(?is)" + c.Header.Regex)
			if err != nil {
				return err
			}
			c.Header.re = re
		}
	}
	if c.Body != "" {
		set++
		re, err := regexp.Compile("(?is)" + c.Body)
		if err != nil {
			return err
		}
		c.bodyRe = re
	}
	if c.Signal != "" {
		set++
		if !in(c.Signal, KnownSignals) {
			return fmt.Errorf("unknown signal %q", c.Signal)
		}
	}
	if set != 1 {
		return fmt.Errorf("a condition must set exactly one field (got %d)", set)
	}
	return nil
}

// Validate checks a rule's structure and advice. It also prepares regexes.
func (r *Rule) Validate() error {
	fail := func(f string, a ...any) error {
		return fmt.Errorf("rule %s (%s): %s", r.ID, r.File, fmt.Sprintf(f, a...))
	}
	if !idRe.MatchString(r.ID) {
		return fail("id must look like area.name (lowercase)")
	}
	if r.Title == "" || r.Verdict == "" {
		return fail("title and verdict are required")
	}
	if !in(r.Layer, Layers) {
		return fail("layer %q not in %v", r.Layer, Layers)
	}
	if !in(r.Severity, Severities) {
		return fail("severity %q not in %v", r.Severity, Severities)
	}
	if len(r.Match.All)+len(r.Match.Any) == 0 {
		return fail("match needs at least one condition in all or any")
	}
	for _, group := range [][]Cond{r.Match.All, r.Match.Any, r.Match.None} {
		for i := range group {
			if err := group[i].compile(); err != nil {
				return fail("match: %v", err)
			}
		}
	}
	if r.Confidence.Base <= 0 || r.Confidence.Base > 1 {
		return fail("confidence.base must be in (0,1]")
	}
	for i := range r.Confidence.Boosts {
		b := &r.Confidence.Boosts[i]
		if err := b.When.compile(); err != nil {
			return fail("boost: %v", err)
		}
		if b.Add <= 0 || b.Add > 0.5 || b.Why == "" {
			return fail("boost needs add in (0,0.5] and a why")
		}
	}
	for _, m := range templateRe.FindAllStringSubmatch(r.Verdict, -1) {
		if !in(m[1], TemplateVars) {
			return fail("verdict uses unknown variable {%s}", m[1])
		}
	}
	if len(r.Causes) == 0 {
		return fail("at least one cause is required")
	}
	for _, c := range r.Causes {
		if c.Text == "" || !in(c.Likelihood, Likelihoods) {
			return fail("cause needs text and likelihood in %v", Likelihoods)
		}
	}
	if len(r.Fixes) == 0 {
		return fail("at least one fix is required")
	}
	for i, f := range r.Fixes {
		if f.Step == "" || f.Verify == "" {
			return fail("fix %d needs step and verify", i+1)
		}
		for _, t := range f.AppliesTo {
			if !in(t, Targets) {
				return fail("fix %d applies_to unknown target %q", i+1, t)
			}
		}
		for k := range f.Snippets {
			if !in(k, Targets) {
				return fail("fix %d snippet for unknown target %q", i+1, k)
			}
		}
		if err := lintFix(i, f); err != nil {
			return fail("%v", err)
		}
	}
	for _, c := range r.Causes {
		if err := lintText(c.Text); err != nil {
			return fail("cause: %v", err)
		}
	}
	if len(r.CannotDetermine) == 0 {
		return fail("cannot_determine must list at least one thing the check cannot see")
	}
	pos := 0
	for _, t := range r.Tests {
		if t.Name == "" || (t.Expect != "match" && t.Expect != "no_match") {
			return fail("test needs a name and expect match|no_match")
		}
		if t.Expect == "match" {
			pos++
		}
	}
	if pos == 0 {
		return fail("at least one test with expect: match is required")
	}
	return nil
}

func fixText(f Fix) string {
	var b strings.Builder
	b.WriteString(f.Step + "\n" + f.Why + "\n" + f.Verify + "\n")
	for _, s := range f.Snippets {
		b.WriteString(s + "\n")
	}
	return b.String()
}

// lintFix enforces safe advice: banned patterns never; risky ones only in a
// later fix that carries an explicit warning (a safer fix comes first).
func lintFix(i int, f Fix) error {
	t := fixText(f)
	for _, re := range bannedAdvice {
		if re.MatchString(t) {
			return fmt.Errorf("fix %d contains banned advice %q", i+1, re.FindString(t))
		}
	}
	for _, re := range unsafeAdvice {
		if re.MatchString(t) && (i == 0 || f.Warning == "") {
			return fmt.Errorf("fix %d contains risky advice %q without a warning and a safer earlier fix", i+1, re.FindString(t))
		}
	}
	return nil
}

func lintText(t string) error {
	for _, re := range bannedAdvice {
		if re.MatchString(t) {
			return fmt.Errorf("banned advice %q", re.FindString(t))
		}
	}
	return nil
}

// KB is a loaded, validated rule set.
type KB struct {
	Rules []Rule
	byID  map[string]*Rule
}

// Rule returns a rule by id.
func (k *KB) Rule(id string) (*Rule, bool) {
	r, ok := k.byID[id]
	return r, ok
}

// Load reads every *.yaml under dir of fsys.
func Load(fsys fs.FS, dir string) (*KB, error) {
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	k := &KB{byID: map[string]*Rule{}}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		rs, err := Parse(b, e.Name())
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if _, dup := k.byID[r.ID]; dup {
				return nil, fmt.Errorf("rule %s defined twice", r.ID)
			}
			k.Rules = append(k.Rules, r)
			k.byID[r.ID] = &k.Rules[len(k.Rules)-1]
		}
	}
	// Re-index after append reallocations.
	for i := range k.Rules {
		k.byID[k.Rules[i].ID] = &k.Rules[i]
	}
	if len(k.Rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s", dir)
	}
	return k, nil
}

// Parse strictly decodes and validates one rule file.
func Parse(b []byte, name string) ([]Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var rs []Rule
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	for i := range rs {
		rs[i].File = name
		if err := rs[i].Validate(); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

var (
	defOnce sync.Once
	defKB   *KB
	defErr  error
)

// Default returns the embedded knowledge base (loaded once).
func Default() (*KB, error) {
	defOnce.Do(func() { defKB, defErr = Load(rules.FS, "kb") })
	return defKB, defErr
}

// MustDefault panics if the embedded rules are invalid (caught by tests).
func MustDefault() *KB {
	k, err := Default()
	if err != nil {
		panic(err)
	}
	return k
}

// sortRules is used by tests for deterministic output.
func sortRules(rs []Rule) { sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID }) }
