// Package fingerprint detects what sits in front of a website (CDN/WAF),
// which web server answers, and which platform runs behind it, from response
// headers, cookies, error-page bodies, TLS issuer, CNAMEs and IP ranges.
// Signatures are data (rules/fingerprints.yaml). Every detection carries a
// confidence level and the evidence it was derived from; a single weak signal
// is never reported above "low".
package fingerprint

import (
	"bytes"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"domaindoctor/rules"
)

var weights = map[string]float64{"strong": 0.7, "medium": 0.4, "weak": 0.15}

type Signal struct {
	Type   string   `yaml:"type"`
	Name   string   `yaml:"name"`
	Regex  string   `yaml:"regex"`
	Suffix string   `yaml:"suffix"`
	CIDRs  []string `yaml:"cidrs"`
	Weight string   `yaml:"weight"`

	re       *regexp.Regexp
	prefixes []netip.Prefix
}

type Signature struct {
	ID      string   `yaml:"id"`
	Kind    string   `yaml:"kind"` // cdn, server, platform
	Name    string   `yaml:"name"`
	Signals []Signal `yaml:"signals"`
}

// Sample is one HTTP response as seen by an agent.
type Sample struct {
	Source    string              `json:"source"` // human-readable request description
	Status    int                 `json:"status"`
	Headers   map[string][]string `json:"headers"` // lower-case names
	Cookies   []string            `json:"cookies"` // Set-Cookie names
	Body      string              `json:"-"`       // size-limited sample
	TLSIssuer string              `json:"tls_issuer,omitempty"`
}

// Input is everything known about the site.
type Input struct {
	Samples []Sample
	CNAMEs  []string
	IPs     []netip.Addr
}

type Detection struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Confidence float64  `json:"confidence"`
	Level      string   `json:"level"` // high, medium, low
	Evidence   []string `json:"evidence"`
}

// Result groups detections by kind, most confident first.
type Result struct {
	CDN      []Detection `json:"cdn"`
	Server   []Detection `json:"server"`
	Platform []Detection `json:"platform"`
	NoCDN    bool        `json:"no_cdn"` // no CDN reached medium confidence
}

// Primary returns the most confident detection of a kind at medium or above.
func (r *Result) Primary(kind string) *Detection {
	var list []Detection
	switch kind {
	case "cdn":
		list = r.CDN
	case "server":
		list = r.Server
	case "platform":
		list = r.Platform
	}
	if len(list) > 0 && list[0].Level != "low" {
		return &list[0]
	}
	return nil
}

var (
	loadOnce sync.Once
	loaded   []Signature
	loadErr  error
)

// Signatures returns the embedded signatures (parsed once).
func Signatures() ([]Signature, error) {
	loadOnce.Do(func() {
		b, err := rules.FS.ReadFile("fingerprints.yaml")
		if err != nil {
			loadErr = err
			return
		}
		loaded, loadErr = Parse(b)
	})
	return loaded, loadErr
}

// Parse decodes and validates signature data.
func Parse(b []byte) ([]Signature, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var sigs []Signature
	if err := dec.Decode(&sigs); err != nil {
		return nil, fmt.Errorf("fingerprints: %w", err)
	}
	seen := map[string]bool{}
	for i := range sigs {
		s := &sigs[i]
		if s.ID == "" || seen[s.ID] {
			return nil, fmt.Errorf("fingerprints: missing or duplicate id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Kind != "cdn" && s.Kind != "server" && s.Kind != "platform" {
			return nil, fmt.Errorf("fingerprints %s: bad kind %q", s.ID, s.Kind)
		}
		if len(s.Signals) == 0 {
			return nil, fmt.Errorf("fingerprints %s: no signals", s.ID)
		}
		for j := range s.Signals {
			sg := &s.Signals[j]
			if _, ok := weights[sg.Weight]; !ok {
				return nil, fmt.Errorf("fingerprints %s: bad weight %q", s.ID, sg.Weight)
			}
			if sg.Regex != "" {
				re, err := regexp.Compile("(?is)" + sg.Regex)
				if err != nil {
					return nil, fmt.Errorf("fingerprints %s: %w", s.ID, err)
				}
				sg.re = re
			}
			sg.Name = strings.ToLower(sg.Name)
			switch sg.Type {
			case "header", "cookie":
				if sg.Name == "" {
					return nil, fmt.Errorf("fingerprints %s: %s signal needs a name", s.ID, sg.Type)
				}
			case "body", "tls_issuer":
				if sg.re == nil {
					return nil, fmt.Errorf("fingerprints %s: %s signal needs a regex", s.ID, sg.Type)
				}
			case "cname":
				if sg.Suffix == "" {
					return nil, fmt.Errorf("fingerprints %s: cname signal needs a suffix", s.ID)
				}
				sg.Suffix = strings.ToLower(strings.TrimSuffix(sg.Suffix, "."))
			case "ip":
				for _, c := range sg.CIDRs {
					p, err := netip.ParsePrefix(c)
					if err != nil {
						return nil, fmt.Errorf("fingerprints %s: %w", s.ID, err)
					}
					sg.prefixes = append(sg.prefixes, p)
				}
				if len(sg.prefixes) == 0 {
					return nil, fmt.Errorf("fingerprints %s: ip signal needs cidrs", s.ID)
				}
			default:
				return nil, fmt.Errorf("fingerprints %s: unknown signal type %q", s.ID, sg.Type)
			}
		}
	}
	return sigs, nil
}

// Level maps a confidence to a label.
func Level(c float64) string {
	switch {
	case c >= 0.8:
		return "high"
	case c >= 0.5:
		return "medium"
	}
	return "low"
}

// Detect scores every signature against the input.
func Detect(sigs []Signature, in Input) *Result {
	res := &Result{CDN: []Detection{}, Server: []Detection{}, Platform: []Detection{}}
	for _, s := range sigs {
		var ev []string
		miss := 1.0
		onlyWeak := true
		for _, sg := range s.Signals {
			e, ok := match(sg, in)
			if !ok {
				continue
			}
			ev = append(ev, e)
			miss *= 1 - weights[sg.Weight]
			if sg.Weight != "weak" {
				onlyWeak = false
			}
		}
		if len(ev) == 0 {
			continue
		}
		conf := 1 - miss
		if onlyWeak {
			conf = math.Min(conf, 0.45) // weak hints alone never exceed "low"
		}
		conf = math.Round(conf*100) / 100
		d := Detection{ID: s.ID, Kind: s.Kind, Name: s.Name, Confidence: conf, Level: Level(conf), Evidence: ev}
		switch s.Kind {
		case "cdn":
			res.CDN = append(res.CDN, d)
		case "server":
			res.Server = append(res.Server, d)
		case "platform":
			res.Platform = append(res.Platform, d)
		}
	}
	for _, l := range [][]Detection{res.CDN, res.Server, res.Platform} {
		sort.SliceStable(l, func(i, j int) bool { return l[i].Confidence > l[j].Confidence })
	}
	res.NoCDN = res.Primary("cdn") == nil
	return res
}

// match reports the first piece of evidence for a signal across all samples.
func match(sg Signal, in Input) (string, bool) {
	switch sg.Type {
	case "header":
		for _, s := range in.Samples {
			for _, v := range s.Headers[sg.Name] {
				if sg.re == nil || sg.re.MatchString(v) {
					return fmt.Sprintf("header %s: %s (%s)", sg.Name, clip(v, 80), s.Source), true
				}
			}
		}
	case "cookie":
		for _, s := range in.Samples {
			for _, c := range s.Cookies {
				if strings.HasPrefix(strings.ToLower(c), sg.Name) {
					return fmt.Sprintf("cookie %s (%s)", c, s.Source), true
				}
			}
		}
	case "body":
		for _, s := range in.Samples {
			if m := sg.re.FindString(s.Body); m != "" {
				return fmt.Sprintf("page content %q (%s)", clip(m, 60), s.Source), true
			}
		}
	case "tls_issuer":
		for _, s := range in.Samples {
			if s.TLSIssuer != "" && sg.re.MatchString(s.TLSIssuer) {
				return "TLS issuer " + s.TLSIssuer, true
			}
		}
	case "cname":
		for _, c := range in.CNAMEs {
			c = strings.ToLower(strings.TrimSuffix(c, "."))
			if strings.HasSuffix(c, sg.Suffix) {
				return "CNAME → " + c, true
			}
		}
	case "ip":
		for _, ip := range in.IPs {
			for _, p := range sg.prefixes {
				if p.Contains(ip.Unmap()) {
					return fmt.Sprintf("address %s is in %s", ip, p), true
				}
			}
		}
	}
	return "", false
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
