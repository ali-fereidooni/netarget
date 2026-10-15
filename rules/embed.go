// Package rules embeds the data files that drive the Website Load
// troubleshooter: fingerprints.yaml (what is in front of a site) and kb/*.yaml
// (the knowledge base of failure rules). See the http-error-knowledge skill.
package rules

import "embed"

//go:embed fingerprints.yaml kb/*.yaml
var FS embed.FS
