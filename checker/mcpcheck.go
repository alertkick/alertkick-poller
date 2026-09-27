package checker

// MCP server check for the "mcp" monitor type: handshake, tool-surface
// fingerprints, drift against a human-approved baseline, tool-poisoning lint,
// and (auth mode "oauth") an unauthenticated check of the OAuth discovery
// chain. The check only lists; it never calls a tool.
//
// This file is shared verbatim between alertkick-poller/checker/mcpcheck.go
// and alertkick-api/scheduler/mcpcheck.go (only the package line differs).
// Edit one, copy to the other. Design: fleet/docs/features/mcp-monitor.md.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpMaxTools          = 500
	mcpMaxPages          = 20
	mcpDescExcerptLen    = 300
	mcpFindingExcerptLen = 120
	mcpDescWarnBytes     = 4 * 1024
	mcpDescFailBytes     = 16 * 1024
	// Servers negotiating anything older than this get a warning: 2025-03-26
	// predates structured tool output and the OAuth resource-server split.
	mcpOldestGoodProtocol = "2025-06-18"
)

// MCPCheckConfig is everything one check needs. Headers are already
// decrypted by the caller.
type MCPCheckConfig struct {
	Endpoint      string
	Transport     string // "streamable-http" (default) | "sse"
	AuthMode      string // "none" (default) | "header" | "oauth"
	Headers       map[string]string
	DriftPolicy   string // "alert" (default) | "record"
	ExpectedTools []string
	MaxTools      int
	Baseline      *MCPBaseline
	UserAgent     string
	ClientVersion string
}

// MCPBaseline is the approved tool surface. Only hashes travel to pollers;
// the API keeps description excerpts alongside for the "what changed" view.
type MCPBaseline struct {
	Digest           string                   `json:"digest"`
	InstructionsHash string                   `json:"instructions_hash"`
	Tools            map[string]MCPToolHashes `json:"tools"`
	AcceptedFindings []string                 `json:"accepted_findings,omitempty"`
}

// MCPToolHashes fingerprints one tool. Hash covers everything; Desc, Schema
// and Annotations say which part moved. ReadOnly/Destructive are the
// effective annotation values (spec defaults applied) so a flip can be
// classified without the full annotation object.
type MCPToolHashes struct {
	Hash        string `json:"hash"`
	Desc        string `json:"desc"`
	Schema      string `json:"schema"`
	Annotations string `json:"annotations"`
	ReadOnly    bool   `json:"read_only"`
	Destructive bool   `json:"destructive"`
}

// MCPToolInfo is one listed tool as reported back (description excerpted).
type MCPToolInfo struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	DescBytes   int    `json:"desc_bytes"`
	MCPToolHashes
}

// MCPDrift is one difference from the baseline.
type MCPDrift struct {
	Kind     string `json:"kind"` // tool_added, tool_removed, tool_schema_changed, tool_description_changed, tool_annotations_changed, instructions_changed
	Tool     string `json:"tool,omitempty"`
	Severity string `json:"severity"` // "fail" | "info"
	Detail   string `json:"detail"`
}

// MCPFinding is one poison-lint hit. Key is stable across checks so an
// accepted finding stays accepted.
type MCPFinding struct {
	Key      string `json:"key"`
	Rule     string `json:"rule"`
	Tool     string `json:"tool,omitempty"` // empty = server instructions
	Excerpt  string `json:"excerpt"`
	Accepted bool   `json:"accepted"`
}

// MCPAuthChain is the result of walking the OAuth discovery chain without
// credentials: 401 challenge -> protected-resource metadata (RFC 9728) ->
// authorization-server metadata (RFC 8414 / OIDC).
type MCPAuthChain struct {
	Challenge           bool     `json:"challenge"`
	ResourceMetadataURL string   `json:"resource_metadata_url,omitempty"`
	Resource            string   `json:"resource,omitempty"`
	AuthorizationServer string   `json:"authorization_server,omitempty"`
	Issuer              string   `json:"issuer,omitempty"`
	IssuerMatches       bool     `json:"issuer_matches"`
	PKCES256            bool     `json:"pkce_s256"`
	CIMD                bool     `json:"cimd"`
	DCR                 bool     `json:"dcr"`
	Scopes              []string `json:"scopes,omitempty"`
	Hash                string   `json:"hash,omitempty"`
	Errors              []string `json:"errors,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
}

// MCPReport is the full result of one check.
type MCPReport struct {
	Endpoint         string        `json:"endpoint"`
	Transport        string        `json:"transport"`
	AuthMode         string        `json:"auth_mode"`
	ProtocolVersion  string        `json:"protocol_version,omitempty"`
	ServerName       string        `json:"server_name,omitempty"`
	ServerVersion    string        `json:"server_version,omitempty"`
	Instructions     string        `json:"instructions,omitempty"` // excerpt
	InstructionsHash string        `json:"instructions_hash,omitempty"`
	Capabilities     []string      `json:"capabilities,omitempty"`
	ToolsListed      bool          `json:"tools_listed"`
	ToolCount        int           `json:"tool_count"`
	Truncated        bool          `json:"truncated,omitempty"`
	Tools            []MCPToolInfo `json:"tools,omitempty"`
	Digest           string        `json:"digest,omitempty"`
	InitMs           int64         `json:"init_ms"`
	ListMs           int64         `json:"list_ms"`
	HasBaseline      bool          `json:"has_baseline"`
	BaselineDigest   string        `json:"baseline_digest,omitempty"`
	Drift            []MCPDrift    `json:"drift,omitempty"`
	Findings         []MCPFinding  `json:"findings,omitempty"`
	AuthChain        *MCPAuthChain `json:"auth_chain,omitempty"`
	Warnings         []string      `json:"warnings,omitempty"`
	Fails            []string      `json:"fails,omitempty"`
}

// ToDetails flattens the report into the generic check-result details map.
func (r *MCPReport) ToDetails() map[string]interface{} {
	b, err := json.Marshal(r)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	out := map[string]interface{}{}
	_ = json.Unmarshal(b, &out)
	return out
}

// Summary is a one-line human description for the result body.
func (r *MCPReport) Summary() string {
	if !r.ToolsListed {
		if r.AuthChain != nil {
			return fmt.Sprintf("MCP %s: OAuth discovery chain checked (%d errors)", r.Endpoint, len(r.AuthChain.Errors))
		}
		return fmt.Sprintf("MCP %s: tools not listed", r.Endpoint)
	}
	return fmt.Sprintf("MCP %s: %s %s, protocol %s, %d tools, %d drift, %d findings",
		r.Endpoint, r.ServerName, r.ServerVersion, r.ProtocolVersion, r.ToolCount, len(r.Drift), len(r.Findings))
}

// CheckMCP runs one MCP check. It never returns nil.
func CheckMCP(ctx context.Context, cfg MCPCheckConfig) *MCPReport {
	if cfg.Transport == "" {
		cfg.Transport = "streamable-http"
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = "none"
	}
	if cfg.DriftPolicy == "" {
		cfg.DriftPolicy = "alert"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "AlertKick-MCP-Monitor/1.0 (+https://alertkick.com/docs/monitoring/mcp-server/)"
	}
	r := &MCPReport{Endpoint: cfg.Endpoint, Transport: cfg.Transport, AuthMode: cfg.AuthMode}
	if cfg.Baseline != nil {
		r.HasBaseline = true
		r.BaselineDigest = cfg.Baseline.Digest
	}

	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		r.Fails = append(r.Fails, "endpoint must be an http(s) URL")
		return r
	}

	rec := &mcpRoundTripper{base: http.DefaultTransport, userAgent: cfg.UserAgent}
	if cfg.AuthMode == "header" {
		rec.headers = cfg.Headers
	}
	hc := &http.Client{Transport: rec}

	if cfg.AuthMode == "oauth" {
		// No login in v1: verify the discovery chain a client would walk.
		r.AuthChain = mcpAuthDiscovery(ctx, &http.Client{Transport: &mcpRoundTripper{base: http.DefaultTransport, userAgent: cfg.UserAgent}}, cfg.Endpoint)
		for _, e := range r.AuthChain.Errors {
			r.Fails = append(r.Fails, "oauth: "+e)
		}
		r.Warnings = append(r.Warnings, r.AuthChain.Warnings...)
		r.Warnings = append(r.Warnings, "tool surface not checked: OAuth login is not supported yet, only the discovery chain")
		return r
	}

	var transport mcp.Transport
	if cfg.Transport == "sse" {
		transport = &mcp.SSEClientTransport{Endpoint: cfg.Endpoint, HTTPClient: hc}
	} else {
		transport = &mcp.StreamableClientTransport{
			Endpoint:             cfg.Endpoint,
			HTTPClient:           hc,
			MaxRetries:           -1, // a monitor reports failures, it does not paper over them
			DisableStandaloneSSE: true,
		}
	}
	version := cfg.ClientVersion
	if version == "" {
		version = "1.0"
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "alertkick-monitor", Version: version},
		&mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})

	start := time.Now()
	session, err := client.Connect(ctx, transport, nil)
	r.InitMs = time.Since(start).Milliseconds()
	if err != nil {
		switch rec.lastAuthStatus() {
		case http.StatusUnauthorized, http.StatusForbidden:
			if cfg.AuthMode == "header" {
				r.Fails = append(r.Fails, fmt.Sprintf("server rejected the configured credentials (HTTP %d)", rec.lastAuthStatus()))
			} else {
				r.Fails = append(r.Fails, fmt.Sprintf("server requires authentication (HTTP %d); set auth mode to header or oauth", rec.lastAuthStatus()))
			}
		default:
			r.Fails = append(r.Fails, "connect failed: "+mcpTrimErr(err))
		}
		return r
	}
	defer session.Close()

	instructions := ""
	if init := session.InitializeResult(); init != nil {
		r.ProtocolVersion = init.ProtocolVersion
		if init.ServerInfo != nil {
			r.ServerName = mcpExcerpt(init.ServerInfo.Name, 64)
			r.ServerVersion = mcpExcerpt(init.ServerInfo.Version, 64)
		}
		r.Instructions = mcpExcerpt(init.Instructions, mcpDescExcerptLen)
		if init.Instructions != "" {
			r.InstructionsHash = mcpHashString(init.Instructions)
		}
		r.Capabilities = mcpCapabilityKeys(init.Capabilities)
		if init.ProtocolVersion != "" && init.ProtocolVersion < mcpOldestGoodProtocol {
			r.Warnings = append(r.Warnings, fmt.Sprintf("server negotiated protocol %s; %s or newer is recommended", init.ProtocolVersion, mcpOldestGoodProtocol))
		}
		instructions = init.Instructions
	}

	listStart := time.Now()
	var tools []*mcp.Tool
	cursor := ""
	for page := 0; page < mcpMaxPages; page++ {
		res, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			r.ListMs = time.Since(listStart).Milliseconds()
			r.Fails = append(r.Fails, "tools/list failed: "+mcpTrimErr(err))
			return r
		}
		tools = append(tools, res.Tools...)
		if res.NextCursor == "" || len(tools) >= mcpMaxTools {
			if res.NextCursor != "" {
				r.Truncated = true
			}
			break
		}
		cursor = res.NextCursor
		if page == mcpMaxPages-1 {
			r.Truncated = true
		}
	}
	r.ListMs = time.Since(listStart).Milliseconds()
	if len(tools) > mcpMaxTools {
		tools = tools[:mcpMaxTools]
		r.Truncated = true
	}
	if r.Truncated {
		r.Warnings = append(r.Warnings, fmt.Sprintf("tool list truncated at %d tools / %d pages", mcpMaxTools, mcpMaxPages))
	}
	r.ToolsListed = true
	r.ToolCount = len(tools)

	names := map[string]bool{}
	for _, t := range tools {
		names[t.Name] = true
	}
	current := map[string]MCPToolHashes{}
	for _, t := range tools {
		h := mcpFingerprintTool(t)
		current[t.Name] = h
		r.Tools = append(r.Tools, MCPToolInfo{
			Name:          t.Name,
			Title:         t.Title,
			Description:   mcpExcerpt(t.Description, mcpDescExcerptLen),
			DescBytes:     len(t.Description),
			MCPToolHashes: h,
		})
		r.Findings = append(r.Findings, mcpLint(t.Name, t.Title+"\n"+t.Description, names)...)
		if n := len(t.Description); n > mcpDescFailBytes {
			r.Findings = append(r.Findings, mcpNewFinding("oversized", t.Name, fmt.Sprintf("description is %d bytes", n)))
		} else if n > mcpDescWarnBytes {
			r.Warnings = append(r.Warnings, fmt.Sprintf("tool %s has a %d byte description", t.Name, n))
		}
	}
	r.Findings = append(r.Findings, mcpLint("", instructions, names)...)
	sort.Slice(r.Tools, func(i, j int) bool { return r.Tools[i].Name < r.Tools[j].Name })
	r.Digest = mcpSurfaceDigest(current, r.InstructionsHash)

	if cfg.Baseline != nil {
		r.Drift = mcpDiff(cfg.Baseline, current, r.InstructionsHash, cfg.DriftPolicy)
	}

	accepted := map[string]bool{}
	if cfg.Baseline != nil {
		for _, k := range cfg.Baseline.AcceptedFindings {
			accepted[k] = true
		}
	}
	var openFindings []string
	for i := range r.Findings {
		if accepted[r.Findings[i].Key] {
			r.Findings[i].Accepted = true
			continue
		}
		label := mcpShort(r.Findings[i].Tool)
		if label == "" {
			label = "instructions"
		}
		openFindings = append(openFindings, label+" ("+r.Findings[i].Rule+")")
	}

	// Assertions fail regardless of drift policy.
	for _, want := range cfg.ExpectedTools {
		if want != "" && !names[want] {
			r.Fails = append(r.Fails, "expected tool missing: "+mcpShort(want))
		}
	}
	if cfg.MaxTools > 0 && r.ToolCount > cfg.MaxTools {
		r.Fails = append(r.Fails, fmt.Sprintf("%d tools listed, more than the allowed %d", r.ToolCount, cfg.MaxTools))
	}
	if cfg.DriftPolicy != "record" {
		var failDrift []string
		for _, d := range r.Drift {
			if d.Severity == "fail" {
				failDrift = append(failDrift, d.Detail)
			}
		}
		if len(failDrift) > 0 {
			r.Fails = append(r.Fails, fmt.Sprintf("%d change(s) since the approved baseline: %s", len(failDrift), strings.Join(mcpCap(failDrift, 5), "; ")))
		}
		if len(openFindings) > 0 {
			r.Fails = append(r.Fails, fmt.Sprintf("%d suspicious pattern(s) in tool text: %s", len(openFindings), strings.Join(mcpCap(openFindings, 5), "; ")))
		}
	}
	return r
}

// --- fingerprints -----------------------------------------------------------

func mcpFingerprintTool(t *mcp.Tool) MCPToolHashes {
	readOnly := t.Annotations != nil && t.Annotations.ReadOnlyHint
	destructive := !readOnly && (t.Annotations == nil || t.Annotations.DestructiveHint == nil || *t.Annotations.DestructiveHint)
	return MCPToolHashes{
		Hash: mcpCanonicalHash(map[string]interface{}{
			"name": t.Name, "title": t.Title, "description": t.Description,
			"inputSchema": t.InputSchema, "outputSchema": t.OutputSchema, "annotations": t.Annotations,
		}),
		Desc:        mcpHashString(t.Title + "\x00" + t.Description),
		Schema:      mcpCanonicalHash(map[string]interface{}{"inputSchema": t.InputSchema, "outputSchema": t.OutputSchema}),
		Annotations: mcpCanonicalHash(t.Annotations),
		ReadOnly:    readOnly,
		Destructive: destructive,
	}
}

// mcpCanonicalHash hashes JSON with sorted keys: marshal, decode into
// generic values (maps), marshal again (encoding/json sorts map keys).
func mcpCanonicalHash(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	var generic interface{}
	if err := json.Unmarshal(b, &generic); err != nil {
		return ""
	}
	b, _ = json.Marshal(generic)
	return mcpHashBytes(b)
}

func mcpHashString(s string) string { return mcpHashBytes([]byte(s)) }

func mcpHashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mcpSurfaceDigest(tools map[string]MCPToolHashes, instructionsHash string) string {
	names := make([]string, 0, len(tools))
	for n := range tools {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		sb.WriteString(n)
		sb.WriteByte('=')
		sb.WriteString(tools[n].Hash)
		sb.WriteByte('\n')
	}
	sb.WriteString("instructions=")
	sb.WriteString(instructionsHash)
	return mcpHashString(sb.String())
}

// --- drift ------------------------------------------------------------------

func mcpDiff(base *MCPBaseline, current map[string]MCPToolHashes, instructionsHash, policy string) []MCPDrift {
	var out []MCPDrift
	sev := func(s string) string {
		if policy == "record" {
			return "info"
		}
		return s
	}
	for _, name := range mcpSortedKeys(base.Tools) {
		if _, ok := current[name]; !ok {
			out = append(out, MCPDrift{Kind: "tool_removed", Tool: name, Severity: sev("fail"), Detail: mcpShort(name) + " removed"})
		}
	}
	for _, name := range mcpSortedKeys(current) {
		now := current[name]
		was, ok := base.Tools[name]
		if !ok {
			out = append(out, MCPDrift{Kind: "tool_added", Tool: name, Severity: sev("fail"), Detail: mcpShort(name) + " added"})
			continue
		}
		if was.Hash == now.Hash {
			continue
		}
		label := mcpShort(name)
		if was.Schema != now.Schema {
			out = append(out, MCPDrift{Kind: "tool_schema_changed", Tool: name, Severity: sev("fail"), Detail: label + " (input/output schema)"})
		}
		if was.Desc != now.Desc {
			out = append(out, MCPDrift{Kind: "tool_description_changed", Tool: name, Severity: sev("fail"), Detail: label + " (description)"})
		}
		if was.Annotations != now.Annotations {
			s, detail := "info", label+" (annotations)"
			if was.ReadOnly && !now.ReadOnly {
				s, detail = "fail", label+" (no longer read-only)"
			} else if !was.Destructive && now.Destructive {
				s, detail = "fail", label+" (now destructive)"
			}
			out = append(out, MCPDrift{Kind: "tool_annotations_changed", Tool: name, Severity: sev(s), Detail: detail})
		}
	}
	if base.InstructionsHash != instructionsHash {
		out = append(out, MCPDrift{Kind: "instructions_changed", Severity: sev("fail"), Detail: "server instructions changed"})
	}
	return out
}

func mcpSortedKeys(m map[string]MCPToolHashes) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- poison lint ------------------------------------------------------------

var (
	mcpInstructionMarkerRe = regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|secret)\s*>|ignore (all |any )?(previous|prior|above) (instructions|prompts|messages)|do not (tell|mention|inform|reveal|show)[^.\n]{0,40}\buser|before (using|calling) this tool,? (you must |always |first )?(read|send|include|pass|fetch)`)
	mcpSensitivePathRe     = regexp.MustCompile(`(?i)~/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|(^|[\s/'"])\.env\b|\bmcp\.json\b|\.cursor/|\.claude/|/etc/(passwd|shadow)|\.npmrc|\.git-credentials|\.kube/config`)
	mcpCrossToolRe         = regexp.MustCompile("(?i)when (calling|using|invoking) (the )?[`'\"]?([a-z0-9][a-z0-9_.\\-]{1,63})[`'\"]? tool")
	mcpBase64BlobRe        = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)
	mcpHexBlobRe           = regexp.MustCompile(`\b[0-9a-fA-F]{128,}\b`)
)

// mcpHiddenRune reports zero-width, bidi-control, word-joiner/invisible
// operator, BOM, and Unicode tag characters: text a model reads but a human
// reviewing the tool list does not see.
func mcpHiddenRune(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064,
		r >= 0x2066 && r <= 0x2069, r == 0xFEFF, r >= 0xE0000 && r <= 0xE007F:
		return true
	}
	return false
}

// mcpLint scans one text (a tool's title+description, or the server
// instructions when tool is empty). names is this server's tool set, used
// to spot steering toward tools the server does not own.
func mcpLint(tool, text string, names map[string]bool) []MCPFinding {
	if text == "" {
		return nil
	}
	var out []MCPFinding
	var hidden []string
	for _, r := range text {
		if mcpHiddenRune(r) {
			hidden = append(hidden, fmt.Sprintf("U+%04X", r))
		}
	}
	if len(hidden) > 0 {
		out = append(out, mcpNewFinding("hidden_unicode", tool, fmt.Sprintf("%d hidden character(s): %s", len(hidden), strings.Join(mcpCap(mcpUniq(hidden), 6), " "))))
	}
	if loc := mcpInstructionMarkerRe.FindStringIndex(text); loc != nil {
		out = append(out, mcpNewFinding("instruction_marker", tool, mcpAround(text, loc)))
	}
	if loc := mcpSensitivePathRe.FindStringIndex(text); loc != nil {
		out = append(out, mcpNewFinding("sensitive_path", tool, mcpAround(text, loc)))
	}
	for _, m := range mcpCrossToolRe.FindAllStringSubmatchIndex(text, -1) {
		name := strings.ToLower(text[m[6]:m[7]])
		if names != nil && !names[name] && !names[text[m[6]:m[7]]] && name != "this" && name != "that" {
			out = append(out, mcpNewFinding("cross_tool", tool, mcpAround(text, []int{m[0], m[1]})))
			break
		}
	}
	if loc := mcpBase64BlobRe.FindStringIndex(text); loc != nil {
		out = append(out, mcpNewFinding("encoded_blob", tool, fmt.Sprintf("%d char base64-like run", loc[1]-loc[0])))
	} else if loc := mcpHexBlobRe.FindStringIndex(text); loc != nil {
		out = append(out, mcpNewFinding("encoded_blob", tool, fmt.Sprintf("%d char hex run", loc[1]-loc[0])))
	}
	return out
}

func mcpNewFinding(rule, tool, excerpt string) MCPFinding {
	excerpt = mcpExcerpt(excerpt, mcpFindingExcerptLen)
	return MCPFinding{
		Key:     rule + ":" + tool + ":" + mcpHashString(excerpt)[:12],
		Rule:    rule,
		Tool:    tool,
		Excerpt: excerpt,
	}
}

// mcpAround returns the match with a little context, hidden runes made
// visible so the excerpt is safe to render and to read.
func mcpAround(text string, loc []int) string {
	start, end := loc[0]-40, loc[1]+40
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	for start > 0 && !utf8.RuneStart(text[start]) {
		start--
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	return text[start:end]
}

// mcpExcerpt trims to n bytes on a rune boundary and replaces hidden runes
// and newlines with visible markers.
func mcpExcerpt(s string, n int) string {
	var sb strings.Builder
	for _, r := range s {
		if sb.Len() >= n {
			sb.WriteString("...")
			break
		}
		switch {
		case mcpHiddenRune(r):
			fmt.Fprintf(&sb, "[U+%04X]", r)
		case r == '\n' || r == '\r' || r == '\t':
			sb.WriteByte(' ')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// mcpShort bounds a server-controlled name before it lands in an error
// message: alert text is read by people and by our own triage agent.
func mcpShort(name string) string { return mcpExcerpt(name, 64) }

func mcpUniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func mcpCap(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(append([]string{}, in[:n]...), fmt.Sprintf("and %d more", len(in)-n))
}

func mcpCapabilityKeys(c *mcp.ServerCapabilities) []string {
	if c == nil {
		return nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	m := map[string]interface{}{}
	_ = json.Unmarshal(b, &m)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mcpTrimErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// --- HTTP plumbing ----------------------------------------------------------

// mcpRoundTripper adds the monitor's User-Agent and configured headers, and
// remembers the last 401/403 so an auth failure can be reported plainly
// instead of as an SDK transport error.
type mcpRoundTripper struct {
	base      http.RoundTripper
	userAgent string
	headers   map[string]string

	mu         sync.Mutex
	authStatus int
}

func (t *mcpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.userAgent)
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	resp, err := t.base.RoundTrip(req)
	if err == nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		t.mu.Lock()
		t.authStatus = resp.StatusCode
		t.mu.Unlock()
	}
	return resp, err
}

func (t *mcpRoundTripper) lastAuthStatus() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.authStatus
}

// --- OAuth discovery --------------------------------------------------------

var mcpResourceMetadataRe = regexp.MustCompile(`resource_metadata="([^"]+)"`)

func mcpAuthDiscovery(ctx context.Context, hc *http.Client, endpoint string) *MCPAuthChain {
	c := &MCPAuthChain{}
	fail := func(format string, a ...interface{}) *MCPAuthChain {
		c.Errors = append(c.Errors, fmt.Sprintf(format, a...))
		return c
	}
	u, _ := url.Parse(endpoint)
	origin := u.Scheme + "://" + u.Host

	// 1. An unauthenticated request must be challenged.
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return fail("bad endpoint: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return fail("endpoint unreachable: %s", mcpTrimErr(err))
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return fail("expected HTTP 401 without credentials, got %d", resp.StatusCode)
	}
	c.Challenge = true

	// 2. Protected-resource metadata: from the challenge, else well-known.
	candidates := []string{}
	if m := mcpResourceMetadataRe.FindStringSubmatch(resp.Header.Get("WWW-Authenticate")); m != nil {
		candidates = append(candidates, m[1])
	} else {
		c.Warnings = append(c.Warnings, "401 has no resource_metadata in WWW-Authenticate; fell back to well-known lookup")
		if p := strings.TrimSuffix(u.Path, "/"); p != "" {
			candidates = append(candidates, origin+"/.well-known/oauth-protected-resource"+p)
		}
		candidates = append(candidates, origin+"/.well-known/oauth-protected-resource")
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	var prmErr error
	for _, cand := range candidates {
		if prmErr = mcpGetJSON(ctx, hc, cand, &prm); prmErr == nil {
			c.ResourceMetadataURL = cand
			break
		}
	}
	if c.ResourceMetadataURL == "" {
		return fail("protected-resource metadata not found: %v", prmErr)
	}
	c.Resource = prm.Resource
	c.Scopes = prm.ScopesSupported
	if len(prm.AuthorizationServers) == 0 {
		return fail("protected-resource metadata lists no authorization_servers")
	}
	c.AuthorizationServer = prm.AuthorizationServers[0]

	// 3. Authorization-server metadata (RFC 8414, then OIDC).
	as, err := url.Parse(c.AuthorizationServer)
	if err != nil || as.Host == "" {
		return fail("authorization server %q is not a URL", c.AuthorizationServer)
	}
	asOrigin := as.Scheme + "://" + as.Host
	asPath := strings.TrimSuffix(as.Path, "/")
	var meta struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		RegistrationEndpoint              string   `json:"registration_endpoint"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
		ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported"`
	}
	var metaErr error
	found := false
	for _, cand := range []string{
		asOrigin + "/.well-known/oauth-authorization-server" + asPath,
		strings.TrimSuffix(c.AuthorizationServer, "/") + "/.well-known/openid-configuration",
	} {
		if metaErr = mcpGetJSON(ctx, hc, cand, &meta); metaErr == nil {
			found = true
			break
		}
	}
	if !found {
		return fail("authorization-server metadata not found: %v", metaErr)
	}
	c.Issuer = meta.Issuer
	c.IssuerMatches = strings.TrimSuffix(meta.Issuer, "/") == strings.TrimSuffix(c.AuthorizationServer, "/")
	c.CIMD = meta.ClientIDMetadataDocumentSupported
	c.DCR = meta.RegistrationEndpoint != ""
	for _, m := range meta.CodeChallengeMethodsSupported {
		if m == "S256" {
			c.PKCES256 = true
		}
	}
	if !c.IssuerMatches {
		c.Errors = append(c.Errors, fmt.Sprintf("issuer %q does not match authorization server %q (RFC 9207 mix-up defence)", meta.Issuer, c.AuthorizationServer))
	}
	if !c.PKCES256 {
		c.Errors = append(c.Errors, "PKCE S256 not advertised in code_challenge_methods_supported")
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		c.Errors = append(c.Errors, "authorization or token endpoint missing")
	}
	if !c.CIMD {
		if c.DCR {
			c.Warnings = append(c.Warnings, "relies on dynamic client registration, deprecated in the 2026-07-28 spec; advertise client ID metadata documents")
		} else {
			c.Errors = append(c.Errors, "no client registration path: neither client ID metadata documents nor dynamic registration advertised")
		}
	}
	c.Hash = mcpCanonicalHash(map[string]interface{}{
		"resource": c.Resource, "as": c.AuthorizationServer, "issuer": meta.Issuer,
		"authz": meta.AuthorizationEndpoint, "token": meta.TokenEndpoint, "reg": meta.RegistrationEndpoint,
		"cimd": c.CIMD, "s256": c.PKCES256,
	})
	return c
}

func mcpGetJSON(ctx context.Context, hc *http.Client, target string, v interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return errors.New(mcpTrimErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", target, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(v); err != nil {
		return fmt.Errorf("%s: invalid JSON: %v", target, err)
	}
	return nil
}
