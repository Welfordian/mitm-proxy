package threats

import (
	"bytes"
	"math"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	cfgpkg "mitm-proxy/internal/config"
)

var (
	credentialFieldRE  = regexp.MustCompile(`(?i)(password|passwd|pwd|login|username|email|token|api[_-]?key|secret)`)
	obfuscatedJSRE     = regexp.MustCompile(`(?i)(eval\s*\(|atob\s*\(|fromCharCode|unescape\s*\(|\\x[0-9a-f]{2}|[A-Za-z0-9+/]{80,}={0,2})`)
	redirectRE         = regexp.MustCompile(`(?i)(window\.location|location\.href|http-equiv=["']refresh|<meta[^>]+refresh)`)
	cookieReadRE       = regexp.MustCompile(`(?i)document\.cookie`)
	storageReadRE      = regexp.MustCompile(`(?i)(localStorage|sessionStorage)\s*[\[.]`)
	networkSinkRE      = regexp.MustCompile(`(?i)(fetch\s*\(|XMLHttpRequest|navigator\.sendBeacon|WebSocket\s*\()`)
	endpointRE         = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
	dynamicScriptRE    = regexp.MustCompile(`(?i)(createElement\s*\(\s*["']script|appendChild\s*\(|import\s*\()`)
	documentWriteRE    = regexp.MustCompile(`(?i)document\.write\s*\(`)
	commandInjectionRE = regexp.MustCompile(`(?i)(;\s*(cat|curl|wget|bash|sh|powershell|cmd|nc|python)\b|\$\(|\|\s*(sh|bash|cmd)|` + "`" + `[^` + "`" + `]+` + "`" + `)`)
	ssrfRE             = regexp.MustCompile(`(?i)(url=|uri=|target=|dest=|redirect=|callback=|webhook=).*(127\.0\.0\.1|localhost|169\.254\.169\.254|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)`)
	traversalRE        = regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)`)
	sqlRE              = regexp.MustCompile(`(?i)(\bunion\s+select\b|\bor\s+1=1\b|\bsleep\s*\(|benchmark\s*\(|information_schema|drop\s+table)`)
	xssRE              = regexp.MustCompile(`(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|<img[^>]+src=)`)
	templateRE         = regexp.MustCompile(`(?i)(\{\{.*\}\}|\$\{.*\}|<%.*%>)`)
	deserializeRE      = regexp.MustCompile(`(?i)(rO0AB|__VIEWSTATE|ysoserial|java\.util\.PriorityQueue|O:\d+:"[^"]+")`)
	encodedPayloadRE   = regexp.MustCompile(`(?i)(%[0-9a-f]{2}){8,}|[A-Za-z0-9+/]{120,}={0,2}`)
	cardLikeRE         = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
)

func BuildEvidence(input ScanInput, cfg cfgpkg.ThreatScannerConfig, local HeuristicResult) EvidenceBundle {
	body := input.BodySample
	bodyLimit := cfg.MaxAIBodyBytes
	if bodyLimit <= 0 {
		bodyLimit = int64(len(body))
	}
	truncated := int64(len(body)) > bodyLimit
	if truncated {
		body = body[:bodyLimit]
	}

	report := RedactionReport{
		Enabled:           cfg.RedactBeforeAI,
		OriginalBodyBytes: len(input.BodySample),
		BodySampleLimit:   bodyLimit,
		BodyTruncated:     truncated,
		RedactionVersion:  redactionVersion,
	}

	headers := http.Header(input.Headers)
	if cfg.RedactBeforeAI {
		var redacted []string
		headers, redacted = RedactHeadersWithReport(headers)
		body, report.BodyRedactions = RedactBodyWithReport(body)
		report.HeadersRedacted = redacted
	}
	report.RedactedBodyBytes = len(body)

	meta := map[string]any{
		"method":       input.Method,
		"url":          input.URL,
		"host":         input.Host,
		"headers":      map[string][]string(headers),
		"content_type": input.ContentType,
		"body_hash":    input.BodyHash,
		"remote_ip":    input.RemoteIP,
	}
	if input.Target == ScanResponse {
		meta["status_code"] = input.StatusCode
	}

	extracted := ExtractFeatures(input, cfg)
	q := QuarantineRecommendation(input, extracted)
	if q != nil {
		q.BodyHash = input.BodyHash
		q.ContentType = input.ContentType
	}

	evidence := EvidenceBundle{
		BodySample:   string(body),
		Extracted:    extracted,
		LocalSignals: local.Signals,
		Redaction:    report,
		Quarantine:   q,
	}
	if input.Target == ScanRequest {
		evidence.RequestMetadata = meta
	} else {
		evidence.ResponseMetadata = meta
	}
	return evidence
}

func ExtractFeatures(input ScanInput, cfg cfgpkg.ThreatScannerConfig) ExtractedFeatures {
	urlFeatures := extractURLFeatures(input)
	htmlFeatures := extractHTMLFeatures(input, urlFeatures)
	jsFeatures := extractJSFeatures(input, urlFeatures)
	payloadFeatures := extractPayloadFeatures(input)
	downloadFeatures := extractDownloadFeatures(input)
	networkFeatures := extractNetworkFeatures(input, urlFeatures)

	return ExtractedFeatures{
		URL:              urlFeatures,
		HTML:             htmlFeatures,
		JavaScript:       jsFeatures,
		Payload:          payloadFeatures,
		Download:         downloadFeatures,
		Network:          networkFeatures,
		ThreatIntelHits:  threatIntelHits(input, cfg),
		TrustedDomainHit: domainMatchesAny(urlFeatures.Hostname, cfg.TrustedDomains) || domainMatchesAny(urlFeatures.Hostname, cfg.AllowlistDomains),
	}
}

func extractURLFeatures(input ScanInput) URLFeatures {
	raw := input.URL
	parsed, _ := url.Parse(raw)
	host := input.Host
	if host == "" && parsed != nil {
		host = parsed.Host
	}
	hostname := stripHostPort(host)
	if parsed != nil && parsed.Hostname() != "" {
		hostname = parsed.Hostname()
	}
	ip := net.ParseIP(strings.Trim(hostname, "[]"))
	path := ""
	query := ""
	scheme := ""
	if parsed != nil {
		path = parsed.EscapedPath()
		query = parsed.RawQuery
		scheme = parsed.Scheme
	}
	combined := strings.ToLower(raw + " " + query + " " + path)
	return URLFeatures{
		Host:                    host,
		Hostname:                strings.ToLower(strings.TrimSuffix(hostname, ".")),
		Scheme:                  scheme,
		Path:                    path,
		Query:                   query,
		Extension:               strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")),
		IsIPAddress:             ip != nil,
		IsPrivateAddress:        ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()),
		IsLoopback:              ip != nil && ip.IsLoopback() || strings.EqualFold(hostname, "localhost"),
		SuspiciousTLD:           hasSuspiciousTLD(hostname),
		CredentialThemed:        containsAny(combined, "login", "signin", "sign-in", "verify", "password", "reset", "account", "oauth"),
		Entropy:                 entropy(strings.ReplaceAll(hostname+path, ".", "")),
		Punycode:                strings.Contains(strings.ToLower(hostname), "xn--"),
		HomoglyphLike:           containsNonASCII(hostname),
		SuspiciousQueryKeys:     suspiciousQueryKeys(parsed),
		RedirectTargets:         redirectTargets(parsed),
		ExternalRedirectTargets: externalRedirectTargets(parsed, hostname),
	}
}

func extractHTMLFeatures(input ScanInput, u URLFeatures) HTMLFeatures {
	body := input.BodySample
	lower := bytes.ToLower(body)
	features := HTMLFeatures{
		HasTestPhishingMarker:   bytes.Contains(lower, []byte("test_marker_threat_scanner_phishing")),
		HasClientSideRedirect:   redirectRE.Match(body),
		HasCookieExfiltration:   cookieReadRE.Match(body) && networkSinkRE.Match(body),
		HasStorageExfiltration:  storageReadRE.Match(body) && networkSinkRE.Match(body),
		HasObfuscatedJavaScript: obfuscatedJSRE.Match(body),
		HasSuspiciousScriptSink: networkSinkRE.Match(body),
	}

	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	var currentForm *FormFeature
	var visibleText strings.Builder
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		token := tokenizer.Token()
		switch tt {
		case html.TextToken:
			visibleText.WriteString(token.Data)
			visibleText.WriteByte(' ')
		case html.StartTagToken, html.SelfClosingTagToken:
			tag := strings.ToLower(token.Data)
			attrs := attrsToMap(token.Attr)
			switch tag {
			case "form":
				form := FormFeature{Action: attrs["action"], Method: strings.ToUpper(attrs["method"])}
				form.External = isExternalURL(form.Action, u.Hostname)
				features.Forms = append(features.Forms, form)
				currentForm = &features.Forms[len(features.Forms)-1]
			case "input":
				name := strings.ToLower(attrs["name"] + " " + attrs["id"] + " " + attrs["placeholder"] + " " + attrs["autocomplete"])
				typ := strings.ToLower(attrs["type"])
				if typ == "password" {
					features.PasswordFields++
					if currentForm != nil {
						currentForm.PasswordFields++
					}
				}
				if typ == "hidden" {
					features.HiddenFields++
					if currentForm != nil {
						currentForm.HiddenFields++
					}
				}
				if credentialFieldRE.MatchString(name) && currentForm != nil {
					currentForm.SensitiveFields = appendUnique(currentForm.SensitiveFields, strings.TrimSpace(name))
				}
			case "iframe":
				features.IFrames = appendExternal(features.IFrames, attrs["src"], u.Hostname)
			case "script":
				features.ExternalScripts = appendExternal(features.ExternalScripts, attrs["src"], u.Hostname)
			case "meta":
				if strings.EqualFold(attrs["http-equiv"], "refresh") {
					features.MetaRefreshTargets = append(features.MetaRefreshTargets, attrs["content"])
				}
			case "a":
				href := attrs["href"]
				if isSuspiciousLink(href, u.Hostname) {
					features.SuspiciousLinks = append(features.SuspiciousLinks, href)
				}
			}
		case html.EndTagToken:
			if strings.EqualFold(token.Data, "form") {
				currentForm = nil
			}
		}
	}

	for _, form := range features.Forms {
		if form.External {
			features.ExternalFormActions = append(features.ExternalFormActions, form.Action)
		}
	}
	features.HasCredentialCollection = features.PasswordFields > 0 || credentialFieldRE.Match(body)
	features.BrandTerms = brandTerms(visibleText.String() + " " + string(body))
	features.HasBrandImpersonation = len(features.BrandTerms) > 0 && features.HasCredentialCollection && !trustedBrandHost(u.Hostname, features.BrandTerms)
	sort.Strings(features.BrandTerms)
	return features
}

func extractJSFeatures(input ScanInput, u URLFeatures) JSFeatures {
	body := input.BodySample
	endpoints := endpointRE.FindAllString(string(body), -1)
	features := JSFeatures{
		ReadsCookies:       cookieReadRE.Match(body),
		ReadsStorage:       storageReadRE.Match(body),
		UsesEval:           regexp.MustCompile(`(?i)(eval\s*\(|Function\s*\()`).Match(body),
		UsesDynamicScript:  dynamicScriptRE.Match(body),
		UsesDocumentWrite:  documentWriteRE.Match(body),
		ExternalEndpoints:  externalEndpoints(endpoints, u.Hostname),
		NetworkSinks:       networkSinks(body),
		ObfuscationMarkers: obfuscationMarkers(body),
	}
	for _, endpoint := range features.ExternalEndpoints {
		if containsAny(strings.ToLower(endpoint), "beacon", "collect", "exfil", "gate", "panel", "api/checkin") {
			features.BeaconLikeEndpoints = append(features.BeaconLikeEndpoints, endpoint)
		}
	}
	return features
}

func extractPayloadFeatures(input ScanInput) PayloadFeatures {
	text := input.URL + "\n" + string(input.BodySample)
	features := PayloadFeatures{
		CommandInjection:     commandInjectionRE.MatchString(text),
		SSRF:                 ssrfRE.MatchString(text),
		PathTraversal:        traversalRE.MatchString(text),
		SQLInjection:         sqlRE.MatchString(text),
		XSS:                  xssRE.MatchString(text),
		TemplateInjection:    templateRE.MatchString(text),
		DeserializationProbe: deserializeRE.MatchString(text),
		EncodedPayload:       encodedPayloadRE.MatchString(text),
	}
	addPayloadMatch := func(name string, matched bool) {
		if matched {
			features.MatchedPatterns = append(features.MatchedPatterns, name)
		}
	}
	addPayloadMatch("command-injection", features.CommandInjection)
	addPayloadMatch("ssrf", features.SSRF)
	addPayloadMatch("path-traversal", features.PathTraversal)
	addPayloadMatch("sql-injection", features.SQLInjection)
	addPayloadMatch("xss", features.XSS)
	addPayloadMatch("template-injection", features.TemplateInjection)
	addPayloadMatch("deserialization", features.DeserializationProbe)
	addPayloadMatch("encoded-payload", features.EncodedPayload)
	return features
}

func extractDownloadFeatures(input ScanInput) DownloadFeatures {
	headers := http.Header(input.Headers)
	contentDisposition := headers.Get("Content-Disposition")
	filename := fileNameFromDisposition(contentDisposition)
	if filename == "" {
		if parsed, err := url.Parse(input.URL); err == nil {
			filename = filepath.Base(parsed.Path)
		}
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))
	ct := strings.ToLower(input.ContentType)
	features := DownloadFeatures{
		FileName:           filename,
		Extension:          ext,
		ContentDisposition: contentDisposition,
	}
	features.SuspiciousExecutable = containsString([]string{"exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "msi", "hta", "jar"}, ext)
	features.SuspiciousArchive = containsString([]string{"zip", "rar", "7z", "iso", "img", "gz", "tar"}, ext)
	features.SuspiciousDocument = containsString([]string{"docm", "xlsm", "pptm", "rtf", "one"}, ext)
	features.UnknownBinaryDownload = strings.HasPrefix(ct, "application/octet-stream") || ct == "binary/octet-stream"
	features.QuarantineRecommended = input.Target == ScanResponse && (features.SuspiciousExecutable || features.SuspiciousArchive || features.SuspiciousDocument || features.UnknownBinaryDownload)
	return features
}

func extractNetworkFeatures(input ScanInput, u URLFeatures) NetworkFeatures {
	port := ""
	host := input.Host
	if parsed, err := url.Parse(input.URL); err == nil && parsed.Host != "" {
		host = parsed.Host
	}
	if _, p, err := net.SplitHostPort(host); err == nil {
		port = p
	}
	return NetworkFeatures{
		PrivateNetworkTarget: input.Target == ScanRequest && u.IsPrivateAddress,
		LoopbackTarget:       input.Target == ScanRequest && u.IsLoopback,
		IPAddressHost:        u.IsIPAddress,
		NonStandardPort:      port != "" && port != "80" && port != "443",
		C2BeaconLike:         input.Target == ScanResponse && len(extractJSFeatures(input, u).BeaconLikeEndpoints) > 0,
	}
}

func QuarantineRecommendation(input ScanInput, features ExtractedFeatures) *QuarantineMetadata {
	if !features.Download.QuarantineRecommended {
		return nil
	}
	return &QuarantineMetadata{
		Recommended: true,
		Reason:      "Suspicious download type should be quarantined for analyst review.",
		FileName:    features.Download.FileName,
	}
}

func hasSuspiciousTLD(host string) bool {
	for _, tld := range []string{".zip", ".mov", ".country", ".kim", ".gq", ".tk", ".ml", ".cf", ".top", ".xyz", ".quest"} {
		if strings.HasSuffix(strings.ToLower(host), tld) {
			return true
		}
	}
	return false
}

func stripHostPort(host string) string {
	host = strings.TrimSpace(host)
	if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
		host = parsed.Host
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return strings.ToLower(strings.Trim(h, "[]"))
		}
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func domainMatchesAny(host string, patterns []string) bool {
	host = strings.TrimSuffix(strings.ToLower(stripHostPort(host)), ".")
	for _, pattern := range patterns {
		pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			base := strings.TrimPrefix(pattern, "*.")
			if host == base || strings.HasSuffix(host, "."+base) {
				return true
			}
			continue
		}
		if host == pattern || strings.HasSuffix(host, "."+pattern) {
			return true
		}
	}
	return false
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	var e float64
	length := float64(len([]rune(s)))
	for _, count := range counts {
		p := count / length
		e -= p * math.Log2(p)
	}
	return e
}

func containsNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func suspiciousQueryKeys(parsed *url.URL) []string {
	if parsed == nil {
		return nil
	}
	var keys []string
	for key := range parsed.Query() {
		lower := strings.ToLower(key)
		if containsAny(lower, "url", "uri", "redirect", "next", "return", "callback", "token", "password", "session") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func redirectTargets(parsed *url.URL) []string {
	if parsed == nil {
		return nil
	}
	var targets []string
	for key, vals := range parsed.Query() {
		if !containsAny(strings.ToLower(key), "url", "uri", "redirect", "next", "return", "callback") {
			continue
		}
		for _, val := range vals {
			if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
				targets = append(targets, val)
			}
		}
	}
	return targets
}

func externalRedirectTargets(parsed *url.URL, host string) []string {
	var out []string
	for _, target := range redirectTargets(parsed) {
		if isExternalURL(target, host) {
			out = append(out, target)
		}
	}
	return out
}

func attrsToMap(attrs []html.Attribute) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		out[strings.ToLower(attr.Key)] = attr.Val
	}
	return out
}

func isExternalURL(raw, pageHost string) bool {
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	return !domainMatchesAny(parsed.Hostname(), []string{pageHost})
}

func appendExternal(values []string, raw, pageHost string) []string {
	if isExternalURL(raw, pageHost) {
		return append(values, raw)
	}
	return values
}

func isSuspiciousLink(raw, pageHost string) bool {
	if raw == "" {
		return false
	}
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "javascript:") || isExternalURL(raw, pageHost) && containsAny(lower, "login", "verify", "account", "password", "reset")
}

func brandTerms(text string) []string {
	lower := strings.ToLower(text)
	var brands []string
	for _, brand := range []string{"microsoft", "office 365", "outlook", "google", "apple", "facebook", "paypal", "amazon", "github", "docusign"} {
		if strings.Contains(lower, brand) {
			brands = appendUnique(brands, brand)
		}
	}
	return brands
}

func trustedBrandHost(host string, brands []string) bool {
	host = strings.ToLower(host)
	for _, brand := range brands {
		switch brand {
		case "microsoft", "office 365", "outlook":
			if domainMatchesAny(host, []string{"microsoft.com", "live.com", "office.com", "outlook.com", "login.microsoftonline.com"}) {
				return true
			}
		case "google":
			if domainMatchesAny(host, []string{"google.com", "accounts.google.com"}) {
				return true
			}
		case "github":
			if domainMatchesAny(host, []string{"github.com"}) {
				return true
			}
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func externalEndpoints(endpoints []string, pageHost string) []string {
	var out []string
	for _, endpoint := range endpoints {
		if isExternalURL(endpoint, pageHost) {
			out = appendUnique(out, endpoint)
		}
	}
	return out
}

func networkSinks(body []byte) []string {
	var sinks []string
	lower := strings.ToLower(string(body))
	for _, sink := range []string{"fetch(", "xmlhttprequest", "navigator.sendbeacon", "websocket("} {
		if strings.Contains(lower, sink) {
			sinks = append(sinks, sink)
		}
	}
	return sinks
}

func obfuscationMarkers(body []byte) []string {
	var markers []string
	lower := strings.ToLower(string(body))
	for _, marker := range []string{"eval(", "atob(", "fromcharcode", "unescape(", "\\x"} {
		if strings.Contains(lower, marker) {
			markers = append(markers, marker)
		}
	}
	return markers
}

func fileNameFromDisposition(disposition string) string {
	if disposition == "" {
		return ""
	}
	_, params, err := mimeParseMediaType(disposition)
	if err == nil {
		return params["filename"]
	}
	return ""
}

func mimeParseMediaType(value string) (string, map[string]string, error) {
	parts := strings.Split(value, ";")
	params := map[string]string{}
	for _, part := range parts[1:] {
		key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			params[strings.ToLower(key)] = strings.Trim(val, `"`)
		}
	}
	return strings.TrimSpace(parts[0]), params, nil
}

func containsString(list []string, needle string) bool {
	for _, value := range list {
		if value == needle {
			return true
		}
	}
	return false
}

func threatIntelHits(input ScanInput, cfg cfgpkg.ThreatScannerConfig) []string {
	var hits []string
	host := stripHostPort(input.Host)
	if domainMatchesAny(host, cfg.MaliciousDomains) {
		hits = append(hits, "malicious-domain:"+host)
	}
	if input.BodyHash != "" && containsString(cfg.MaliciousFileHashes, input.BodyHash) {
		hits = append(hits, "malicious-hash:"+input.BodyHash)
	}
	return hits
}

func isPrivateAddressTarget(host string) bool {
	ip := net.ParseIP(stripHostPort(host))
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func parsePort(host string) int {
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return 0
	}
	value, _ := strconv.Atoi(port)
	return value
}
