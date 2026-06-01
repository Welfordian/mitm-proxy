package threats

import (
	"net/http"
	"regexp"
	"strings"
)

const redactionVersion = "redaction-v1"

var (
	jwtRE        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	apiKeyRE     = regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|pwd)["'\s:=]+[A-Za-z0-9._~+/=-]{8,}`)
	emailRE      = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	creditCardRE = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
)

func RedactHeaders(headers http.Header) http.Header {
	out, _ := RedactHeadersWithReport(headers)
	return out
}

func RedactHeadersWithReport(headers http.Header) (http.Header, []string) {
	out := make(http.Header, len(headers))
	var redacted []string
	for k, vals := range headers {
		if isSensitiveHeader(k) {
			out[k] = []string{"[REDACTED]"}
			redacted = append(redacted, http.CanonicalHeaderKey(k))
			continue
		}
		out[k] = append([]string(nil), vals...)
	}
	return out, redacted
}

func RedactBody(body []byte) []byte {
	out, _ := RedactBodyWithReport(body)
	return out
}

func RedactBodyWithReport(body []byte) ([]byte, []string) {
	redacted := append([]byte(nil), body...)
	var report []string
	apply := func(name string, re *regexp.Regexp, replacement []byte) {
		if re.Match(redacted) {
			report = append(report, name)
			redacted = re.ReplaceAll(redacted, replacement)
		}
	}
	apply("jwt", jwtRE, []byte("[REDACTED_JWT]"))
	apply("api-key-or-secret", apiKeyRE, []byte("$1=[REDACTED]"))
	apply("email", emailRE, []byte("[REDACTED_EMAIL]"))
	apply("payment-card", creditCardRE, []byte("[REDACTED_CARD]"))
	return redacted, report
}

func isSensitiveHeader(header string) bool {
	switch strings.ToLower(http.CanonicalHeaderKey(header)) {
	case "authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization":
		return true
	default:
		return false
	}
}
