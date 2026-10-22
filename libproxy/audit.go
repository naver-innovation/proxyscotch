package libproxy

// [wasl] 호출 1건당 구조화 Audit 로그 한 줄.
//
// proxyHandler 가 POST(프록시 요청)를 받을 때마다 결과와 상관없이 stdout 에 JSON 한 줄을 쓴다.
// 사용자는 앞단 프록시가 넘기는 X-Forwarded-Email / X-Forwarded-User(oauth2-proxy 가 세운 값)에서 읽는다.
// Authorization · Cookie · 요청 / 응답 본문은 기록하지 않고, URL 의 userinfo 와 민감한 쿼리 값은 가린다.
// 업스트림 텍스트 로그(Proxying / Received response / Completed 등)의 URL 도 같은 규칙으로 가린다(logURL · logErr).
//
// 같은 호출이 변경 호출이면 감사 수집용 줄을 한 줄 더 쓴다(siemLine, 첫 키 siem_audit). 위 Audit 줄은 그대로 두고 따로 쓴다.
//   - 대상 method 가 GET · HEAD · OPTIONS · TRACE 인 조회는 쓰지 않는다. 본문을 읽기 전에 거부돼 method 를 모르는 호출은 쓴다.
//   - action 은 api.<method 소문자>(method 를 모르면 api.call), result 는 success · denied · error 로 맞춘다.
//     프록시 전달에 성공해도 대상이 401 · 403 을 주면 denied, 그 밖의 4xx · 5xx 는 error 다.
//   - target 은 대상 호스트와 앞단 프록시의 요청 ID(hopp_rid) - 경로 · 쿼리는 토큰이 남을 수 있어 쓰지 않는다.
//   - src 는 앞단 프록시가 판정해 넘긴 출발지(hopp_src)다. IP 가 아니면 비운다.

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	auditEnv = os.Getenv("PROXYSCOTCH_AUDIT_ENV")
	auditOut = log.New(os.Stdout, "", 0)
	siemOut  = log.New(os.Stdout, "", 0)

	siemReadMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "TRACE": true}
	siemMethodName  = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,19}$`)
	siemRequestID   = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)
)

type auditRecord struct {
	skip   bool
	start  time.Time
	user   string
	userID string
	rid    string
	src    string
	method string
	target string
	status int
	bytes  int
	result string
}

type auditLine struct {
	Audit     string `json:"audit"`
	Timestamp string `json:"timestamp"`
	Env       string `json:"env"`
	User      string `json:"user"`
	UserID    string `json:"user_id,omitempty"`
	RID       string `json:"rid,omitempty"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Host      string `json:"host"`
	Status    int    `json:"status"`
	LatencyMs int64  `json:"latency_ms"`
	Bytes     int    `json:"bytes"`
	Result    string `json:"result"`
}

// siemLine 은 감사 수집 계약 형식이다. 첫 키가 siem_audit 이어야 수집되므로 키 순서를 struct 로 고정한다(map 은 키를 정렬한다).
type siemLine struct {
	SIEMAudit string `json:"siem_audit"`
	Time      string `json:"time"`
	User      string `json:"user"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Result    string `json:"result"`
	Src       string `json:"src"`
}

func newAuditRecord(r *http.Request, start time.Time) *auditRecord {
	return &auditRecord{
		skip:   r.Method != http.MethodPost || r.URL.Path == "/health" || r.URL.Path == "/metrics",
		start:  start,
		user:   r.Header.Get("X-Forwarded-Email"),
		userID: r.Header.Get("X-Forwarded-User"),
		rid:    r.URL.Query().Get("hopp_rid"),
		src:    siemSource(r.URL.Query().Get("hopp_src")),
		result: "rejected",
	}
}

func (a *auditRecord) emit() {
	if a.skip {
		return
	}
	masked, host := maskAuditURL(a.target)
	line, err := json.Marshal(auditLine{
		Audit:     "hoppscotch",
		Timestamp: a.start.UTC().Format(time.RFC3339Nano),
		Env:       auditEnv,
		User:      a.user,
		UserID:    a.userID,
		RID:       a.rid,
		Method:    strings.ToUpper(a.method),
		URL:       masked,
		Host:      host,
		Status:    a.status,
		LatencyMs: time.Since(a.start).Milliseconds(),
		Bytes:     a.bytes,
		Result:    a.result,
	})
	if err != nil {
		ErrorLogger.Printf("Failed to encode audit line: %v", err)
		return
	}
	auditOut.Println(string(line))

	action, ok := siemAction(a.method)
	if !ok {
		return
	}
	siem, err := json.Marshal(siemLine{
		SIEMAudit: "v1",
		Time:      a.start.UTC().Format(time.RFC3339Nano),
		User:      a.user,
		Action:    action,
		Target:    siemTarget(host, a.rid),
		Result:    siemResult(a.result, a.status),
		Src:       a.src,
	})
	if err != nil {
		ErrorLogger.Printf("Failed to encode siem audit line: %v", err)
		return
	}
	siemOut.Println(string(siem))
}

// siemAction 은 대상 method 를 action 으로 바꾼다. 조회 method 면 false(쓰지 않는다)다.
// method 는 클라이언트가 보낸 값이라 이름 꼴이 아니면 api.other 로 묶는다.
func siemAction(method string) (string, bool) {
	m := strings.ToUpper(strings.TrimSpace(method))
	switch {
	case m == "":
		return "api.call", true
	case siemReadMethods[m]:
		return "", false
	case !siemMethodName.MatchString(m):
		return "api.other", true
	default:
		return "api." + strings.ToLower(m), true
	}
}

// siemResult 는 Audit 줄의 result 와 대상 응답 코드를 success · denied · error 로 맞춘다.
func siemResult(result string, status int) string {
	switch {
	case result == "ok" && status >= 200 && status < 400:
		return "success"
	case result == "ok" && (status == http.StatusUnauthorized || status == http.StatusForbidden):
		return "denied"
	case strings.HasPrefix(result, "denied"):
		return "denied"
	default:
		return "error"
	}
}

// siemTarget 은 대상 호스트와 요청 ID 를 잇는다. 요청 ID 로 Audit 줄(경로 · 응답 코드)을 찾는다.
func siemTarget(host, rid string) string {
	if !siemRequestID.MatchString(rid) {
		rid = ""
	}
	switch {
	case host != "" && rid != "":
		return host + " rid=" + rid
	case rid != "":
		return "rid=" + rid
	default:
		return host
	}
}

// siemSource 는 앞단 프록시가 넘긴 출발지가 IP 일 때만 돌려준다.
func siemSource(raw string) string {
	if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
		return ip.String()
	}
	return ""
}

// 값을 가릴 쿼리 키. 부분 일치(소문자 비교)와 완전 일치 두 목록으로 둔다 - "code" · "key" 같은 짧은 이름을 부분 일치로 두면
// countryCode 같은 평범한 키까지 가려진다.
var (
	sensitiveQueryParts = []string{"token", "secret", "passw", "apikey", "api_key", "api-key", "accesskey", "access_key",
		"signature", "credential", "session", "jwt", "bearer", "cookie"}
	sensitiveQueryKeys = map[string]bool{"code": true, "sig": true, "key": true, "auth": true, "pwd": true, "otp": true}
)

func isSensitiveQueryKey(k string) bool {
	k = strings.ToLower(k)
	if sensitiveQueryKeys[k] {
		return true
	}
	for _, p := range sensitiveQueryParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// maskAuditURL 은 기록용 URL 과 호스트를 돌려준다. userinfo 는 통째로 지우고 민감한 쿼리 값은 *** 로 바꾼다.
// 파싱하지 못하면 쿼리를 통째로 버린다(값을 남기지 않는 쪽으로 실패).
func maskAuditURL(raw string) (string, string) {
	if raw == "" {
		return "", ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			raw = raw[:i]
		}
		return sanitizeLogInput(raw), ""
	}
	u.User = nil
	u.Fragment = ""
	if u.RawQuery != "" {
		q := u.Query()
		for k, vs := range q {
			if isSensitiveQueryKey(k) {
				for i := range vs {
					vs[i] = "***"
				}
			}
		}
		u.RawQuery = q.Encode()
	}
	return u.String(), u.Hostname()
}

// logURL 은 업스트림 텍스트 로그에 찍는 URL 을 Audit 줄과 같은 규칙으로 가린다.
func logURL(raw string) string {
	masked, _ := maskAuditURL(raw)
	return sanitizeLogInput(masked)
}

// logErr 는 client.Do 오류(*url.Error)에 실린 대상 URL 을 가린다. 사용자에게 돌려주는 오류 응답은 그대로 둔다.
func logErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return &url.Error{Op: ue.Op, URL: logURL(ue.URL), Err: ue.Err}
	}
	return err
}

// isLoopbackTarget 은 대상 호스트가 이 Pod 자신을 가리키는지 본다. Go 는 이런 대상에 HTTP_PROXY 를 쓰지 않고 바로 붙어서
// 앞단 egress 프록시(목적지 allowlist)를 거치지 않는다. banned-dests 는 문자열 완전 일치라 [::ffff:127.0.0.1] 같은 표기를 거르지 못해,
// 같은 Pod 의 다른 리스너(앞단 프록시 · egress 프록시 · proxyscotch 자신)에 사용자 헤더를 위조한 요청을 넣을 수 있었다.
// PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS=true 는 업스트림 테스트(127.0.0.1 의 httpbin 을 대상으로 쓴다)용이다. 배포에서는 쓰지 않는다.
func isLoopbackTarget(host string) bool {
	if os.Getenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS") == "true" {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
	}
	return false
}
