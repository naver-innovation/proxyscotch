package libproxy

// [wasl] Audit 로그 · 루프백 대상 차단 검증. 이미지 빌드 단계에서 go test 로 돈다(출하 바이너리에는 들어가지 않는다).

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
)

func auditCall(t *testing.T, req Request, origin string, hdr map[string]string, method, path string) []map[string]interface{} {
	t.Helper()
	var buf bytes.Buffer
	old := auditOut
	auditOut = log.New(&buf, "", 0)
	defer func() { auditOut = old }()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	proxyHandler(w, r)
	var out []map[string]interface{}
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("audit line is not JSON: %q", l)
		}
		out = append(out, m)
	}
	return out
}

func TestAuditOkWithUserMaskedUrl(t *testing.T) {
	t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true") // 대상이 127.0.0.1 의 httpbin 이다
	u := strings.Replace(testServerUrl, "http://", "http://alice:pw@", 1) + "/get?access_token=abc&countryCode=KR&code=xyz#frag"
	lines := auditCall(t, Request{Url: u, Method: "GET", Params: map[string]string{"api_key": "k1", "page": "2"},
		Headers: map[string]string{"Authorization": "Bearer SECRET"}, Data: "BODYSECRET"},
		"validorigin1.com", map[string]string{"X-Forwarded-Email": "dev@example.com", "X-Forwarded-User": "u1"}, "POST", "/?hopp_rid=r123")
	if len(lines) != 1 {
		t.Fatalf("want 1 audit line, got %d", len(lines))
	}
	a := lines[0]
	t.Logf("%v", a)
	for k, want := range map[string]interface{}{"audit": "hoppscotch", "user": "dev@example.com", "user_id": "u1", "rid": "r123",
		"method": "GET", "status": float64(200), "result": "ok", "host": "127.0.0.1"} {
		if a[k] != want {
			t.Errorf("%s = %v, want %v", k, a[k], want)
		}
	}
	url := a["url"].(string)
	for _, bad := range []string{"abc", "xyz", "k1", "alice", ":pw@", "frag", "SECRET", "BODYSECRET"} {
		if strings.Contains(url, bad) {
			t.Errorf("url leaks %q: %s", bad, url)
		}
	}
	for _, good := range []string{"countryCode=KR", "page=2", "access_token=%2A%2A%2A", "api_key=%2A%2A%2A", "code=%2A%2A%2A"} {
		if !strings.Contains(url, good) {
			t.Errorf("url missing %q: %s", good, url)
		}
	}
	raw, _ := json.Marshal(a)
	for _, bad := range []string{"Bearer", "BODYSECRET", "Authorization"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("audit line leaks %q", bad)
		}
	}
	if a["bytes"].(float64) <= 0 {
		t.Errorf("bytes not recorded")
	}
}

func TestAuditLoopbackDenied(t *testing.T) {
	t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "")
	for _, target := range []string{"http://[::ffff:127.0.0.1]:8081/", "http://[::ffff:7f00:1]:9159/", "http://127.0.0.2:3128/",
		"http://localhost:8081/", "http://foo.localhost/", "http://0.0.0.0:8081/", "http://169.254.169.254/latest", "http://[::1]:8081/"} {
		lines := auditCall(t, Request{Url: target, Method: "GET"}, "validorigin1.com",
			map[string]string{"X-Forwarded-Email": "attacker@example.com"}, "POST", "/")
		if len(lines) != 1 || lines[0]["result"] != "denied_destination" {
			t.Errorf("%s: want denied_destination, got %v", target, lines)
		}
	}
}

func TestAuditRejections(t *testing.T) {
	if l := auditCall(t, Request{Url: "http://example.com/", Method: "GET"}, "evil.com", nil, "POST", "/"); len(l) != 1 || l[0]["result"] != "denied_origin" {
		t.Errorf("origin: %v", l)
	}
	old := accessToken
	accessToken = "tok"
	defer func() { accessToken = old }()
	if l := auditCall(t, Request{Url: "http://example.com/", Method: "GET", AccessToken: "wrong"}, "validorigin1.com", nil, "POST", "/"); len(l) != 1 || l[0]["result"] != "denied_token" {
		t.Errorf("token: %v", l)
	}
	if l := auditCall(t, Request{Url: "", Method: "GET", AccessToken: "tok"}, "validorigin1.com", nil, "POST", "/"); len(l) != 1 || l[0]["result"] != "rejected" {
		t.Errorf("empty url: %v", l)
	}
}

func TestAuditSkipsNonProxyRequests(t *testing.T) {
	for _, c := range [][2]string{{"GET", "/"}, {"OPTIONS", "/"}, {"GET", "/health"}} {
		if l := auditCall(t, Request{}, "validorigin1.com", nil, c[0], c[1]); len(l) != 0 {
			t.Errorf("%s %s should not be audited: %v", c[0], c[1], l)
		}
	}
}

func TestUpstreamLogLinesMasked(t *testing.T) {
	t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true") // 대상이 127.0.0.1 이다
	var buf bytes.Buffer
	oi, oe, od := InfoLogger, ErrorLogger, DebugLogger
	InfoLogger, ErrorLogger, DebugLogger = log.New(&buf, "INFO: ", 0), log.New(&buf, "ERROR: ", 0), log.New(&buf, "DEBUG: ", 0)
	defer func() { InfoLogger, ErrorLogger, DebugLogger = oi, oe, od }()
	ok := strings.Replace(testServerUrl, "http://", "http://alice:pw@", 1) + "/get?access_token=abc&page=2"
	auditCall(t, Request{Url: ok, Method: "GET", Params: map[string]string{"api_key": "k1"}}, "validorigin1.com", nil, "POST", "/")
	// 연결 거부 - client.Do 오류(*url.Error)에도 대상 URL 이 실린다
	auditCall(t, Request{Url: "http://bob:pw2@127.0.0.1:1/x?token=SEKRET", Method: "GET"}, "validorigin1.com", nil, "POST", "/")
	out := buf.String()
	t.Log(out)
	for _, bad := range []string{"abc", "k1", "alice", ":pw@", "bob", "SEKRET"} {
		if strings.Contains(out, bad) {
			t.Errorf("upstream log leaks %q", bad)
		}
	}
	for _, good := range []string{"Proxying GET request", "Received response from", "Completed GET request", "Failed to execute proxied request", "access_token=%2A%2A%2A", "page=2"} {
		if !strings.Contains(out, good) {
			t.Errorf("upstream log missing %q", good)
		}
	}
}
