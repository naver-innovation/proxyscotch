package libproxy

// [wasl] CLI · CI 경로(/cli)의 PAT 확인 검증. DB 대신 가짜 조회 함수를 쓴다 - 함수 자체(SQL)는 배포 차트 쪽에서 시험한다.

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	testPATGood    = "pat-11111111-2222-4333-8444-555555555555"
	testPATUnknown = "pat-99999999-2222-4333-8444-555555555555"
)

type fakePATs struct {
	owners map[string]*patOwner // uuid → 주인
	err    error
	calls  int
}

func (f *fakePATs) lookup(_ context.Context, uuid string) (*patOwner, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.owners[uuid], nil
}

// withPAT 는 가짜 조회 함수와 시계를 붙이고, 캐시 · 실패 카운터를 새로 만든다. 테스트가 끝나면 되돌린다.
func withPAT(t *testing.T, f *fakePATs, now time.Time) *time.Time {
	t.Helper()
	oldLookup, oldNow, oldCache, oldFails, oldLimit, oldMax := patLookup, patNow, patCache, patFails, patFailLimit, patMaxAge
	oldNoExpiry, oldAllow, oldDeny := patNoExpiryOwners, patAllowNoExpiry, patDenyOwners
	clock := now
	patNow = func() time.Time { return clock }
	if f != nil {
		patLookup = f.lookup
	} else {
		patLookup = nil
	}
	patCache, patFails, patFailLimit, patMaxAge = newPATCache(), newPATFailCounter(), 10, 90*24*time.Hour
	patNoExpiryOwners, patAllowNoExpiry, patDenyOwners = map[string]bool{}, false, nil
	t.Cleanup(func() {
		patLookup, patNow, patCache, patFails, patFailLimit, patMaxAge = oldLookup, oldNow, oldCache, oldFails, oldLimit, oldMax
		patNoExpiryOwners, patAllowNoExpiry, patDenyOwners = oldNoExpiry, oldAllow, oldDeny
	})
	return &clock
}

func goodOwner(now time.Time, days int) *patOwner {
	exp := now.Add(time.Duration(days) * 24 * time.Hour)
	return &patOwner{ID: "clpat1", Email: "dev@example.com", ExpiresOn: &exp, CreatedOn: now, Verified: true}
}

func cliCall(t *testing.T, token, src string, hdr map[string]string) map[string]interface{} {
	t.Helper()
	lines := auditCall(t, Request{Url: testServerUrl + "/get", Method: "GET", AccessToken: token}, "validorigin1.com", hdr,
		"POST", "/cli?hopp_rid=r1&hopp_src="+src)
	if len(lines) != 1 {
		t.Fatalf("want 1 audit line, got %d", len(lines))
	}
	return lines[0]
}

func TestCLIValidPATUsesOwnerNotHeaders(t *testing.T) {
	t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true") // 대상이 127.0.0.1 의 httpbin 이다
	now := time.Now()
	f := &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): goodOwner(now, 30)}}
	withPAT(t, f, now)
	a := cliCall(t, testPATGood, "10.0.0.9", map[string]string{"X-Forwarded-Email": "attacker@example.com", "X-Forwarded-User": "evil"})
	for k, want := range map[string]interface{}{"result": "ok", "status": float64(200), "user": "dev@example.com", "user_id": "pat:clpat1", "rid": "r1"} {
		if a[k] != want {
			t.Errorf("%s = %v, want %v", k, a[k], want)
		}
	}
}

func TestCLIRejectsSharedToken(t *testing.T) {
	f := &fakePATs{}
	withPAT(t, f, time.Now())
	old := accessToken
	accessToken = "tok"
	defer func() { accessToken = old }()
	a := cliCall(t, "tok", "10.0.0.9", nil)
	if a["result"] != "denied_pat" || a["user"] != patAnonymousUser || f.calls != 0 {
		t.Errorf("shared token on /cli: result=%v user=%v lookups=%d", a["result"], a["user"], f.calls)
	}
}

func TestWebPathDoesNotAcceptPAT(t *testing.T) {
	now := time.Now()
	f := &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): goodOwner(now, 30)}}
	withPAT(t, f, now)
	old := accessToken
	accessToken = "tok"
	defer func() { accessToken = old }()
	lines := auditCall(t, Request{Url: testServerUrl + "/get", Method: "GET", AccessToken: testPATGood}, "validorigin1.com",
		map[string]string{"X-Forwarded-Email": "dev@example.com"}, "POST", "/")
	if len(lines) != 1 || lines[0]["result"] != "denied_token" || f.calls != 0 {
		t.Errorf("PAT on web path: %v lookups=%d", lines, f.calls)
	}
}

func TestCLIOwnerChecks(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	long := now.Add(91 * 24 * time.Hour)
	cases := []struct {
		name, result, user string
		owner              *patOwner
	}{
		{"no expiry", "denied_pat_no_expiry", "dev@example.com", &patOwner{ID: "p", Email: "dev@example.com", CreatedOn: now, Verified: true}},
		{"expired", "denied_pat_expired", "dev@example.com", &patOwner{ID: "p", Email: "dev@example.com", ExpiresOn: &past, CreatedOn: now.Add(-48 * time.Hour), Verified: true}},
		{"longer than max", "denied_pat_lifetime", "dev@example.com", &patOwner{ID: "p", Email: "dev@example.com", ExpiresOn: &long, CreatedOn: now, Verified: true}},
		{"owner not verified", "denied_pat_owner", patAnonymousUser, &patOwner{ID: "p", Email: "dev@example.com", ExpiresOn: &long, CreatedOn: now, Verified: false}},
		{"owner without email", "denied_pat_owner", patAnonymousUser, &patOwner{ID: "p", ExpiresOn: &long, CreatedOn: now, Verified: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withPAT(t, &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): c.owner}}, now)
			a := cliCall(t, testPATGood, "10.0.0.9", nil)
			if a["result"] != c.result || a["user"] != c.user || a["user_id"] != "pat:p" {
				t.Errorf("result=%v user=%v user_id=%v, want %s %s pat:p", a["result"], a["user"], a["user_id"], c.result, c.user)
			}
		})
	}
	// 90일짜리 PAT 는 발급 · 만료 시각 차이(밀리초)가 있어도 통과한다
	t.Run("exactly max days", func(t *testing.T) {
		t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true")
		o := goodOwner(now, 90)
		o.CreatedOn = now.Add(-3 * time.Millisecond)
		withPAT(t, &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): o}}, now)
		if a := cliCall(t, testPATGood, "10.0.0.9", nil); a["result"] != "ok" {
			t.Errorf("90-day PAT: %v", a["result"])
		}
	})
}

// PROXYSCOTCH_PAT_NO_EXPIRY_OWNERS 에 있는 주인만 만료가 없는 PAT 를 쓸 수 있다. 다른 검사(주인 확인 · 만료)는 그대로다.
func TestCLINoExpiryOwners(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	cases := []struct {
		name, result string
		owner        *patOwner
	}{
		{"listed owner, no expiry", "ok", &patOwner{ID: "p", Email: "CI-Bot@Example.com", CreatedOn: now, Verified: true}},
		{"other owner, no expiry", "denied_pat_no_expiry", &patOwner{ID: "p", Email: "dev@example.com", CreatedOn: now, Verified: true}},
		{"listed owner, expired", "denied_pat_expired", &patOwner{ID: "p", Email: "ci-bot@example.com", ExpiresOn: &past, CreatedOn: now.Add(-48 * time.Hour), Verified: true}},
		{"listed owner, not verified", "denied_pat_owner", &patOwner{ID: "p", Email: "ci-bot@example.com", CreatedOn: now, Verified: false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true")
			withPAT(t, &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): c.owner}}, now)
			owners, err := parsePATOwners(" ci-bot@example.com , ,other@example.com")
			if err != nil {
				t.Fatal(err)
			}
			patNoExpiryOwners = owners
			if a := cliCall(t, testPATGood, "10.0.0.9", nil); a["result"] != c.result {
				t.Errorf("result=%v, want %s", a["result"], c.result)
			}
		})
	}
}

func TestCLIAllowNoExpiry(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	cases := []struct {
		name, result string
		owner        *patOwner
	}{
		{"any owner, no expiry", "ok", &patOwner{ID: "p", Email: "dev@example.com", CreatedOn: now, Verified: true}},
		{"with expiry", "ok", goodOwner(now, 30)},
		{"expired", "denied_pat_expired", &patOwner{ID: "p", Email: "dev@example.com", ExpiresOn: &past, CreatedOn: now.Add(-48 * time.Hour), Verified: true}},
		{"no expiry, not verified", "denied_pat_owner", &patOwner{ID: "p", Email: "dev@example.com", CreatedOn: now, Verified: false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true")
			withPAT(t, &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): c.owner}}, now)
			patAllowNoExpiry = true
			if a := cliCall(t, testPATGood, "10.0.0.9", nil); a["result"] != c.result {
				t.Errorf("result=%v, want %s", a["result"], c.result)
			}
		})
	}
}

func TestCLIDenyOwners(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name, result, user string
		owner              *patOwner
	}{
		{"shared, no expiry", "denied_pat_shared", "DL_Team@example.com", &patOwner{ID: "p", Email: "DL_Team@example.com", CreatedOn: now, Verified: true}},
		{"shared, with expiry", "denied_pat_shared", "dl_team@example.com", &patOwner{ID: "p", Email: "dl_team@example.com", ExpiresOn: goodOwner(now, 30).ExpiresOn, CreatedOn: now, Verified: true}},
		{"personal", "ok", "dev@example.com", goodOwner(now, 30)},
		{"dl_ not at the start", "ok", "handle_dl_x@example.com", &patOwner{ID: "p", Email: "handle_dl_x@example.com", CreatedOn: now, Verified: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true")
			withPAT(t, &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): c.owner}}, now)
			patAllowNoExpiry, patDenyOwners = true, regexp.MustCompile(`^dl_`)
			a := cliCall(t, testPATGood, "10.0.0.9", nil)
			if a["result"] != c.result || a["user"] != c.user {
				t.Errorf("result=%v user=%v, want %s %s", a["result"], a["user"], c.result, c.user)
			}
		})
	}
	if !strings.Contains(patDeniedBody("denied_pat_shared"), "shared account") {
		t.Error("denied_pat_shared needs its own message")
	}
}

func TestParsePATOwners(t *testing.T) {
	if o, err := parsePATOwners(""); err != nil || len(o) != 0 {
		t.Errorf("empty: %v %v", o, err)
	}
	if o, err := parsePATOwners("A@x.com,b@y.com"); err != nil || !o["a@x.com"] || !o["b@y.com"] || len(o) != 2 {
		t.Errorf("list: %v %v", o, err)
	}
	if _, err := parsePATOwners("a@x.com,not-an-email"); err == nil {
		t.Error("want an error for an entry without @")
	}
}

func TestCLIMalformedAndUnknown(t *testing.T) {
	f := &fakePATs{owners: map[string]*patOwner{}}
	withPAT(t, f, time.Now())
	for _, tok := range []string{"", "pat-", "PAT-11111111-2222-4333-8444-555555555555", "pat-11111111-2222-4333-8444-555555555555x", "11111111-2222-4333-8444-555555555555"} {
		if a := cliCall(t, tok, "10.0.0.1", nil); a["result"] != "denied_pat" {
			t.Errorf("%q: %v", tok, a["result"])
		}
	}
	if f.calls != 0 {
		t.Errorf("malformed tokens must not reach the DB, got %d lookups", f.calls)
	}
	if a := cliCall(t, testPATUnknown, "10.0.0.2", nil); a["result"] != "denied_pat" || a["user"] != patAnonymousUser || a["user_id"] != nil {
		t.Errorf("unknown PAT: %v", a)
	}
	if f.calls != 1 {
		t.Errorf("unknown PAT lookups = %d, want 1", f.calls)
	}
}

func TestCLIFailLimitPerSource(t *testing.T) {
	t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true")
	now := time.Now()
	f := &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): goodOwner(now, 30)}}
	clock := withPAT(t, f, now)
	patFailLimit = 3
	for i := 0; i < 3; i++ {
		cliCall(t, "pat-bad", "10.0.0.9", nil)
	}
	calls := f.calls
	if a := cliCall(t, testPATGood, "10.0.0.9", nil); a["result"] != "denied_pat_rate" || f.calls != calls {
		t.Errorf("over the limit: result=%v lookups %d → %d", a["result"], calls, f.calls)
	}
	if a := cliCall(t, testPATGood, "10.0.0.10", nil); a["result"] != "ok" {
		t.Errorf("another source must not be limited: %v", a["result"])
	}
	*clock = now.Add(61 * time.Second)
	if a := cliCall(t, testPATGood, "10.0.0.9", nil); a["result"] != "ok" {
		t.Errorf("after the window: %v", a["result"])
	}
}

func TestCLICache(t *testing.T) {
	t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true")
	now := time.Now()
	f := &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): goodOwner(now, 30)}}
	clock := withPAT(t, f, now)
	cliCall(t, testPATGood, "10.0.0.9", nil)
	cliCall(t, testPATGood, "10.0.0.9", nil)
	if f.calls != 1 {
		t.Errorf("found PAT should be cached, lookups=%d", f.calls)
	}
	*clock = now.Add(patFoundTTL)
	cliCall(t, testPATGood, "10.0.0.9", nil)
	if f.calls != 2 {
		t.Errorf("cache should expire after %v, lookups=%d", patFoundTTL, f.calls)
	}
	cliCall(t, testPATUnknown, "10.0.0.9", nil)
	cliCall(t, testPATUnknown, "10.0.0.9", nil)
	if f.calls != 3 {
		t.Errorf("unknown PAT should be cached, lookups=%d", f.calls)
	}
}

func TestCLILookupErrorIsNotCached(t *testing.T) {
	f := &fakePATs{err: errors.New("connection refused")}
	withPAT(t, f, time.Now())
	for i := 0; i < 2; i++ {
		if a := cliCall(t, testPATGood, "10.0.0.9", nil); a["result"] != "error_pat_lookup" {
			t.Errorf("lookup error: %v", a["result"])
		}
	}
	if f.calls != 2 {
		t.Errorf("errors must not be cached, lookups=%d", f.calls)
	}
}

func TestCLIDisabledWithoutDSN(t *testing.T) {
	withPAT(t, nil, time.Now())
	if a := cliCall(t, testPATGood, "10.0.0.9", nil); a["result"] != "denied_cli_disabled" {
		t.Errorf("CLI path without DSN: %v", a["result"])
	}
}

func TestCLISIEMLineUsesOwner(t *testing.T) {
	t.Setenv("PROXYSCOTCH_ALLOW_LOOPBACK_TARGETS", "true")
	now := time.Now()
	withPAT(t, &fakePATs{owners: map[string]*patOwner{strings.TrimPrefix(testPATGood, "pat-"): goodOwner(now, 30)}}, now)
	lines := siemCall(t, Request{Url: testServerUrl + "/post", Method: "POST", AccessToken: testPATGood}, "validorigin1.com",
		map[string]string{"X-Forwarded-Email": "attacker@example.com"}, "/cli?hopp_rid=r2&hopp_src=10.0.0.9")
	if len(lines) != 1 {
		t.Fatalf("want 1 siem line, got %d", len(lines))
	}
	m := siemFields(t, lines[0])
	if m["user"] != "dev@example.com" || m["result"] != "success" || m["src"] != "10.0.0.9" {
		t.Errorf("siem line: %v", m)
	}
	lines = siemCall(t, Request{Url: testServerUrl + "/post", Method: "POST", AccessToken: testPATUnknown}, "validorigin1.com",
		map[string]string{"X-Forwarded-Email": "attacker@example.com"}, "/cli?hopp_rid=r3&hopp_src=10.0.0.9")
	if len(lines) != 1 || siemFields(t, lines[0])["user"] != patAnonymousUser || siemFields(t, lines[0])["result"] != "denied" {
		t.Errorf("unknown PAT siem line: %v", lines)
	}
}

func TestPATDeniedBodyIsJSON(t *testing.T) {
	for _, r := range []string{"denied_pat", "denied_pat_rate", "error_pat_lookup", "denied_pat_no_expiry", "denied_pat_lifetime",
		"denied_pat_expired", "denied_pat_owner", "denied_cli_disabled"} {
		b := patDeniedBody(r)
		if !strings.HasPrefix(b, `{"success": false`) || strings.Contains(b, "pat-") {
			t.Errorf("%s: %s", r, b)
		}
	}
}
