package libproxy

// [wasl] CLI · CI 경로(/cli)의 Hoppscotch Personal Access Token(PAT) 확인.
//
// 브라우저가 아닌 클라이언트(CLI, CI)는 앞단 프록시의 SSO 세션이 없다. 앞단 프록시가 /cli 로 넘긴 요청은 본문 accessToken 의
// Hoppscotch PAT(pat-<uuid>)로 인증하고, 공용 토큰(--token)은 이 경로에서 받지 않는다. 그 밖의 경로는 지금처럼 공용 토큰과
// 앞단 프록시가 세운 사용자 헤더를 쓴다.
//   - PAT 는 PostgreSQL 함수 proxyscotch_pat.lookup(uuid) 하나로 확인한다(PROXYSCOTCH_PAT_DSN 의 role 은 그 함수의 실행 권한만 갖는다).
//     Hoppscotch 는 PAT 를 평문으로 저장하므로, 테이블을 읽을 수 있는 role 이면 모든 PAT 를 읽을 수 있다.
//     함수는 (pat_id, owner_email, expires_on, created_on, owner_verified) 한 행을 돌려주고, 없으면 행이 없다.
//   - 만료가 없는 PAT, 발급부터 만료까지가 PROXYSCOTCH_PAT_MAX_DAYS 를 넘는 PAT, 만료된 PAT, 함수가 owner_verified=false 로
//     돌려준 PAT 는 거부한다. 만료가 없는 PAT 는 PROXYSCOTCH_PAT_ALLOW_NO_EXPIRY=true 이면 누구의 것이든 받고, 아니면 주인 이메일이
//     PROXYSCOTCH_PAT_NO_EXPIRY_OWNERS(쉼표로 구분, 대소문자 무시)에 있을 때만 받는다.
//   - 주인 이메일(소문자)이 PROXYSCOTCH_PAT_DENY_OWNERS(정규식)에 맞는 PAT 는 거부한다 - 여럿이 함께 쓰는 공용 계정은
//     누가 불렀는지 남지 않으므로, CI 도 사람마다 자기 계정의 PAT 를 쓰게 한다.
//   - 조회 결과는 PAT 의 SHA-256 으로 짧게 캐시한다(찾음 30초, 없음 10초). 조회 오류는 캐시하지 않고 거부한다(닫힌 실패).
//   - 출발지(hopp_src)마다 1분에 PROXYSCOTCH_PAT_FAIL_PER_MINUTE 번 넘게 없는 PAT 를 보내면 그 분이 끝날 때까지 조회 없이 거부한다.
//   - Audit · SIEM 줄의 user 는 PAT 주인 이메일, user_id 는 pat:<PAT id> 다. 주인을 모르면 user 는 anonymous 다.
//     이 경로에서는 요청 헤더의 사용자(X-Forwarded-Email · X-Forwarded-User)를 쓰지 않는다.
//   - PAT 값은 어디에도 기록하지 않는다.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

const (
	cliPath          = "/cli"
	patAnonymousUser = "anonymous"
	patFoundTTL      = 30 * time.Second
	patMissingTTL    = 10 * time.Second
	patCacheMax      = 10000
	patLookupTimeout = 3 * time.Second
	// Hoppscotch 는 만료를 발급 시각 + N일로 계산한다. 두 시각이 같은 순간에 찍히지 않아 생기는 차이만 넘겨준다.
	patLifetimeSlack = time.Hour
)

// Hoppscotch 는 PAT 를 "pat-" + uuid 로 내주고 DB 에는 uuid 만 둔다.
var patFormat = regexp.MustCompile(`^pat-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

type patOwner struct {
	ID        string
	Email     string
	ExpiresOn *time.Time // nil = 만료 없음
	CreatedOn time.Time
	Verified  bool
}

// patLookupFunc 는 PAT 의 uuid 로 주인을 찾는다. 없으면 (nil, nil) 이다.
type patLookupFunc func(ctx context.Context, uuid string) (*patOwner, error)

var (
	patLookup    patLookupFunc // nil 이면 CLI 경로가 꺼져 있다
	patMaxAge    = 90 * 24 * time.Hour
	patFailLimit = 10
	patNow       = time.Now
	patCache     = newPATCache()
	patFails     = newPATFailCounter()
	// 만료가 없는 PAT 를 받는 주인(소문자 이메일). 비어 있고 patAllowNoExpiry 도 거짓이면 만료가 없는 PAT 는 모두 거부한다.
	patNoExpiryOwners = map[string]bool{}
	// 참이면 만료가 없는 PAT 를 주인과 관계없이 받는다.
	patAllowNoExpiry = false
	// 주인 이메일(소문자)이 맞으면 거부한다(공용 계정). nil 이면 거부하지 않는다.
	patDenyOwners *regexp.Regexp
)

// parsePATOwners 는 쉼표로 구분한 이메일 목록을 소문자 집합으로 바꾼다. 빈 항목은 건너뛰고, @ 가 없는 항목은 오류다.
func parsePATOwners(v string) (map[string]bool, error) {
	owners := map[string]bool{}
	for _, e := range strings.Split(v, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.Contains(e, "@") {
			return nil, fmt.Errorf("%q is not an email address", e)
		}
		owners[e] = true
	}
	return owners, nil
}

// initPATFromEnv 는 PROXYSCOTCH_PAT_DSN 이 있을 때만 CLI 경로를 켠다. 값이 잘못됐으면 기동을 멈춘다(조용히 꺼진 채로 뜨지 않게).
// DSN 에는 비밀번호를 넣지 않는다 - 드라이버가 PGPASSWORD 를 읽는다.
func initPATFromEnv() {
	dsn := os.Getenv("PROXYSCOTCH_PAT_DSN")
	if dsn == "" {
		return
	}
	if v := os.Getenv("PROXYSCOTCH_PAT_MAX_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			ErrorLogger.Fatalf("PROXYSCOTCH_PAT_MAX_DAYS must be a positive integer, got %q", sanitizeLogInput(v))
		}
		patMaxAge = time.Duration(n) * 24 * time.Hour
	}
	if v := os.Getenv("PROXYSCOTCH_PAT_FAIL_PER_MINUTE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			ErrorLogger.Fatalf("PROXYSCOTCH_PAT_FAIL_PER_MINUTE must be a positive integer, got %q", sanitizeLogInput(v))
		}
		patFailLimit = n
	}
	owners, err := parsePATOwners(os.Getenv("PROXYSCOTCH_PAT_NO_EXPIRY_OWNERS"))
	if err != nil {
		ErrorLogger.Fatalf("PROXYSCOTCH_PAT_NO_EXPIRY_OWNERS: %s", sanitizeLogInput(err.Error()))
	}
	patNoExpiryOwners = owners
	if v := os.Getenv("PROXYSCOTCH_PAT_ALLOW_NO_EXPIRY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			ErrorLogger.Fatalf("PROXYSCOTCH_PAT_ALLOW_NO_EXPIRY must be true or false, got %q", sanitizeLogInput(v))
		}
		patAllowNoExpiry = b
	}
	if v := os.Getenv("PROXYSCOTCH_PAT_DENY_OWNERS"); v != "" {
		re, err := regexp.Compile(v)
		if err != nil {
			ErrorLogger.Fatalf("PROXYSCOTCH_PAT_DENY_OWNERS is not a valid regular expression: %s", sanitizeLogInput(err.Error()))
		}
		patDenyOwners = re
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		ErrorLogger.Fatalf("PROXYSCOTCH_PAT_DSN is invalid: %v", err)
	}
	// 캐시가 있어 조회는 드물다. 게이트 Pod 이 여러 개여도 DB 연결 수가 작게 머물도록 둘로 묶는다.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(10 * time.Minute)
	patLookup = sqlPATLookup(db)
	noExpiry := fmt.Sprintf("%d owners may use PATs without expiry", len(patNoExpiryOwners))
	if patAllowNoExpiry {
		noExpiry = "PATs without expiry accepted"
	}
	deny := "no owners denied"
	if patDenyOwners != nil {
		deny = "owners matching " + strconv.Quote(patDenyOwners.String()) + " denied"
	}
	InfoLogger.Printf("CLI path %s enabled: Hoppscotch PAT up to %d days (%s, %s), %d unknown tokens per source per minute",
		cliPath, int(patMaxAge/(24*time.Hour)), noExpiry, deny, patFailLimit)
}

func sqlPATLookup(db *sql.DB) patLookupFunc {
	return func(ctx context.Context, uuid string) (*patOwner, error) {
		var o patOwner
		var email sql.NullString
		var expires sql.NullTime
		err := db.QueryRowContext(ctx,
			`SELECT pat_id, owner_email, expires_on, created_on, owner_verified FROM proxyscotch_pat.lookup($1)`, uuid).
			Scan(&o.ID, &email, &expires, &o.CreatedOn, &o.Verified)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		o.Email = email.String
		if expires.Valid {
			t := expires.Time
			o.ExpiresOn = &t
		}
		return &o, nil
	}
}

// checkPAT 는 CLI 경로의 accessToken 을 확인한다. 주인을 찾으면 audit 의 user · userID 를 주인으로 바꾼다(거부여도).
// 통과면 빈 문자열, 아니면 Audit 줄의 result 값을 돌려준다.
func checkPAT(ctx context.Context, a *auditRecord, token string) string {
	if patLookup == nil {
		return "denied_cli_disabled"
	}
	now := patNow()
	src := a.src
	if src == "" {
		src = "unknown"
	}
	if patFails.blocked(src, now) {
		return "denied_pat_rate"
	}
	m := patFormat.FindStringSubmatch(token)
	if m == nil {
		patFails.add(src, now)
		return "denied_pat"
	}
	key := sha256.Sum256([]byte(m[1]))
	owner, cached := patCache.get(key, now)
	if !cached {
		lctx, cancel := context.WithTimeout(ctx, patLookupTimeout)
		defer cancel()
		o, err := patLookup(lctx, m[1])
		if err != nil {
			ErrorLogger.Printf("PAT lookup failed: %v", err)
			return "error_pat_lookup"
		}
		owner = o
		patCache.put(key, o, now)
	}
	if owner == nil {
		patFails.add(src, now)
		return "denied_pat"
	}
	a.user, a.userID = owner.Email, "pat:"+owner.ID
	if patDenyOwners != nil && patDenyOwners.MatchString(strings.ToLower(owner.Email)) {
		return "denied_pat_shared"
	}
	switch {
	case owner.Email == "" || !owner.Verified:
		a.user = patAnonymousUser
		return "denied_pat_owner"
	case owner.ExpiresOn == nil:
		if !patAllowNoExpiry && !patNoExpiryOwners[strings.ToLower(owner.Email)] {
			return "denied_pat_no_expiry"
		}
	case !now.Before(*owner.ExpiresOn):
		return "denied_pat_expired"
	case owner.ExpiresOn.Sub(owner.CreatedOn) > patMaxAge+patLifetimeSlack:
		return "denied_pat_lifetime"
	}
	return ""
}

// patDeniedBody 는 거부 사유별 응답 본문이다. 주인을 찾은 PAT(만료 · 기간 · 주인)는 고칠 방법을 알려 준다 -
// 그 PAT 를 가진 사람만 받는 응답이다. 찾지 못한 경우는 사유를 구분하지 않는다.
func patDeniedBody(result string) string {
	msg := "Unauthorized request; send a valid Hoppscotch personal access token as accessToken."
	switch result {
	case "error_pat_lookup":
		msg = "Could not verify the access token. Try again later."
	case "denied_pat_shared":
		msg = "This personal access token belongs to a shared account, which cannot use this path. Use a token made in your own account."
	case "denied_pat_no_expiry":
		msg = "This personal access token has no expiry. Create one with an expiry."
	case "denied_pat_lifetime":
		msg = "This personal access token is valid for longer than " + strconv.Itoa(int(patMaxAge/(24*time.Hour))) + " days. Create one with a shorter expiry."
	case "denied_pat_expired":
		msg = "This personal access token has expired."
	case "denied_pat_owner":
		msg = "The owner of this personal access token has not signed in with the identity provider."
	case "denied_cli_disabled":
		msg = "This path is not enabled."
	}
	return `{"success": false, "data":{"message":"(Proxy Error) ` + msg + `"}}`
}

type patCacheEntry struct {
	owner *patOwner
	until time.Time
}

type patCacheStore struct {
	mu      sync.Mutex
	entries map[[32]byte]patCacheEntry
}

func newPATCache() *patCacheStore {
	return &patCacheStore{entries: map[[32]byte]patCacheEntry{}}
}

func (c *patCacheStore) get(key [32]byte, now time.Time) (*patOwner, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !now.Before(e.until) {
		return nil, false
	}
	return e.owner, true
}

func (c *patCacheStore) put(key [32]byte, owner *patOwner, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= patCacheMax {
		c.entries = map[[32]byte]patCacheEntry{}
	}
	ttl := patFoundTTL
	if owner == nil {
		ttl = patMissingTTL
	}
	c.entries[key] = patCacheEntry{owner: owner, until: now.Add(ttl)}
}

type patFailWindow struct {
	start time.Time
	count int
}

type patFailCounter struct {
	mu     sync.Mutex
	counts map[string]*patFailWindow
}

func newPATFailCounter() *patFailCounter {
	return &patFailCounter{counts: map[string]*patFailWindow{}}
}

func (f *patFailCounter) window(src string, now time.Time) *patFailWindow {
	w, ok := f.counts[src]
	if !ok || now.Sub(w.start) >= time.Minute {
		if len(f.counts) >= patCacheMax {
			f.counts = map[string]*patFailWindow{}
		}
		w = &patFailWindow{start: now}
		f.counts[src] = w
	}
	return w
}

func (f *patFailCounter) blocked(src string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.window(src, now).count >= patFailLimit
}

func (f *patFailCounter) add(src string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.window(src, now).count++
}
