package libproxy

// [wasl] 기록용 URL 의 개인정보 부분 마스킹.
//
// Audit 줄과 업스트림 텍스트 로그(maskAuditURL)에 남는 URL 의 경로 · 쿼리 값에서 이메일과 휴대폰 번호를 일부만 가리고,
// 신분번호를 담는 쿼리 키의 값은 앞 한 글자만 남긴다. 사용자에게 돌려주는 응답과 요청은 건드리지 않는다 - 응답의 노출 통제는
// 대상 API 의 인가와 등급별 API 개방이 맡는다(hoppscotch 설계 7절 · D2 · D11).
//
//	이메일   abcdef@naver.com  → ab***@naver.com   (로컬 부분 앞 2자, 2자 이하면 앞 1자)
//	휴대폰   010-1234-5678     → 010-****-5678     (숫자 앞 3자리와 끝 4자리만, 구분자는 그대로)
//	         +966512345678     → +966*****5678
//	신분번호 ?nationalId=1234567890 → ?nationalId=1***
//
// 휴대폰은 KR(01X, +82 1X)과 KSA(05X, +966 5X) 이동전화 형식만 잡는다. 같은 길이의 숫자(주문 번호, epoch 초 등)를 가리지 않도록
// 앞뒤가 숫자인 경우는 건너뛴다. 신분번호(National ID · Iqama · 주민번호)는 epoch 초 같은 10자리 숫자와 구분되지 않아
// 값 모양이 아니라 쿼리 키 이름으로만 잡는다.

import (
	"regexp"
	"strings"
)

var (
	piiEmail = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
	piiPhone = regexp.MustCompile(`(?:\+?82[ .\-]?|0)1[016789][ .\-]?\d{3,4}[ .\-]?\d{4}|(?:\+?966[ .\-]?|0)5\d(?:[ .\-]?\d){7}`)

	// 신분번호를 담는 쿼리 키(소문자 부분 일치).
	piiIDQueryParts = []string{"nationalid", "national_id", "national-id", "iqama", "ssn", "rrn", "jumin"}
)

func isPIIIDQueryKey(k string) bool {
	k = strings.ToLower(k)
	for _, p := range piiIDQueryParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// maskPII 는 문자열 안의 이메일과 휴대폰 번호를 부분 마스킹한다. 바뀐 것이 없으면 입력을 그대로 돌려준다.
func maskPII(s string) string {
	if s == "" {
		return s
	}
	if strings.IndexByte(s, '@') >= 0 {
		s = piiEmail.ReplaceAllStringFunc(s, maskEmail)
	}
	return maskPhones(s)
}

func maskEmail(e string) string {
	at := strings.LastIndexByte(e, '@')
	local, domain := e[:at], e[at:]
	keep := 2
	if len(local) <= 2 {
		keep = 1
	}
	return local[:keep] + "***" + domain
}

func maskPhones(s string) string {
	idx := piiPhone.FindAllStringIndex(s, -1)
	if idx == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		st, en := m[0], m[1]
		// 더 긴 숫자열의 일부면 휴대폰으로 보지 않는다
		if (st > 0 && isDigit(s[st-1])) || (en < len(s) && isDigit(s[en])) {
			continue
		}
		b.WriteString(s[last:st])
		b.WriteString(maskPhoneDigits(s[st:en]))
		last = en
	}
	b.WriteString(s[last:])
	return b.String()
}

// maskPhoneDigits 는 숫자 앞 3자리와 끝 4자리만 남기고 나머지 숫자를 * 로 바꾼다. 숫자가 아닌 문자(+, 구분자)는 그대로 둔다.
func maskPhoneDigits(p string) string {
	n := 0
	for i := 0; i < len(p); i++ {
		if isDigit(p[i]) {
			n++
		}
	}
	out := []byte(p)
	d := 0
	for i := 0; i < len(out); i++ {
		if !isDigit(out[i]) {
			continue
		}
		if d >= 3 && d < n-4 {
			out[i] = '*'
		}
		d++
	}
	return string(out)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// maskIDValue 는 신분번호 값을 앞 한 글자만 남긴다.
func maskIDValue(v string) string {
	if v == "" || v == "***" {
		return v
	}
	return string([]rune(v)[:1]) + "***"
}
