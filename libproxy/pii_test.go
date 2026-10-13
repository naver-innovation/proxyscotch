package libproxy

// [wasl] 기록용 URL 의 개인정보 부분 마스킹 검증. 이미지 빌드 단계에서 go test 로 돈다.

import "testing"

func TestMaskPII(t *testing.T) {
	cases := []struct{ in, want string }{
		// 이메일: 로컬 부분 앞 2자(2자 이하면 1자), 도메인은 그대로
		{"abcdef@naver.com", "ab***@naver.com"},
		{"ab@x.co", "a***@x.co"},
		{"a.b+tag@mail.example.sa", "a.***@mail.example.sa"},
		{"/users/abcdef@naver.com/profile", "/users/ab***@naver.com/profile"},
		{"/npm/@scope/pkg", "/npm/@scope/pkg"}, // @ 앞에 로컬 부분이 없으면 이메일이 아니다
		// 휴대폰 KR: 숫자 앞 3자리 · 끝 4자리만, 구분자는 그대로
		{"010-1234-5678", "010-****-5678"},
		{"01012345678", "010****5678"},
		{"011.123.4567", "011.***.4567"},
		{"+82-10-1234-5678", "+82-1*-****-5678"},
		// 휴대폰 KSA
		{"0512345678", "051***5678"},
		{"+966512345678", "+966*****5678"},
		{"+966 51 234 5678", "+966 ** *** 5678"},
		{"/members/0512345678/orders", "/members/051***5678/orders"},
		// 휴대폰이 아닌 숫자는 그대로
		{"1791851277", "1791851277"},         // epoch 초
		{"05123456789012", "05123456789012"}, // 더 긴 숫자열
		{"order-901012345678", "order-901012345678"},
		{"/v1/items/12345", "/v1/items/12345"},
		{"", ""},
	}
	for _, c := range cases {
		if got := maskPII(c.in); got != c.want {
			t.Errorf("maskPII(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMaskAuditURLPII(t *testing.T) {
	cases := []struct{ in, want string }{
		// 경로의 이메일 · 휴대폰 - 경로의 * 는 인코딩하지 않는다(Slack 알림에 그대로 보인다)
		{"https://api.example/v1/users/abcdef@naver.com", "https://api.example/v1/users/ab***@naver.com"},
		{"https://api.example/v1/users/abcdef%40naver.com/profile", "https://api.example/v1/users/ab***@naver.com/profile"},
		{"https://api.example/v1/members/01012345678", "https://api.example/v1/members/010****5678"},
		// 쿼리 값의 이메일 · 휴대폰, 신분번호 키, 기존 민감 키 - 쿼리는 기존처럼 QueryEscape(* 는 %2A)
		{"https://api.example/v1/find?email=abcdef@naver.com&page=1", "https://api.example/v1/find?email=ab%2A%2A%2A%40naver.com&page=1"},
		{"https://api.example/v1/find?phone=%2B966512345678", "https://api.example/v1/find?phone=%2B966%2A%2A%2A%2A%2A5678"},
		{"https://api.example/v1/find?nationalId=1234567890&iqama=2345678901", "https://api.example/v1/find?iqama=2%2A%2A%2A&nationalId=1%2A%2A%2A"},
		{"https://api.example/v1/find?access_token=abc&q=1791851277", "https://api.example/v1/find?access_token=%2A%2A%2A&q=1791851277"},
		// 개인정보가 없으면 경로 표기를 바꾸지 않는다
		{"https://api.example/v1/a%2Fb/items/12345", "https://api.example/v1/a%2Fb/items/12345"},
	}
	for _, c := range cases {
		if got, _ := maskAuditURL(c.in); got != c.want {
			t.Errorf("maskAuditURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
