package privacy

import (
	"errors"
	"strings"
	"testing"
)

func TestMaskValue(t *testing.T) {
	cases := []struct {
		name  string
		value string
		hint  FieldHint
		want  string
	}{
		// EMAIL: first rune of the localpart + the whole domain.
		{"email", "joseph@example.com", HintEmail, "j**@example.com"},
		{"email one rune local", "a@example.com", HintEmail, "a**@example.com"},
		{"email empty local", "@example.com", HintEmail, "**@example.com"},
		{"email unicode local", "홍길동@example.com", HintEmail, "홍**@example.com"},
		{"email plus tag", "joseph+tag@sub.example.co.kr", HintEmail, "j**@sub.example.co.kr"},
		{"email multiple at", "a@b@example.com", HintEmail, "a**@example.com"},
		{"email no at falls back to generic", "not-an-email", HintEmail, "****"},
		{"email empty", "", HintEmail, "****"},

		// NAME: first rune only, rune-safe.
		{"name korean", "홍길동", HintName, "홍**"},
		{"name latin", "Joseph", HintName, "J**"},
		{"name single rune", "홍", HintName, "홍**"},
		{"name emoji", "🙂ab", HintName, "🙂**"},
		{"name empty", "", HintName, "**"},

		// PHONE: <first3>-****-<last4> over the digits.
		{"phone kr", "010-1234-5678", HintPhone, "010-****-5678"},
		{"phone digits only", "01012345678", HintPhone, "010-****-5678"},
		{"phone e164", "+82 10-1234-5678", HintPhone, "821-****-5678"},
		{"phone exactly 8 digits", "12345678", HintPhone, "123-****-5678"},
		{"phone 7 digits too short", "1234567", HintPhone, "****"},
		{"phone no digits", "call me", HintPhone, "****"},
		{"phone empty", "", HintPhone, "****"},

		// ADDRESS: first whitespace token + " ***".
		{"address kr", "서울시 강남구 테헤란로 1", HintAddress, "서울시 ***"},
		{"address single token", "Seoul", HintAddress, "Seoul ***"},
		{"address leading space", "  Seoul  Gangnam", HintAddress, "Seoul ***"},
		{"address tab separated", "Seoul\tGangnam", HintAddress, "Seoul ***"},
		{"address blank", "   ", HintAddress, "****"},
		{"address empty", "", HintAddress, "****"},

		// GENERIC and anything unknown.
		{"generic", "whatever", HintGeneric, "****"},
		{"generic empty", "", HintGeneric, "****"},
		{"unknown hint masks fully", "secret", FieldHint("SSN"), "****"},
		{"empty hint masks fully", "secret", FieldHint(""), "****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := maskValue(tc.value, tc.hint); got != tc.want {
				t.Errorf("maskValue(%q, %s) = %q, want %q", tc.value, tc.hint, got, tc.want)
			}
		})
	}
}

// Whatever the hint, a multi-part value is never echoed back whole.
func TestMaskValueNeverEchoesTheWholeValue(t *testing.T) {
	const secret = "홍길동 010-9876-5432 joseph@example.com"
	for _, hint := range []FieldHint{HintEmail, HintName, HintPhone, HintAddress, HintGeneric, FieldHint("SSN")} {
		got := maskValue(secret, hint)
		if strings.Contains(got, secret) || strings.Contains(got, "9876") {
			t.Errorf("hint %s leaked the value: %q", hint, got)
		}
	}
}

func TestProjectProfileViews(t *testing.T) {
	fields := map[string]ProfileField{
		"email": {Value: "joseph@example.com", Hint: HintEmail},
		"name":  {Value: "홍길동", Hint: HintName},
	}

	masked := projectProfile("u1", fields, nil, false)
	if masked.View != ViewMasked {
		t.Errorf("view = %s, want MASKED", masked.View)
	}
	if masked.Fields["email"].Value != "j**@example.com" || masked.Fields["name"].Value != "홍**" {
		t.Errorf("masked fields = %+v", masked.Fields)
	}
	if masked.Fields["email"].Hint != HintEmail {
		t.Error("the hint must survive the masked projection")
	}
	// The projection must not mutate the source document.
	if fields["name"].Value != "홍길동" {
		t.Error("projectProfile mutated its input")
	}

	full := projectProfile("u1", fields, nil, true)
	if full.View != ViewFull || full.Fields["name"].Value != "홍길동" {
		t.Errorf("full projection = %+v", full)
	}

	empty := projectProfile("u1", nil, nil, false)
	if empty.Fields == nil || len(empty.Fields) != 0 {
		t.Errorf("fields = %v, want an empty (non-nil) map", empty.Fields)
	}
}

func TestValidateProfilePatch(t *testing.T) {
	ok := ProfileField{Value: "x", Hint: HintGeneric}

	if err := validateProfilePatch(map[string]ProfileField{
		"email":                 {Value: "a@b.c", Hint: HintEmail},
		"home.address":          {Value: "Seoul", Hint: HintAddress},
		"legacy_id-2":           ok,
		"a":                     ok,
		strings.Repeat("k", 64): ok,
	}, []string{"email", "a.b-c_d"}); err != nil {
		t.Errorf("valid patch rejected: %v", err)
	}

	bad := []struct {
		name   string
		set    map[string]ProfileField
		remove []string
	}{
		{"uppercase key", map[string]ProfileField{"Email": ok}, nil},
		{"leading digit", map[string]ProfileField{"1email": ok}, nil},
		{"empty key", map[string]ProfileField{"": ok}, nil},
		{"key too long", map[string]ProfileField{strings.Repeat("k", 65): ok}, nil},
		{"illegal rune", map[string]ProfileField{"email address": ok}, nil},
		{"unicode key", map[string]ProfileField{"이름": ok}, nil},
		{"unknown hint", map[string]ProfileField{"ssn": {Value: "x", Hint: "SSN"}}, nil},
		{"empty hint is not defaulted", map[string]ProfileField{"nick": {Value: "x"}}, nil},
		{"value too large", map[string]ProfileField{
			"bio": {Value: strings.Repeat("a", maxProfileValueBytes+1), Hint: HintGeneric}}, nil},
		{"bad remove key", nil, []string{"Email"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateProfilePatch(tc.set, tc.remove); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("err = %v, want ErrInvalidInput", err)
			}
		})
	}

	// Exactly at the limits is allowed.
	if err := validateProfilePatch(map[string]ProfileField{
		"bio": {Value: strings.Repeat("a", maxProfileValueBytes), Hint: HintGeneric}}, nil); err != nil {
		t.Errorf("4KB value rejected: %v", err)
	}
	full := map[string]ProfileField{}
	for i := 0; i < maxProfileFields; i++ {
		full[fieldKey(i)] = ok
	}
	if err := validateProfilePatch(full, nil); err != nil {
		t.Errorf("%d fields rejected: %v", maxProfileFields, err)
	}
	full[fieldKey(maxProfileFields)] = ok
	if err := validateProfilePatch(full, nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v, want ErrInvalidInput for %d fields", err, len(full))
	}
}

func fieldKey(i int) string {
	return "f" + strings.Repeat("x", i%7) + "." + string(rune('a'+i%26)) + string(rune('a'+i/26))
}
