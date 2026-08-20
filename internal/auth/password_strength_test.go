package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// assertWeakPassword checks the 422 envelope and the reasons a client reads.
func assertWeakPassword(t *testing.T, herr *HTTPError, wantReasons []string) {
	t.Helper()
	if herr == nil {
		t.Fatal("expected a weak_password error, got nil")
	}
	if herr.HTTPStatus != http.StatusUnprocessableEntity || herr.ErrorCode != ErrorCodeWeakPassword {
		t.Fatalf("got %d/%s, want 422/%s", herr.HTTPStatus, herr.ErrorCode, ErrorCodeWeakPassword)
	}
	var body struct {
		Code         int    `json:"code"`
		ErrorCode    string `json:"error_code"`
		Message      string `json:"msg"`
		WeakPassword *struct {
			Reasons []string `json:"reasons"`
		} `json:"weak_password"`
	}
	raw, err := json.Marshal(herr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	if body.WeakPassword == nil {
		t.Fatalf("body %s has no weak_password payload", raw)
	}
	if !reflect.DeepEqual(body.WeakPassword.Reasons, wantReasons) {
		t.Errorf("reasons = %v, want %v (body %s)", body.WeakPassword.Reasons, wantReasons, raw)
	}
}

func TestPasswordMinLength(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Password.MinLength = 8
	a := newSecurityTestAPI(t, cfg)

	herr := a.checkPasswordStrength(context.Background(), "short12")
	assertWeakPassword(t, herr, []string{"length"})
	if herr.Message != "Password should be at least 8 characters." {
		t.Errorf("msg = %q, want upstream's length message", herr.Message)
	}
	if herr := a.checkPasswordStrength(context.Background(), "longenough"); herr != nil {
		t.Errorf("an 10-character password must pass MinLength=8, got %v", herr)
	}
}

// bcrypt truncates past 72 bytes, so a longer password is a 400, NOT a
// weak_password (upstream's checkPasswordStrength does the same).
func TestPasswordTooLongIsValidationFailed(t *testing.T) {
	a := newSecurityTestAPI(t, DefaultConfig())

	herr := a.checkPasswordStrength(context.Background(), strings.Repeat("x", 73))
	if herr == nil {
		t.Fatal("a 73-byte password must be rejected")
	}
	if herr.HTTPStatus != http.StatusBadRequest || herr.ErrorCode != ErrorCodeValidationFailed {
		t.Fatalf("got %d/%s, want 400/%s", herr.HTTPStatus, herr.ErrorCode, ErrorCodeValidationFailed)
	}
	if herr.Message != "Password cannot be longer than 72 characters" {
		t.Errorf("msg = %q, want upstream's message", herr.Message)
	}
}

// Each colon-separated set must contribute at least one character.
func TestPasswordRequiredCharactersMatrix(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Password.MinLength = 6
	cfg.Password.RequiredCharacters = parseRequiredCharacters(
		"abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ:0123456789:!@#$%^&*()")
	a := newSecurityTestAPI(t, cfg)

	for _, tc := range []struct {
		name        string
		password    string
		wantReasons []string
	}{
		{"all four classes", "Passw0rd!", nil},
		{"no upper", "passw0rd!", []string{"characters"}},
		{"no lower", "PASSW0RD!", []string{"characters"}},
		{"no digit", "Password!", []string{"characters"}},
		{"no symbol", "Passw0rdd", []string{"characters"}},
		{"nothing but lower", "password", []string{"characters"}},
		{"short and incomplete", "Ab1c", []string{"length", "characters"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			herr := a.checkPasswordStrength(context.Background(), tc.password)
			if tc.wantReasons == nil {
				if herr != nil {
					t.Fatalf("%q must pass, got %v", tc.password, herr)
				}
				return
			}
			assertWeakPassword(t, herr, tc.wantReasons)
		})
	}
}

// An empty RequiredCharacters list (the default) imposes no class rule at all.
func TestPasswordRequiredCharactersEmptyIsNoRule(t *testing.T) {
	a := newSecurityTestAPI(t, DefaultConfig())
	if herr := a.checkPasswordStrength(context.Background(), "aaaaaa"); herr != nil {
		t.Errorf("with no required character sets, any 6-character password passes; got %v", herr)
	}
}

// The wire shape is part of the client contract (gotrue-js reads
// error.weak_password.reasons).
func TestWeakPasswordJSONShape(t *testing.T) {
	herr := weakPasswordError("Password should be at least 8 characters.", []string{"length"})
	raw, err := json.Marshal(herr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"code":422,"error_code":"weak_password","msg":"Password should be at least 8 characters.",` +
		`"weak_password":{"reasons":["length"]}}`
	if string(raw) != want {
		t.Errorf("body =\n  %s\nwant\n  %s", raw, want)
	}
}

// Ordinary errors must NOT grow a weak_password field.
func TestNonWeakPasswordErrorsKeepTheirShape(t *testing.T) {
	raw, err := json.Marshal(internalServerError("boom").withInternal(context.Canceled))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "weak_password") {
		t.Errorf("body = %s, must not carry a weak_password payload", raw)
	}
}
