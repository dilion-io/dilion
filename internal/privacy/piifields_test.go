package privacy

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePIIFields(t *testing.T) {
	t.Run("empty input is free-form", func(t *testing.T) {
		for _, in := range [][]byte{nil, {}, []byte("  \n ")} {
			got, err := ParsePIIFields(in)
			if err != nil || got != nil {
				t.Fatalf("ParsePIIFields(%q) = (%v, %v), want (nil, nil)", in, got, err)
			}
		}
	})

	t.Run("definitions are loaded and normalised", func(t *testing.T) {
		got, err := ParsePIIFields([]byte(`
pii-fields:
  email: {hint: EMAIL}
  full_name: {hint: name}
  home.address: {hint: ADDRESS}
`))
		if err != nil {
			t.Fatalf("ParsePIIFields: %v", err)
		}
		want := map[string]FieldHint{
			"email":        HintEmail,
			"full_name":    HintName,
			"home.address": HintAddress,
		}
		if len(got) != len(want) {
			t.Fatalf("got %d fields, want %d", len(got), len(want))
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %q, want %q", k, got[k], v)
			}
		}
	})

	for _, tc := range []struct {
		name string
		yaml string
	}{
		{"unknown hint", "pii-fields:\n  email: {hint: MAIL}\n"},
		{"missing hint", "pii-fields:\n  email: {}\n"},
		{"bad key", "pii-fields:\n  Email: {hint: EMAIL}\n"},
		{"no pii-fields key", "other: {}\n"},
		{"empty definition set", "pii-fields: {}\n"},
		{"malformed yaml", "pii-fields: [\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePIIFields([]byte(tc.yaml)); err == nil {
				t.Fatal("ParsePIIFields succeeded, want an error")
			}
		})
	}
}

// Invalid definitions are a startup failure, like invalid policy data.
func TestNewEngineRejectsInvalidPIIFields(t *testing.T) {
	_, err := NewEngine(EngineDeps{
		Pool:          nil,
		KMS:           nil,
		TombstoneKey:  []byte("k"),
		PIIFieldsYAML: []byte("pii-fields:\n  email: {hint: NOPE}\n"),
	})
	if err == nil {
		t.Fatal("NewEngine accepted an unknown hint")
	}
}

func TestApplyPIIFieldDefs(t *testing.T) {
	defs := map[string]FieldHint{"email": HintEmail, "full_name": HintName}
	e := &Engine{piiFields: defs}
	free := &Engine{}

	t.Run("free-form passes the patch through", func(t *testing.T) {
		in := map[string]ProfileField{"anything": {Value: "v", Hint: HintGeneric}}
		out, err := free.applyPIIFieldDefs(in)
		if err != nil {
			t.Fatalf("applyPIIFieldDefs: %v", err)
		}
		if out["anything"].Hint != HintGeneric {
			t.Fatalf("hint = %q, want GENERIC", out["anything"].Hint)
		}
	})

	t.Run("omitted hint comes from the definition", func(t *testing.T) {
		out, err := e.applyPIIFieldDefs(map[string]ProfileField{"email": {Value: "a@b.c"}})
		if err != nil {
			t.Fatalf("applyPIIFieldDefs: %v", err)
		}
		if out["email"].Hint != HintEmail {
			t.Fatalf("hint = %q, want EMAIL", out["email"].Hint)
		}
	})

	t.Run("matching hint is accepted", func(t *testing.T) {
		out, err := e.applyPIIFieldDefs(map[string]ProfileField{"email": {Value: "a@b.c", Hint: HintEmail}})
		if err != nil {
			t.Fatalf("applyPIIFieldDefs: %v", err)
		}
		if out["email"].Hint != HintEmail {
			t.Fatalf("hint = %q, want EMAIL", out["email"].Hint)
		}
	})

	t.Run("conflicting hint is rejected", func(t *testing.T) {
		_, err := e.applyPIIFieldDefs(map[string]ProfileField{"email": {Value: "a@b.c", Hint: HintGeneric}})
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v, want ErrInvalidInput", err)
		}
	})

	t.Run("undefined key is rejected and lists the allowed keys", func(t *testing.T) {
		_, err := e.applyPIIFieldDefs(map[string]ProfileField{"nickname": {Value: "n", Hint: HintGeneric}})
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v, want ErrInvalidInput", err)
		}
		if !strings.Contains(err.Error(), "email, full_name") {
			t.Fatalf("error %q does not list the allowed keys", err)
		}
	})
}

// Without definitions the hint stays mandatory (unchanged free-form contract).
func TestValidateProfilePatchRequiresHintWhenFreeForm(t *testing.T) {
	err := validateProfilePatch(map[string]ProfileField{"email": {Value: "a@b.c"}}, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
}

func TestPIIFieldDefsIsACopy(t *testing.T) {
	e := &Engine{piiFields: map[string]FieldHint{"email": HintEmail}}
	got := e.PIIFieldDefs()
	got["email"] = HintGeneric
	if e.piiFields["email"] != HintEmail {
		t.Fatal("PIIFieldDefs exposed the engine's own map")
	}
	if (&Engine{}).PIIFieldDefs() != nil {
		t.Fatal("free-form engine returned non-nil definitions")
	}
}
