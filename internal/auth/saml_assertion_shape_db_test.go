package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
	dsig "github.com/russellhaering/goxmldsig"
)

// GO-2026-6909: crewjam/saml through v0.5.1 accepted, from a validly signed
// assertion,
//
//   - a <NameID> in any XML namespace as Subject.NameID (the tag carried no
//     namespace), so a foreign element became the authenticated subject;
//   - a missing <Subject>, <Conditions> or <SubjectConfirmationData>, which
//     validateAssertion then dereferenced: a nil-pointer panic.
//
// v0.5.2 fixes both. These tests pin that through the ACS, with assertions
// the registered IdP really signed (and encrypted, as it does for Dilion's SP
// metadata), so a downgrade or a library swap that reopens either hole fails
// here. The vulndb record does not yet name v0.5.2 as fixed; see
// scripts/govulncheck-allow.txt.
func TestSAMLACSRejectsMalformedSignedAssertions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tamper   func(t *testing.T, assertion *etree.Element)
		wantCode string
	}{
		{
			// The signing path itself is sound: an untampered assertion
			// through it signs in, so the rejections below are about shape.
			name:   "control",
			tamper: func(*testing.T, *etree.Element) {},
		},
		{
			// With the namespace-blind tag this NameID was the subject, and
			// the account would have been keyed on "attacker".
			name: "foreign-namespace NameID",
			tamper: func(t *testing.T, a *etree.Element) {
				s := mustFind(t, a, "./saml:Subject")
				s.RemoveChild(mustFind(t, s, "./saml:NameID"))
				evil := etree.NewElement("evil:NameID")
				evil.CreateAttr("xmlns:evil", "urn:example:evil")
				evil.CreateAttr("Format", string(saml.PersistentNameIDFormat))
				evil.SetText("attacker")
				s.InsertChildAt(0, evil)
			},
			wantCode: ErrorCodeSAMLAssertionNoUserID,
		},
		{
			name: "no Subject",
			tamper: func(t *testing.T, a *etree.Element) {
				a.RemoveChild(mustFind(t, a, "./saml:Subject"))
			},
			wantCode: ErrorCodeValidationFailed,
		},
		{
			name: "no Conditions",
			tamper: func(t *testing.T, a *etree.Element) {
				a.RemoveChild(mustFind(t, a, "./saml:Conditions"))
			},
			wantCode: ErrorCodeValidationFailed,
		},
		{
			name: "no SubjectConfirmationData",
			tamper: func(t *testing.T, a *etree.Element) {
				sc := mustFind(t, a, "./saml:Subject/saml:SubjectConfirmation")
				sc.RemoveChild(mustFind(t, sc, "./saml:SubjectConfirmationData"))
			},
			wantCode: ErrorCodeValidationFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newSSOEnv(t)
			env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

			rec := env.do(t, http.MethodPost, "/sso", map[string]any{"domain": "example.com",
				"redirect_to": "https://app.test/welcome", "skip_http_redirect": true}, "")
			out := decodeInto[SingleSignOnResponse](t, rec, http.StatusOK)
			form := env.idp.respondTampered(t, env, out.URL,
				testSession("saml-subject-1", "alice@example.com", "Alice Anderson"),
				func(a *etree.Element) { tc.tamper(t, a) })
			rec = env.form(t, "/sso/saml/acs", form)

			if tc.wantCode == "" {
				if rec.Code != http.StatusFound {
					t.Fatalf("control ACS status = %d, want 302; body = %s", rec.Code, rec.Body.String())
				}
				return
			}
			assertACSRedirectError(t, rec, tc.wantCode)

			var users int
			if err := env.pool.QueryRow(t.Context(), `select count(*) from auth.users`).Scan(&users); err != nil {
				t.Fatalf("count users: %v", err)
			}
			if users != 0 {
				t.Errorf("users = %d after a rejected assertion, want 0", users)
			}
		})
	}
}

func mustFind(t *testing.T, el *etree.Element, path string) *etree.Element {
	t.Helper()
	found := el.FindElement(path)
	if found == nil {
		t.Fatalf("<%s> has no %s", el.FullTag(), path)
	}
	return found
}

// respondTampered is respond, except that the assertion element passes
// through tamper before the IdP signs it. It repeats what
// IdpAuthnRequest.MakeAssertionEl does — sign enveloped, then encrypt to the
// SP's certificate when its metadata offers one — because that method signs
// the struct's own rendering, which can express neither a missing required
// element in every position nor a foreign namespace.
func (ti *samlTestIdP) respondTampered(t *testing.T, e *ssoEnv, redirectURL string,
	session *saml.Session, tamper func(*etree.Element)) url.Values {
	t.Helper()
	ti.sp = e.spMetadata(t)

	req := httptest.NewRequest(http.MethodGet, redirectURL, nil)
	authnReq, err := saml.NewIdpAuthnRequest(ti.idp, req)
	if err != nil {
		t.Fatalf("IdP could not read the AuthnRequest: %v", err)
	}
	if err := authnReq.Validate(); err != nil {
		t.Fatalf("IdP rejected the AuthnRequest: %v", err)
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(authnReq, session); err != nil {
		t.Fatalf("IdP could not make the assertion: %v", err)
	}

	assertionEl := authnReq.Assertion.Element()
	tamper(assertionEl)

	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{ti.idp.Certificate.Raw},
		PrivateKey:  ti.idp.Key,
		Leaf:        ti.idp.Certificate,
	}))
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignEnveloped(assertionEl)
	if err != nil {
		t.Fatalf("sign tampered assertion: %v", err)
	}

	authnReq.AssertionEl = signed
	if cert := spEncryptionCert(t, authnReq.SPSSODescriptor); cert != nil {
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		plain, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		enc := xmlenc.OAEP()
		enc.BlockCipher = xmlenc.AES128CBC
		enc.DigestMethod = &xmlenc.SHA1
		data, err := enc.Encrypt(cert, plain, nil)
		if err != nil {
			t.Fatalf("encrypt tampered assertion: %v", err)
		}
		data.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
		wrapped := etree.NewElement("saml:EncryptedAssertion")
		wrapped.AddChild(data)
		authnReq.AssertionEl = wrapped
	}

	if err := authnReq.MakeResponse(); err != nil {
		t.Fatalf("IdP could not make the response: %v", err)
	}
	form, err := authnReq.PostBinding()
	if err != nil {
		t.Fatalf("IdP could not build the POST binding: %v", err)
	}
	return url.Values{"SAMLResponse": {form.SAMLResponse}, "RelayState": {form.RelayState}}
}

// spEncryptionCert is the certificate the IdP encrypts to, chosen as
// crewjam/saml's getSPEncryptionCert does: the first key marked for
// encryption, else the first unmarked one; nil when there is none.
func spEncryptionCert(t *testing.T, sp *saml.SPSSODescriptor) *x509.Certificate {
	t.Helper()
	pick := func(use string) string {
		for _, kd := range sp.KeyDescriptors {
			if kd.Use == use && len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
				if data := kd.KeyInfo.X509Data.X509Certificates[0].Data; data != "" {
					return data
				}
			}
		}
		return ""
	}
	data := pick("encryption")
	if data == "" {
		data = pick("")
	}
	if data == "" {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), ""))
	if err != nil {
		t.Fatalf("decode SP certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse SP certificate: %v", err)
	}
	return cert
}
