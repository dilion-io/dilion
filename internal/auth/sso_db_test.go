package auth

// Database-backed tests for the SSO / SAML 2.0 surface.
//
// The IdP side is a real crewjam/saml IdentityProvider (samlTestIdP): it
// publishes metadata, validates the AuthnRequest Dilion produced, and signs a
// real assertion. Nothing here hand-rolls XML, so the tests fail if Dilion's SP
// metadata, its AuthnRequest, or its signature verification drift.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
)

// ---- harness ---------------------------------------------------------------

const ssoTestSiteURL = "http://localhost:3000"

type ssoEnv struct {
	*testEnv
	clock *stepClock
	cfg   *Config
	idp   *samlTestIdP
}

// ssoTestConfig is the configuration the SAML surface is exercised under.
func ssoTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := testConfig()
	cfg.SiteURL = ssoTestSiteURL
	cfg.URIAllowList = []string{"http://localhost:3000/**", "https://app.test/**"}
	cfg.SAML.Enabled = true
	cfg.SAML.PrivateKey = testSAMLPrivateKey(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	return cfg
}

// testSAMLPrivateKey is a fixed RSA 2048 key in upstream's wire format
// (standard Base64 of PKCS#1 DER), generated once per process.
var testSAMLPrivateKeyCache string

func testSAMLPrivateKey(t *testing.T) string {
	t.Helper()
	if testSAMLPrivateKeyCache != "" {
		return testSAMLPrivateKeyCache
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate SAML key: %v", err)
	}
	testSAMLPrivateKeyCache = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key))
	return testSAMLPrivateKeyCache
}

func newSSOEnv(t *testing.T) *ssoEnv {
	t.Helper()

	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set; skipping database-backed tests")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}

	applySchema(t, pool)
	applySSOSchema(t, pool)
	truncateAll(t, pool)
	truncateSSOTables(t, pool)

	cfg := ssoTestConfig(t)
	env := &ssoEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: NewTokenServiceHS(testSecret()),
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
		clock: &stepClock{t: time.Now().UTC()},
		cfg:   cfg,
		idp:   newSAMLTestIdP(t),
	}
	env.router = chi.NewRouter()
	Register(env.router, Deps{
		Pool:   pool,
		Tokens: env.tokens,
		Mailer: env.mailer,
		Hooks:  env.hooks,
		Config: cfg,
		Clock:  env.clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return env
}

// applySSOSchema installs the migrations this feature needs on top of the
// shared harness (which applies 0100 only): flow_state (0111) for PKCE, the MFA
// tables (0112) that grantSession writes an AMR claim into, and 0113 itself.
func applySSOSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if !firstApply("applySSOSchema") {
		return
	}
	for _, name := range []string{
		"0111_auth_flow_state.sql",
		"0112_auth_mfa.sql",
		"0113_auth_sso_saml.sql",
	} {
		path := filepath.Join("..", "..", "migrations", name)
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

func truncateSSOTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// DELETE, not TRUNCATE: auth.saml_relay_states carries a foreign key onto
	// auth.flow_state, which TRUNCATE refuses to work around.
	if _, err := pool.Exec(context.Background(),
		`delete from auth.saml_relay_states;
		 delete from auth.sso_domains;
		 delete from auth.saml_providers;
		 delete from auth.sso_providers;
		 delete from auth.flow_state;`); err != nil {
		t.Fatalf("clear SSO tables: %v", err)
	}
}

// form POSTs an application/x-www-form-urlencoded body (the ACS binding).
func (e *ssoEnv) form(t *testing.T, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:41234"
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

// spMetadata reads this deployment's SP metadata through the real endpoint.
func (e *ssoEnv) spMetadata(t *testing.T) *saml.EntityDescriptor {
	t.Helper()
	rec := e.do(t, http.MethodGet, "/sso/saml/metadata", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sso/saml/metadata = %d; body = %s", rec.Code, rec.Body.String())
	}
	md, err := samlsp.ParseMetadata(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse SP metadata: %v\n%s", err, rec.Body.String())
	}
	return md
}

// createProvider registers e.idp and returns the decoded provider.
func (e *ssoEnv) createProvider(t *testing.T, body map[string]any) SSOProvider {
	t.Helper()
	if _, ok := body["type"]; !ok {
		body["type"] = "saml"
	}
	if _, ok := body["metadata_xml"]; !ok {
		body["metadata_xml"] = e.idp.metadataXML(t)
	}
	rec := e.do(t, http.MethodPost, "/admin/sso/providers", body, e.serviceRoleToken(t))
	return decodeInto[SSOProvider](t, rec, http.StatusCreated)
}

// ---- the test identity provider --------------------------------------------

type samlTestIdP struct {
	idp *saml.IdentityProvider
	// sp is filled in per test run: the IdP has to be able to look up the SP
	// metadata the AuthnRequest names.
	sp *saml.EntityDescriptor
}

func newSAMLTestIdP(t *testing.T) *samlTestIdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate IdP key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Dilion Test IdP"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create IdP certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse IdP certificate: %v", err)
	}

	// Every test IdP needs its own EntityID: the registry enforces uniqueness
	// on it, and several tests register two providers side by side.
	host := "idp-" + strings.ReplaceAll(uuid.NewString(), "-", "") + ".test"
	metadataURL, _ := url.Parse("https://" + host + "/metadata")
	ssoURL, _ := url.Parse("https://" + host + "/sso")

	ti := &samlTestIdP{}
	ti.idp = &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		ServiceProviderProvider: ti,
	}
	return ti
}

// GetServiceProvider implements saml.ServiceProviderProvider.
func (ti *samlTestIdP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if ti.sp == nil || ti.sp.EntityID != id {
		return nil, os.ErrNotExist
	}
	return ti.sp, nil
}

func (ti *samlTestIdP) metadataXML(t *testing.T) string {
	t.Helper()
	b, err := xml.Marshal(ti.idp.Metadata())
	if err != nil {
		t.Fatalf("marshal IdP metadata: %v", err)
	}
	return string(b)
}

// entityID is the IdP's SAML EntityID.
func (ti *samlTestIdP) entityID() string { return ti.idp.MetadataURL.String() }

// respond consumes the redirect URL Dilion produced and answers with the form
// values an IdP would POST back to the ACS.
func (ti *samlTestIdP) respond(t *testing.T, e *ssoEnv, redirectURL string, session *saml.Session) url.Values {
	t.Helper()
	ti.sp = e.spMetadata(t)

	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse IdP redirect URL %q: %v", redirectURL, err)
	}
	if u.Query().Get("SAMLRequest") == "" {
		t.Fatalf("redirect URL carries no SAMLRequest: %s", redirectURL)
	}

	req := httptest.NewRequest(http.MethodGet, u.String(), nil)
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
	if err := authnReq.MakeAssertionEl(); err != nil {
		t.Fatalf("IdP could not sign the assertion: %v", err)
	}
	if err := authnReq.MakeResponse(); err != nil {
		t.Fatalf("IdP could not make the response: %v", err)
	}
	form, err := authnReq.PostBinding()
	if err != nil {
		t.Fatalf("IdP could not build the POST binding: %v", err)
	}
	return url.Values{
		"SAMLResponse": {form.SAMLResponse},
		"RelayState":   {form.RelayState},
	}
}

// testSession is the IdP-side session a test signs an assertion for.
func testSession(nameID, email, name string) *saml.Session {
	return &saml.Session{
		ID:             uuid.NewString(),
		CreateTime:     time.Now().UTC(),
		ExpireTime:     time.Now().UTC().Add(time.Hour),
		Index:          "0",
		NameID:         nameID,
		NameIDFormat:   string(saml.PersistentNameIDFormat),
		UserName:       nameID,
		UserEmail:      email,
		UserCommonName: name,
	}
}

// signIn runs a whole SP-initiated flow and returns the ACS response.
func (e *ssoEnv) signIn(t *testing.T, body map[string]any, session *saml.Session) *httptest.ResponseRecorder {
	t.Helper()
	body["skip_http_redirect"] = true
	rec := e.do(t, http.MethodPost, "/sso", body, "")
	out := decodeInto[SingleSignOnResponse](t, rec, http.StatusOK)
	form := e.idp.respond(t, e, out.URL, session)
	return e.form(t, "/sso/saml/acs", form)
}

// ---- SP metadata -----------------------------------------------------------

func TestSAMLServiceProviderMetadata(t *testing.T) {
	env := newSSOEnv(t)

	rec := env.do(t, http.MethodGet, "/sso/saml/metadata", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=600" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("Content-Disposition = %q, want none without ?download=true", cd)
	}

	md, err := samlsp.ParseMetadata(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("SP metadata is not valid SAML metadata: %v\n%s", err, rec.Body.String())
	}

	wantEntityID := ssoTestSiteURL + "/auth/v1/sso/saml/metadata"
	if md.EntityID != wantEntityID {
		t.Errorf("EntityID = %q, want %q", md.EntityID, wantEntityID)
	}
	if len(md.SPSSODescriptors) != 1 {
		t.Fatalf("SPSSODescriptors = %d, want 1", len(md.SPSSODescriptors))
	}
	spd := md.SPSSODescriptors[0]

	wantACS := ssoTestSiteURL + "/auth/v1/sso/saml/acs"
	foundACS := false
	for _, acs := range spd.AssertionConsumerServices {
		if acs.Location == wantACS && acs.Binding == saml.HTTPPostBinding {
			foundACS = true
		}
	}
	if !foundACS {
		t.Errorf("no HTTP-POST AssertionConsumerService at %q; got %+v", wantACS, spd.AssertionConsumerServices)
	}

	if spd.AuthnRequestsSigned != nil {
		t.Errorf("AuthnRequestsSigned = %v, want absent (IdP-initiated assertions are signed alone)", *spd.AuthnRequestsSigned)
	}

	wantFormats := []saml.NameIDFormat{saml.EmailAddressNameIDFormat, saml.PersistentNameIDFormat}
	if len(spd.NameIDFormats) != len(wantFormats) {
		t.Errorf("NameIDFormats = %v, want %v", spd.NameIDFormats, wantFormats)
	} else {
		for i := range wantFormats {
			if spd.NameIDFormats[i] != wantFormats[i] {
				t.Errorf("NameIDFormats = %v, want %v", spd.NameIDFormats, wantFormats)
				break
			}
		}
	}

	if len(spd.KeyDescriptors) != 1 || spd.KeyDescriptors[0].Use != "signing" {
		t.Fatalf("KeyDescriptors = %+v, want exactly one signing key", spd.KeyDescriptors)
	}
	certData := spd.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates
	if len(certData) != 1 || strings.TrimSpace(certData[0].Data) == "" {
		t.Fatalf("signing KeyDescriptor carries no certificate")
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certData[0].Data))
	if err != nil {
		t.Fatalf("certificate is not Base64: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("certificate does not parse: %v", err)
	}
	if want := "SAML 2.0 Certificate for localhost"; cert.Subject.CommonName != want {
		t.Errorf("certificate CN = %q, want %q", cert.Subject.CommonName, want)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "_samlsp.localhost" {
		t.Errorf("certificate DNS names = %v, want [_samlsp.localhost]", cert.DNSNames)
	}
}

func TestSAMLMetadataDownload(t *testing.T) {
	env := newSSOEnv(t)

	rec := env.do(t, http.MethodGet, "/sso/saml/metadata?download=true", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="metadata.xml"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	md, err := samlsp.ParseMetadata(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse metadata: %v", err)
	}
	if md.ValidUntil.IsZero() {
		t.Errorf("?download=true must stamp a validUntil")
	}
}

// The certificate is a stable identity: an operator's IdP trusts it by
// fingerprint, so it must not change between two boots with the same key.
func TestSAMLCertificateIsDeterministic(t *testing.T) {
	key := testSAMLPrivateKey(t)
	first, err := deriveSAMLKeyMaterial(key, "auth.example.com")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	second, err := deriveSAMLKeyMaterial(key, "auth.example.com:443")
	if err != nil {
		t.Fatalf("derive with port: %v", err)
	}
	if string(first.cert.Raw) != string(second.cert.Raw) {
		t.Errorf("certificate differs between derivations; the port must not be part of it")
	}
}

func TestSAMLDisabledIs404(t *testing.T) {
	env := newSSOEnv(t)
	// Rebuild the surface with SAML off.
	cfg := ssoTestConfig(t)
	cfg.SAML.Enabled = false
	r := chi.NewRouter()
	Register(r, Deps{
		Pool: env.pool, Tokens: env.tokens, Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/sso/saml/metadata"},
		{http.MethodPost, "/sso"},
		{http.MethodPost, "/sso/saml/acs"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404; body = %s", tc.method, tc.path, rec.Code, rec.Body.String())
			continue
		}
		var body HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body.ErrorCode != ErrorCodeSAMLProviderDisabled {
			t.Errorf("%s %s error_code = %q, want %q", tc.method, tc.path, body.ErrorCode, ErrorCodeSAMLProviderDisabled)
		}
	}
}

// ---- admin CRUD ------------------------------------------------------------

func TestAdminSSOProviderRoundtrip(t *testing.T) {
	env := newSSOEnv(t)
	admin := env.serviceRoleToken(t)

	created := env.createProvider(t, map[string]any{
		"domains":        []string{"Example.com", "corp.example.com"},
		"resource_id":    "acme",
		"name_id_format": string(saml.EmailAddressNameIDFormat),
		"attribute_mapping": map[string]any{
			"keys": map[string]any{
				"email": map[string]any{"name": "urn:oid:0.9.2342.19200300.100.1.3"},
				"role":  map[string]any{"name": "groups", "default": "member", "array": true},
			},
		},
	})

	if created.ID == "" {
		t.Fatal("created provider has no id")
	}
	if created.SAMLProvider.EntityID != env.idp.entityID() {
		t.Errorf("entity_id = %q, want %q", created.SAMLProvider.EntityID, env.idp.entityID())
	}
	if created.SAMLProvider.MetadataXML == "" {
		t.Error("create response should carry metadata_xml")
	}
	if len(created.SSODomains) != 2 {
		t.Fatalf("domains = %+v, want 2", created.SSODomains)
	}
	if created.SAMLProvider.NameIDFormat == nil || *created.SAMLProvider.NameIDFormat != string(saml.EmailAddressNameIDFormat) {
		t.Errorf("name_id_format = %v", created.SAMLProvider.NameIDFormat)
	}
	if got := created.SAMLProvider.AttributeMapping.Keys["role"]; got.Default != "member" || !got.Array {
		t.Errorf("attribute_mapping role = %+v", got)
	}

	// The raw body is the compatibility contract.
	rec := env.do(t, http.MethodGet, "/admin/sso/providers/"+created.ID, nil, admin)
	var raw map[string]any
	if rec.Code != http.StatusOK {
		t.Fatalf("GET provider = %d; body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"id", "saml", "domains", "created_at", "updated_at", "disabled"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("provider body is missing %q; got %v", k, keysOf(raw))
		}
	}
	samlBody := raw["saml"].(map[string]any)
	for _, k := range []string{"entity_id", "metadata_xml", "attribute_mapping", "name_id_format"} {
		if _, ok := samlBody[k]; !ok {
			t.Errorf("saml body is missing %q; got %v", k, keysOf(samlBody))
		}
	}

	// By resource id.
	rec = env.do(t, http.MethodGet, "/admin/sso/providers/resource_acme", nil, admin)
	byResource := decodeInto[SSOProvider](t, rec, http.StatusOK)
	if byResource.ID != created.ID {
		t.Errorf("resource_acme resolved to %s, want %s", byResource.ID, created.ID)
	}

	// The listing blanks metadata_xml.
	rec = env.do(t, http.MethodGet, "/admin/sso/providers", nil, admin)
	var list struct {
		Items []SSOProvider `json:"items"`
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d; body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(list.Items))
	}
	if list.Items[0].SAMLProvider.MetadataXML != "" {
		t.Error("listing must blank metadata_xml")
	}

	// Update: replace the domain set, disable, drop the name id format.
	rec = env.do(t, http.MethodPut, "/admin/sso/providers/"+created.ID, map[string]any{
		"domains":  []string{"corp.example.com", "new.example.com"},
		"disabled": true,
	}, admin)
	updated := decodeInto[SSOProvider](t, rec, http.StatusOK)
	if updated.Disabled == nil || !*updated.Disabled {
		t.Errorf("disabled = %v, want true", updated.Disabled)
	}
	domains := map[string]bool{}
	for _, d := range updated.SSODomains {
		domains[d.Domain] = true
	}
	if len(domains) != 2 || !domains["corp.example.com"] || !domains["new.example.com"] {
		t.Errorf("domains = %v, want corp+new", domains)
	}
	if updated.SAMLProvider.NameIDFormat != nil {
		t.Errorf("name_id_format = %v, want cleared when absent from the body", *updated.SAMLProvider.NameIDFormat)
	}

	// The removed domain no longer resolves.
	rec = env.do(t, http.MethodPost, "/sso", map[string]any{"domain": "example.com"}, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("removed domain still resolves: %d %s", rec.Code, rec.Body.String())
	}

	// Delete echoes the provider and makes it disappear.
	rec = env.do(t, http.MethodDelete, "/admin/sso/providers/"+created.ID, nil, admin)
	deleted := decodeInto[SSOProvider](t, rec, http.StatusOK)
	if deleted.ID != created.ID {
		t.Errorf("delete echoed %s, want %s", deleted.ID, created.ID)
	}
	rec = env.do(t, http.MethodGet, "/admin/sso/providers/"+created.ID, nil, admin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET after delete = %d, want 404", rec.Code)
	}
}

func TestAdminSSOProviderValidation(t *testing.T) {
	env := newSSOEnv(t)
	admin := env.serviceRoleToken(t)
	metadata := env.idp.metadataXML(t)

	cases := []struct {
		name     string
		body     map[string]any
		status   int
		code     string
		contains string
	}{
		{
			name:     "wrong type",
			body:     map[string]any{"type": "oidc", "metadata_xml": metadata},
			status:   http.StatusBadRequest,
			code:     ErrorCodeValidationFailed,
			contains: "Only 'saml' supported",
		},
		{
			name:     "both metadata sources",
			body:     map[string]any{"type": "saml", "metadata_xml": metadata, "metadata_url": "https://idp.test/metadata"},
			status:   http.StatusBadRequest,
			code:     ErrorCodeValidationFailed,
			contains: "Only one of metadata_xml or metadata_url",
		},
		{
			name:     "no metadata source",
			body:     map[string]any{"type": "saml"},
			status:   http.StatusBadRequest,
			code:     ErrorCodeValidationFailed,
			contains: "Either metadata_xml or metadata_url",
		},
		{
			name:     "plaintext metadata url",
			body:     map[string]any{"type": "saml", "metadata_url": "http://idp.test/metadata"},
			status:   http.StatusBadRequest,
			code:     ErrorCodeValidationFailed,
			contains: "not a HTTPS URL",
		},
		{
			name:     "bad name id format",
			body:     map[string]any{"type": "saml", "metadata_xml": metadata, "name_id_format": "urn:made:up"},
			status:   http.StatusBadRequest,
			code:     ErrorCodeValidationFailed,
			contains: "name_id_format must be",
		},
		{
			name:     "metadata without IDPSSODescriptor",
			body:     map[string]any{"type": "saml", "metadata_xml": `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://nope.test"></EntityDescriptor>`},
			status:   http.StatusBadRequest,
			code:     ErrorCodeValidationFailed,
			contains: "IDPSSODescriptor",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.do(t, http.MethodPost, "/admin/sso/providers", tc.body, admin)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.status, rec.Body.String())
			}
			var body HTTPError
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body.ErrorCode != tc.code {
				t.Errorf("error_code = %q, want %q", body.ErrorCode, tc.code)
			}
			if !strings.Contains(body.Message, tc.contains) {
				t.Errorf("msg = %q, want it to contain %q", body.Message, tc.contains)
			}
		})
	}
}

func TestAdminSSOProviderConflicts(t *testing.T) {
	env := newSSOEnv(t)
	admin := env.serviceRoleToken(t)

	first := env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	// Same EntityID.
	rec := env.do(t, http.MethodPost, "/admin/sso/providers", map[string]any{
		"type":         "saml",
		"metadata_xml": env.idp.metadataXML(t),
	}, admin)
	var body HTTPError
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate entity id = %d, want 422; body = %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.ErrorCode != ErrorCodeSAMLIdPAlreadyExists {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeSAMLIdPAlreadyExists)
	}

	// Same domain on a different provider.
	other := newSAMLTestIdP(t)
	rec = env.do(t, http.MethodPost, "/admin/sso/providers", map[string]any{
		"type":         "saml",
		"metadata_xml": other.metadataXML(t),
		"domains":      []string{"example.com"},
	}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate domain = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.ErrorCode != ErrorCodeSSODomainAlreadyExists {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeSSODomainAlreadyExists)
	}

	// Metadata whose EntityID does not match the provider being updated.
	rec = env.do(t, http.MethodPut, "/admin/sso/providers/"+first.ID, map[string]any{
		"metadata_xml": other.metadataXML(t),
	}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("entity id mismatch = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.ErrorCode != ErrorCodeSAMLEntityIDMismatch {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeSAMLEntityIDMismatch)
	}
}

func TestAdminSSOProvidersRequireAdmin(t *testing.T) {
	env := newSSOEnv(t)
	rec := env.do(t, http.MethodGet, "/admin/sso/providers", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous list = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
}

// ---- POST /sso -------------------------------------------------------------

func TestSingleSignOnProviderResolution(t *testing.T) {
	env := newSSOEnv(t)
	provider := env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	// By domain, case-insensitively (the unique index is on lower(domain)).
	rec := env.do(t, http.MethodPost, "/sso",
		map[string]any{"domain": "EXAMPLE.com", "skip_http_redirect": true}, "")
	out := decodeInto[SingleSignOnResponse](t, rec, http.StatusOK)
	u, err := url.Parse(out.URL)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if u.Host != env.idp.idp.SSOURL.Host || u.Path != "/sso" {
		t.Errorf("redirect = %q, want the IdP SSO endpoint", out.URL)
	}
	if u.Query().Get("SAMLRequest") == "" {
		t.Error("redirect carries no SAMLRequest")
	}
	relayState := u.Query().Get("RelayState")
	if _, uerr := uuid.Parse(relayState); uerr != nil {
		t.Errorf("RelayState = %q, want a UUID", relayState)
	}
	if u.Query().Get("Signature") == "" {
		t.Error("AuthnRequest is not signed")
	}

	// The relay state and its flow state exist.
	rs, err := findSAMLRelayStateByID(context.Background(), env.pool, relayState)
	if err != nil {
		t.Fatalf("relay state not persisted: %v", err)
	}
	if rs.SSOProviderID != provider.ID {
		t.Errorf("relay state provider = %s, want %s", rs.SSOProviderID, provider.ID)
	}
	if rs.FlowStateID == nil {
		t.Fatal("relay state has no flow state")
	}
	fs, err := findOAuthFlowStateByID(context.Background(), env.pool, *rs.FlowStateID)
	if err != nil {
		t.Fatalf("flow state not persisted: %v", err)
	}
	if fs.AuthenticationMethod != authMethodSSOSAML || fs.ProviderType != authMethodSSOSAML {
		t.Errorf("flow state method/provider = %q/%q, want %q",
			fs.AuthenticationMethod, fs.ProviderType, authMethodSSOSAML)
	}

	// By provider id, without skip_http_redirect: a 303 to the IdP.
	rec = env.do(t, http.MethodPost, "/sso", map[string]any{"provider_id": provider.ID}, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, env.idp.idp.SSOURL.String()+"?") {
		t.Errorf("Location = %q", loc)
	}
}

func TestSingleSignOnErrors(t *testing.T) {
	env := newSSOEnv(t)
	provider := env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	cases := []struct {
		name   string
		body   map[string]any
		status int
		code   string
	}{
		{"neither", map[string]any{}, http.StatusBadRequest, ErrorCodeValidationFailed},
		{"both", map[string]any{"domain": "example.com", "provider_id": provider.ID},
			http.StatusBadRequest, ErrorCodeValidationFailed},
		{"unknown domain", map[string]any{"domain": "nobody.test"},
			http.StatusNotFound, ErrorCodeSSOProviderNotFound},
		{"unknown provider id", map[string]any{"provider_id": uuid.NewString()},
			http.StatusNotFound, ErrorCodeSSOProviderNotFound},
		{"provider id is not a uuid", map[string]any{"provider_id": "not-a-uuid"},
			http.StatusNotFound, ErrorCodeSSOProviderNotFound},
		{"bad pkce params", map[string]any{"domain": "example.com", "code_challenge": "too-short", "code_challenge_method": "s256"},
			http.StatusBadRequest, ErrorCodeValidationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.do(t, http.MethodPost, "/sso", tc.body, "")
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.status, rec.Body.String())
			}
			var body HTTPError
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body.ErrorCode != tc.code {
				t.Errorf("error_code = %q, want %q", body.ErrorCode, tc.code)
			}
		})
	}
}

func TestSingleSignOnDisabledProvider(t *testing.T) {
	env := newSSOEnv(t)
	provider := env.createProvider(t, map[string]any{
		"domains":  []string{"example.com"},
		"disabled": true,
	})

	for _, body := range []map[string]any{
		{"domain": "example.com"},
		{"provider_id": provider.ID},
	} {
		rec := env.do(t, http.MethodPost, "/sso", body, "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
		}
		var e HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		if e.ErrorCode != ErrorCodeSSOProviderDisabled {
			t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeSSOProviderDisabled)
		}
	}
}

// ---- POST /sso/saml/acs ----------------------------------------------------

func TestSAMLACSCreatesSSOUser(t *testing.T) {
	env := newSSOEnv(t)
	provider := env.createProvider(t, map[string]any{
		"domains": []string{"example.com"},
		"attribute_mapping": map[string]any{
			"keys": map[string]any{
				"email":     map[string]any{"name": "urn:oid:0.9.2342.19200300.100.1.3"},
				"full_name": map[string]any{"name": "urn:oid:2.5.4.3"},
				"team":      map[string]any{"name": "not-asserted", "default": "engineering"},
			},
		},
	})

	rec := env.signIn(t,
		map[string]any{"domain": "example.com", "redirect_to": "https://app.test/welcome"},
		testSession("saml-subject-1", "alice@example.com", "Alice Anderson"))

	if rec.Code != http.StatusFound {
		t.Fatalf("ACS status = %d, want 302; body = %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.test/welcome#") {
		t.Fatalf("Location = %q, want the implicit-flow fragment on the requested redirect", loc)
	}
	fragment, err := url.ParseQuery(strings.SplitN(loc, "#", 2)[1])
	if err != nil {
		t.Fatalf("parse fragment: %v", err)
	}
	accessToken := fragment.Get("access_token")
	if accessToken == "" || fragment.Get("refresh_token") == "" {
		t.Fatalf("fragment carries no session: %v", fragment)
	}

	// The session's amr must name the SAML sign-in.
	claims, err := env.tokens.Verify(context.Background(), accessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	amr, _ := claims.Extra["amr"].([]any)
	found := false
	for _, entry := range amr {
		if m, ok := entry.(map[string]any); ok && m["method"] == amrSSOSAML {
			found = true
		}
	}
	if !found {
		t.Errorf("amr = %v, want a %q entry", amr, amrSSOSAML)
	}

	// The user is an SSO user with the provider identity and the mapped claims.
	ctx := context.Background()
	user, err := findUserByID(ctx, env.pool, claims.Subject)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if !user.IsSSOUser {
		t.Error("is_sso_user = false, want true for an account created from a SAML assertion")
	}
	if user.Email != "alice@example.com" {
		t.Errorf("email = %q", user.Email)
	}
	if user.EmailConfirmedAt == nil {
		t.Error("an assertion-created account must be confirmed")
	}
	if user.UserMetaData["full_name"] != "Alice Anderson" {
		t.Errorf("user_metadata.full_name = %v, want the mapped cn attribute", user.UserMetaData["full_name"])
	}
	custom, _ := user.UserMetaData["custom_claims"].(map[string]any)
	if custom == nil || custom["team"] != "engineering" {
		t.Errorf("custom_claims = %v, want the mapping default for `team`", user.UserMetaData["custom_claims"])
	}

	identities, err := findIdentitiesByUserID(ctx, env.pool, user.ID)
	if err != nil {
		t.Fatalf("load identities: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("identities = %d, want 1", len(identities))
	}
	if want := ssoProviderName(provider.ID); identities[0].Provider != want {
		t.Errorf("identity provider = %q, want %q", identities[0].Provider, want)
	}
	if identities[0].ProviderID != "saml-subject-1" {
		t.Errorf("identity provider_id = %q, want the assertion subject", identities[0].ProviderID)
	}

	// The relay state is consumed.
	var relayStates int
	if err := env.pool.QueryRow(ctx, `select count(*) from auth.saml_relay_states`).Scan(&relayStates); err != nil {
		t.Fatalf("count relay states: %v", err)
	}
	if relayStates != 0 {
		t.Errorf("relay states left = %d, want 0", relayStates)
	}
}

func TestSAMLACSReloginKeepsTheSameUser(t *testing.T) {
	env := newSSOEnv(t)
	env.createProvider(t, map[string]any{
		"domains": []string{"example.com"},
		"attribute_mapping": map[string]any{
			"keys": map[string]any{"name": map[string]any{"name": "urn:oid:2.5.4.3"}},
		},
	})

	first := env.signIn(t, map[string]any{"domain": "example.com"},
		testSession("saml-subject-1", "alice@example.com", "Alice Anderson"))
	firstUser := userIDFromRedirect(t, env, first)

	second := env.signIn(t, map[string]any{"domain": "example.com"},
		testSession("saml-subject-1", "alice@example.com", "Alice A."))
	secondUser := userIDFromRedirect(t, env, second)

	if firstUser != secondUser {
		t.Fatalf("re-login created a new account: %s -> %s", firstUser, secondUser)
	}

	ctx := context.Background()
	var users int
	if err := env.pool.QueryRow(ctx, `select count(*) from auth.users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 1 {
		t.Errorf("users = %d, want 1", users)
	}
	user, err := findUserByID(ctx, env.pool, secondUser)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if user.UserMetaData["name"] != "Alice A." {
		t.Errorf("user_metadata.name = %v, want the refreshed assertion value", user.UserMetaData["name"])
	}
}

// An SSO assertion must never join a local password account that happens to
// share the address: the SSO provider is its own account-linking domain.
func TestSAMLACSDoesNotLinkIntoPasswordAccount(t *testing.T) {
	env := newSSOEnv(t)
	env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	local := env.signup(t, "alice@example.com", "hunter22-strong")

	rec := env.signIn(t, map[string]any{"domain": "example.com"},
		testSession("saml-subject-1", "alice@example.com", "Alice Anderson"))
	ssoUser := userIDFromRedirect(t, env, rec)

	if ssoUser == local.User.ID {
		t.Fatal("the SAML assertion took over the local password account")
	}
	ctx := context.Background()
	identities, err := findIdentitiesByUserID(ctx, env.pool, local.User.ID)
	if err != nil {
		t.Fatalf("load identities: %v", err)
	}
	for _, i := range identities {
		if strings.HasPrefix(i.Provider, ssoProviderPrefix) {
			t.Errorf("an SSO identity was linked onto the password account: %+v", i)
		}
	}
}

func TestSAMLACSPKCEFlow(t *testing.T) {
	env := newSSOEnv(t)
	env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	verifier, challenge := pkcePair()

	rec := env.signIn(t, map[string]any{
		"domain":                "example.com",
		"redirect_to":           "https://app.test/callback",
		"code_challenge":        challenge,
		"code_challenge_method": "s256",
	}, testSession("saml-subject-1", "alice@example.com", "Alice Anderson"))

	if rec.Code != http.StatusFound {
		t.Fatalf("ACS status = %d, want 302; body = %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "#access_token") {
		t.Fatalf("a PKCE flow must not put tokens in the fragment: %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no ?code= on %q", loc)
	}

	rec = env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": code, "code_verifier": verifier}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.Token == "" || session.User == nil {
		t.Fatalf("pkce exchange returned no session: %s", rec.Body.String())
	}
	exchanged, err := findUserByID(context.Background(), env.pool, session.User.ID)
	if err != nil {
		t.Fatalf("load exchanged user: %v", err)
	}
	if !exchanged.IsSSOUser {
		t.Error("the exchanged session is not for an SSO user")
	}

	// Single use.
	rec = env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": code, "code_verifier": verifier}, "")
	if rec.Code == http.StatusOK {
		t.Error("the auth code was accepted twice")
	}
}

func TestSAMLACSRelayStateFailures(t *testing.T) {
	env := newSSOEnv(t)
	env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	t.Run("unknown relay state", func(t *testing.T) {
		rec := env.form(t, "/sso/saml/acs", url.Values{
			"RelayState":   {uuid.NewString()},
			"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(`<Response/>`))},
		})
		assertACSRedirectError(t, rec, ErrorCodeSAMLRelayStateNotFound)
	})

	t.Run("expired relay state", func(t *testing.T) {
		rec := env.do(t, http.MethodPost, "/sso",
			map[string]any{"domain": "example.com", "skip_http_redirect": true}, "")
		out := decodeInto[SingleSignOnResponse](t, rec, http.StatusOK)
		u, _ := url.Parse(out.URL)
		relayState := u.Query().Get("RelayState")

		env.clock.advance(DefaultSAMLRelayStateValidityPeriod + time.Second)

		rec = env.form(t, "/sso/saml/acs", url.Values{
			"RelayState":   {relayState},
			"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(`<Response/>`))},
		})
		assertACSRedirectError(t, rec, ErrorCodeSAMLRelayStateExpired)

		// The expired row is destroyed on the way out.
		if _, err := findSAMLRelayStateByID(context.Background(), env.pool, relayState); !isNoRows(err) {
			t.Errorf("expired relay state survived: %v", err)
		}
	})

	t.Run("tampered assertion", func(t *testing.T) {
		rec := env.do(t, http.MethodPost, "/sso",
			map[string]any{"domain": "example.com", "skip_http_redirect": true}, "")
		out := decodeInto[SingleSignOnResponse](t, rec, http.StatusOK)
		form := env.idp.respond(t, env, out.URL,
			testSession("saml-subject-1", "alice@example.com", "Alice Anderson"))

		// Flip a byte inside the signed document.
		raw, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
		if err != nil {
			t.Fatalf("decode SAMLResponse: %v", err)
		}
		tampered := strings.Replace(string(raw), "alice@example.com", "mallory@evil.test", 1)
		if tampered == string(raw) {
			t.Fatal("test bug: the email is not present in the assertion")
		}
		form.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tampered)))

		rec = env.form(t, "/sso/saml/acs", form)
		assertACSRedirectError(t, rec, ErrorCodeValidationFailed)

		var users int
		if err := env.pool.QueryRow(context.Background(), `select count(*) from auth.users`).Scan(&users); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if users != 0 {
			t.Errorf("a tampered assertion created %d user(s)", users)
		}
	})

	t.Run("relay state replay", func(t *testing.T) {
		truncateAll(t, env.pool)
		rec := env.do(t, http.MethodPost, "/sso",
			map[string]any{"domain": "example.com", "skip_http_redirect": true}, "")
		out := decodeInto[SingleSignOnResponse](t, rec, http.StatusOK)
		form := env.idp.respond(t, env, out.URL,
			testSession("saml-subject-2", "bob@example.com", "Bob Brown"))

		if rec := env.form(t, "/sso/saml/acs", form); rec.Code != http.StatusFound {
			t.Fatalf("first ACS = %d; body = %s", rec.Code, rec.Body.String())
		}
		rec = env.form(t, "/sso/saml/acs", form)
		assertACSRedirectError(t, rec, ErrorCodeSAMLRelayStateNotFound)
	})
}

// An assertion whose IdP is not registered is refused before anything is
// written.
func TestSAMLACSUnknownIdP(t *testing.T) {
	env := newSSOEnv(t)
	env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	other := newSAMLTestIdP(t)
	other.sp = env.spMetadata(t)

	// An IdP-initiated POST (RelayState is a URL) from an unregistered IdP.
	response := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_x">` +
		`<saml:Issuer>` + other.entityID() + `</saml:Issuer></samlp:Response>`
	rec := env.form(t, "/sso/saml/acs", url.Values{
		"RelayState":   {"https://app.test/welcome"},
		"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(response))},
	})
	assertACSRedirectError(t, rec, ErrorCodeSAMLIdPNotFound)
}

// ---- helpers ---------------------------------------------------------------

// assertACSRedirectError checks that a failed ACS bounced to SiteURL carrying
// the expected error code — the ACS never answers a browser with JSON.
func assertACSRedirectError(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body = %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	if !strings.HasPrefix(loc, ssoTestSiteURL) {
		t.Errorf("Location = %q, want a redirect to SiteURL", loc)
	}
	if got := u.Query().Get("error_code"); got != wantCode {
		t.Errorf("error_code = %q, want %q (Location %q)", got, wantCode, loc)
	}
}

// userIDFromRedirect pulls the user id out of an implicit-flow ACS redirect.
func userIDFromRedirect(t *testing.T, env *ssoEnv, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	parts := strings.SplitN(loc, "#", 2)
	if len(parts) != 2 {
		t.Fatalf("Location %q has no fragment", loc)
	}
	fragment, err := url.ParseQuery(parts[1])
	if err != nil {
		t.Fatalf("parse fragment: %v", err)
	}
	claims, err := env.tokens.Verify(context.Background(), fragment.Get("access_token"))
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	return claims.Subject
}

// Two subjects of the SAME identity provider that assert the same verified
// address land on one account — upstream's LinkAccount decision inside the
// provider's own linking domain.
func TestSAMLACSLinksWithinTheSameProvider(t *testing.T) {
	env := newSSOEnv(t)
	provider := env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	first := env.signIn(t, map[string]any{"domain": "example.com"},
		testSession("saml-subject-1", "alice@example.com", "Alice Anderson"))
	firstUser := userIDFromRedirect(t, env, first)

	second := env.signIn(t, map[string]any{"domain": "example.com"},
		testSession("saml-subject-2", "alice@example.com", "Alice Anderson"))
	secondUser := userIDFromRedirect(t, env, second)

	if firstUser != secondUser {
		t.Fatalf("the second subject created a separate account: %s vs %s", firstUser, secondUser)
	}

	identities, err := findIdentitiesByUserID(context.Background(), env.pool, firstUser)
	if err != nil {
		t.Fatalf("load identities: %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("identities = %d, want 2", len(identities))
	}
	for _, i := range identities {
		if i.Provider != ssoProviderName(provider.ID) {
			t.Errorf("identity provider = %q", i.Provider)
		}
	}
}

// Two DIFFERENT identity providers asserting the same address must stay apart:
// each SSO provider is its own account-linking domain, so one IdP can never
// reach an account another IdP created.
func TestSAMLACSKeepsProvidersIsolated(t *testing.T) {
	env := newSSOEnv(t)
	env.createProvider(t, map[string]any{"domains": []string{"example.com"}})

	first := env.signIn(t, map[string]any{"domain": "example.com"},
		testSession("saml-subject-1", "alice@example.com", "Alice Anderson"))
	firstUser := userIDFromRedirect(t, env, first)

	// A second, independent identity provider on its own domain.
	env.idp = newSAMLTestIdP(t)
	env.createProvider(t, map[string]any{"domains": []string{"other.test"}})

	second := env.signIn(t, map[string]any{"domain": "other.test"},
		testSession("saml-subject-1", "alice@example.com", "Alice Anderson"))
	secondUser := userIDFromRedirect(t, env, second)

	if firstUser == secondUser {
		t.Fatal("a second identity provider took over an account created by the first")
	}
}
