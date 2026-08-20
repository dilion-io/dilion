package auth

// The SAML 2.0 Service Provider identity of this deployment: its key pair, its
// EntityID and the crewjam/saml ServiceProvider every SAML route is built from.
//
// Reproduces github.com/supabase/auth/internal/api/saml.go
// (newSAMLServiceProvider) and internal/conf/saml.go (SAMLConfiguration
// .Validate / .PopulateFields), which is where upstream turns
// GOTRUE_SAML_PRIVATE_KEY into an RSA key and a self-signed certificate.
//
// # The key
//
// Config.SAML.PrivateKey (GOTRUE_SAML_PRIVATE_KEY) is a standard-Base64 encoded
// PKCS#1 DER RSA private key — upstream's exact format, so an existing gotrue
// deployment can move its key over untouched:
//
//	openssl genrsa 2048 | openssl rsa -outform der | base64 -w 0
//
// # The certificate
//
// SAML uses the certificate purely as a vessel for the public key, so it is
// generated deterministically from fixed template values (serial 0, epoch
// notBefore, +200y notAfter, CN "SAML 2.0 Certificate for <host>", DNS name
// "_samlsp.<host>"). Those values are byte-for-byte upstream's: an operator who
// has already established a connection between an IdP and gotrue keeps the same
// certificate, and therefore the same fingerprint, after moving to Dilion.
// DO NOT change them.
//
// # The external URL (DEVIATION, documented)
//
// Upstream derives the SP's EntityID / ACS / metadata URLs from
// API_EXTERNAL_URL (or the SAML-specific override GOTRUE_SAML_EXTERNAL_URL).
// Dilion has no separate external-API URL in Config, and the package already
// resolves the same question the same way elsewhere: token.go builds the default
// OIDC issuer as SiteURL + IssuerPathSuffix ("/auth/v1"), because that is where
// dilion.go mounts this surface. samlExternalURL does exactly that, so
//
//	SITE_URL=https://api.example.com
//	  EntityID / metadata: https://api.example.com/auth/v1/sso/saml/metadata
//	  ACS:                 https://api.example.com/auth/v1/sso/saml/acs
//
// A deployment whose /auth/v1 lives on a different host than SITE_URL must
// front it with a reverse proxy at that path, exactly as it already must for the
// OIDC issuer and for the mailer's action links.

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// samlSPPathSuffix is the path segment appended to the external URL to form the
// SP's base URL. crewjam/samlsp then resolves "saml/metadata" and "saml/acs"
// against it, which is what produces upstream's /sso/saml/{metadata,acs}.
const samlSPPathSuffix = "sso/"

// samlExternalURL is the absolute base this SP's URLs are built on: SiteURL +
// "/auth/v1" (see the file comment). It never returns a trailing slash.
func samlExternalURL(cfg *Config) string {
	site := DefaultSiteURL
	if cfg != nil && strings.TrimSpace(cfg.SiteURL) != "" {
		site = strings.TrimSpace(cfg.SiteURL)
	}
	return strings.TrimRight(site, "/") + IssuerPathSuffix
}

// samlSPBaseURL is samlExternalURL as a *url.URL with the "sso/" suffix, i.e.
// upstream's `u.Path += "sso/"`.
func samlSPBaseURL(cfg *Config) (*url.URL, error) {
	u, err := url.ParseRequestURI(samlExternalURL(cfg))
	if err != nil {
		return nil, fmt.Errorf("auth: SAML external URL is not usable, check SITE_URL: %w", err)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.Path += samlSPPathSuffix
	return u, nil
}

// ---- key material ----------------------------------------------------------

// samlKeyMaterial is the SP's key pair: upstream's
// conf.SAMLConfiguration.{RSAPrivateKey, Certificate}.
type samlKeyMaterial struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// samlKeyCacheKey identifies one derivation. The private key is part of it so a
// re-configured deployment never serves a stale certificate; it never leaves the
// process.
type samlKeyCacheKey struct {
	privateKey string
	host       string
}

// samlKeyCache memoizes the (deterministic) certificate generation. Deriving it
// costs an RSA signature, and /sso/saml/metadata is a hot, unauthenticated
// endpoint.
var samlKeyCache sync.Map // samlKeyCacheKey -> *samlKeyMaterial

// samlKeys parses Config.SAML.PrivateKey and derives the SP certificate.
//
// The validation messages are upstream's, verbatim: an operator reading a
// Dilion boot failure finds the same strings gotrue would have printed.
func (a *api) samlKeys() (*samlKeyMaterial, error) {
	base, err := samlSPBaseURL(a.cfg)
	if err != nil {
		return nil, internalServerError("Error building the SAML Service Provider URL").withInternal(err)
	}
	// Upstream splits the port off the URL's Host; a host without one is used
	// verbatim (net.SplitHostPort errors and the value is kept).
	host := base.Host

	ck := samlKeyCacheKey{privateKey: a.cfg.SAML.PrivateKey, host: host}
	if cached, ok := samlKeyCache.Load(ck); ok {
		return cached.(*samlKeyMaterial), nil
	}

	km, err := deriveSAMLKeyMaterial(a.cfg.SAML.PrivateKey, host)
	if err != nil {
		return nil, internalServerError("Error loading the SAML private key").withInternal(err)
	}
	samlKeyCache.Store(ck, km)
	return km, nil
}

// deriveSAMLKeyMaterial is conf.SAMLConfiguration.Validate + PopulateFields.
func deriveSAMLKeyMaterial(privateKey, host string) (*samlKeyMaterial, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil {
		return nil, errors.New("SAML private key not in standard Base64 format")
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, errors.New("SAML private key not in PKCS#1 format")
	}
	if key.E != 0x10001 {
		return nil, errors.New("SAML private key should use the 65537 (0x10001) RSA public exponent")
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("SAML private key must be at least RSA 2048")
	}

	if h, _, serr := net.SplitHostPort(host); serr == nil {
		host = h
	}

	// UPSTREAM CONTRACT: every value in this template is fixed. Changing one
	// changes the published SAML certificate, which forces every operator to
	// re-establish the connection with their Identity Provider.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		IsCA:         false,
		DNSNames:     []string{"_samlsp." + host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.UnixMilli(0).UTC(),
		NotAfter:     time.UnixMilli(0).UTC().AddDate(200, 0, 0),
		Subject:      pkix.Name{CommonName: "SAML 2.0 Certificate for " + host},
	}
	// rand is nil on purpose (upstream does the same): RSA PKCS#1 v1.5 signing
	// is deterministic, so the certificate is byte-identical on every boot and
	// across every replica.
	certDER, err := x509.CreateCertificate(nil, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &samlKeyMaterial{key: key, cert: cert}, nil
}

// ---- service provider ------------------------------------------------------

// newSAMLServiceProvider is upstream's newSAMLServiceProvider.
//
// idpInitiated is false for an SP-initiated flow (the assertion must be an
// InResponseTo of an AuthnRequest we minted) and true only when the RelayState
// cannot identify a request — see saml_acs.go.
func (a *api) newSAMLServiceProvider(idp *saml.EntityDescriptor, idpInitiated bool) (*saml.ServiceProvider, error) {
	base, err := samlSPBaseURL(a.cfg)
	if err != nil {
		return nil, internalServerError("Error building the SAML Service Provider URL").withInternal(err)
	}
	km, err := a.samlKeys()
	if err != nil {
		return nil, err
	}

	sp := samlsp.DefaultServiceProvider(samlsp.Options{
		URL:               *base,
		Key:               km.key,
		Certificate:       km.cert,
		SignRequest:       true,
		AllowIDPInitiated: idpInitiated,
		IDPMetadata:       idp,
	})
	// Upstream requests `persistent` NameIDs by default; a provider may override
	// the AuthnRequest's NameIDPolicy through saml_providers.name_id_format.
	sp.AuthnNameIDFormat = saml.PersistentNameIDFormat
	return &sp, nil
}

// samlNameIDFormats are the formats POST /admin/sso/providers accepts for
// `name_id_format` and the ones the SP advertises in its metadata.
var samlNameIDFormats = []string{
	string(saml.PersistentNameIDFormat),
	string(saml.EmailAddressNameIDFormat),
	string(saml.TransientNameIDFormat),
	string(saml.UnspecifiedNameIDFormat),
}
