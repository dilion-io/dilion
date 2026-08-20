package auth

// Transactional email for the /auth/v1 email lifecycle.
//
// This is Dilion's equivalent of upstream's internal/api/mail.go +
// internal/mailer/templatemailer: it mints the OTP, persists its hash (legacy
// auth.users column AND auth.one_time_tokens, see ott.go), builds the action
// link exactly as upstream's templatemailer.getPath does, and hands the message
// to ports.Mailer.
//
// # Deviations from upstream, and why
//
//   - TEMPLATES. Upstream ships a template engine (GOTRUE_MAILER_TEMPLATES_*,
//     remote template URLs, a template cache). Dilion's Config has Subjects and
//     URLPaths but no template knobs, and ports.Mailer takes a rendered
//     (text, html) pair — so the bodies below are the upstream default
//     templates, rendered in Go. The link, the OTP and the subject — everything
//     a client or an operator can observe — are upstream-identical.
//
//   - MAILER MAX FREQUENCY. Upstream suppresses a repeat send inside
//     GOTRUE_SMTP_MAX_FREQUENCY (validateSentWithinFrequencyLimit against
//     users.*_sent_at). Dilion implements it as Mailer.MaxFrequency
//     (conf.go, default 1m) and measures it against
//     auth.one_time_tokens.updated_at instead of the legacy users.*_sent_at
//     columns — same instant, but keyed by (user_id, token_type), so the
//     suppression is per USER and per TOKEN TYPE even for the types that share
//     a legacy column (a magic link and a password reset both live in
//     recovery_token / recovery_sent_at). See checkMailFrequency below.
//
//   - SEND ORDER. Upstream mails first and rolls the token back if delivery
//     fails. Dilion persists first and then delivers, because the persistence
//     lives in the caller's transaction: a delivery failure aborts that
//     transaction, so nothing is left behind either way.
//
//   - A NIL ports.Mailer is a no-op (embedders may mount /auth/v1 without one);
//     a mailer that RETURNS AN ERROR fails the request with upstream's 500, so a
//     broken SMTP configuration cannot silently create unusable accounts.

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Email action types. The strings are upstream's mailer constants and are what
// the `type` parameter of a /verify link carries.
const (
	mailSignup             = "signup"
	mailRecovery           = "recovery"
	mailInvite             = "invite"
	mailMagicLink          = "magiclink"
	mailEmailChange        = "email_change"
	mailEmailOTP           = "email"
	mailEmailChangeCurrent = "email_change_current"
	mailEmailChangeNew     = "email_change_new"
	mailReauthentication   = "reauthentication"
)

// defaultSubjects mirrors templatemailer.defaultTemplateSubjects. Reauthentication
// is upstream's "{{ .Token }} is your verification code" with the OTP filled in.
var defaultSubjects = EmailContentConfig{
	Invite:           "You've been invited",
	Confirmation:     "Confirm your email address",
	Recovery:         "Reset your password",
	MagicLink:        "Your sign-in link",
	EmailChange:      "Confirm your new email address",
	Reauthentication: "%s is your verification code",
}

// subjectFor picks the configured subject for an action, falling back to
// upstream's default.
func (a *api) subjectFor(actionType, otp string) string {
	s := a.cfg.Mailer.Subjects
	d := defaultSubjects
	pick := func(configured, fallback string) string {
		if strings.TrimSpace(configured) != "" {
			return configured
		}
		return fallback
	}
	switch actionType {
	case mailInvite:
		return pick(s.Invite, d.Invite)
	case mailSignup:
		return pick(s.Confirmation, d.Confirmation)
	case mailRecovery:
		return pick(s.Recovery, d.Recovery)
	case mailMagicLink:
		return pick(s.MagicLink, d.MagicLink)
	case mailEmailChange:
		return pick(s.EmailChange, d.EmailChange)
	case mailReauthentication:
		if strings.TrimSpace(s.Reauthentication) != "" {
			return s.Reauthentication
		}
		return fmt.Sprintf(d.Reauthentication, otp)
	}
	return "Notification"
}

// urlPathFor picks the configured URL path for an action. Upstream routes
// magiclink through the RECOVERY path (templatemailer.GetEmailActionLink), which
// is reproduced here.
//
// The fallback is DefaultMailerURLPath ("/auth/v1/verify"), NOT upstream's
// "/verify": Dilion mounts this surface under /auth/v1, so upstream's default
// would produce a dead link. GOTRUE_MAILER_URLPATHS_* still overrides.
func (a *api) urlPathFor(actionType string) string {
	p := a.cfg.Mailer.URLPaths
	switch actionType {
	case mailInvite:
		return orDefault(p.Invite, DefaultMailerURLPath)
	case mailSignup:
		return orDefault(p.Confirmation, DefaultMailerURLPath)
	case mailRecovery, mailMagicLink:
		return orDefault(p.Recovery, DefaultMailerURLPath)
	case mailEmailChange, mailEmailChangeCurrent, mailEmailChangeNew:
		return orDefault(p.EmailChange, DefaultMailerURLPath)
	}
	return DefaultMailerURLPath
}

// ---- send frequency --------------------------------------------------------

// checkMailFrequency is upstream's validateSentWithinFrequencyLimit: at most one
// mail of a given type per user per Mailer.MaxFrequency.
//
// The clock it reads is auth.one_time_tokens.updated_at for
// (user_id, token_type) — the instant the live token of that kind was last
// issued, which is written in the same statement that sends the mail
// (issueOneTimeToken). No row means nothing was ever sent, which is never a
// violation.
//
// The 429 body is upstream's verbatim, including the seconds-remaining message,
// because clients display it:
//
//	{"code":429,"error_code":"over_email_send_rate_limit",
//	 "msg":"For security purposes, you can only request this after 42 seconds."}
//
// This is the per-USER throttle; the per-IP buckets of middleware.go
// (LimiterEmailSent, LimiterOTP, ...) are unrelated and both apply.
func (a *api) checkMailFrequency(ctx context.Context, q querier, userID, tokenType string) error {
	freq := a.cfg.Mailer.MaxFrequency
	if freq <= 0 {
		return nil
	}
	var updatedAt time.Time
	err := q.QueryRow(ctx, `
		select updated_at from auth.one_time_tokens
		where user_id = $1::uuid and token_type::text = $2`, userID, tokenType).Scan(&updatedAt)
	if err != nil {
		if isNoRows(err) {
			return nil
		}
		return internalServerError("Error checking email send frequency").withInternal(err)
	}

	sentAt := utcNaive(updatedAt)
	now := a.now()
	if !now.Before(sentAt.Add(freq)) {
		return nil
	}
	left := int64(sentAt.Add(freq).Sub(now) / time.Second)
	return httpError(http.StatusTooManyRequests, ErrorCodeOverEmailSendRateLimit,
		"For security purposes, you can only request this after %d seconds.", left)
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// ---- link building ---------------------------------------------------------

// externalHost is upstream's getExternalHost: the absolute base a link in an
// email resolves against.
//
// The request's own Host is used when it is either the SiteURL host or one of
// Mailer.ExternalHosts — otherwise a forged Host header could plant an
// attacker's domain into a confirmation link. Anything else falls back to
// SiteURL.
func (a *api) externalHost(r *http.Request) *url.URL {
	site, err := url.Parse(a.cfg.SiteURL)
	if err != nil || site.Host == "" {
		site = &url.URL{Scheme: "http", Host: "localhost"}
	}
	host := r.Host
	if host == "" {
		return site
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if fw := r.Header.Get("X-Forwarded-Proto"); fw != "" {
		scheme = fw
	}
	candidate := &url.URL{Scheme: scheme, Host: host}
	if strings.EqualFold(host, site.Host) {
		return candidate
	}
	for _, allowed := range a.cfg.Mailer.ExternalHosts {
		if strings.EqualFold(strings.TrimSpace(allowed), host) {
			return candidate
		}
	}
	return site
}

// actionLinkPath is upstream's templatemailer.getPath: the configured URL path
// with `token`, `type` and `redirect_to` appended, in that fixed order (upstream
// builds RawQuery by hand, so the parameter ORDER is part of the contract).
func actionLinkPath(urlPath, token, actionType, redirectTo string) (*url.URL, error) {
	p := &url.URL{}
	if urlPath != "" {
		parsed, err := url.Parse(urlPath)
		if err != nil {
			return nil, err
		}
		p = parsed
	}
	p.RawQuery = fmt.Sprintf("token=%s&type=%s&redirect_to=%s",
		url.QueryEscape(token), url.QueryEscape(actionType), encodeRedirectURL(redirectTo))
	return p, nil
}

// encodeRedirectURL is upstream's encodeRedirectURL: a redirect that already
// looks encoded is taken as-is, one that contains &, = or # is escaped.
func encodeRedirectURL(redirectTo string) string {
	if redirectTo != "" && strings.ContainsAny(redirectTo, "&=#") {
		return url.QueryEscape(redirectTo)
	}
	return redirectTo
}

// actionLink builds the absolute link that goes into an email — upstream's
// Mailer.GetEmailActionLink.
func (a *api) actionLink(r *http.Request, actionType, token, linkType, redirectTo string) (string, error) {
	p, err := actionLinkPath(a.urlPathFor(actionType), token, linkType, redirectTo)
	if err != nil {
		return "", err
	}
	return a.externalHost(r).ResolveReference(p).String(), nil
}

// referrerFor is upstream's utilities.GetReferrer: the caller's redirect_to when
// the allow-list admits it, else the Referer header when it does, else SiteURL.
func (a *api) referrerFor(r *http.Request, redirectTo string) string {
	return a.cfg.RedirectURLOrSiteURL(redirectTo, r.Referer())
}

// ---- delivery --------------------------------------------------------------

// deliver renders and sends one message. A nil mailer is a no-op; a mailer error
// is surfaced as upstream's 500 so a broken SMTP setup cannot silently create
// unusable accounts.
func (a *api) deliver(ctx context.Context, to, subject, text, htmlBody, what string) error {
	if a.mailer == nil {
		a.log.WarnContext(ctx, "auth: no mailer configured, email not sent",
			"type", what, "subject", subject)
		return nil
	}
	if to == "" {
		return badRequestError(ErrorCodeValidationFailed, "An email address is required")
	}
	if err := a.mailer.Send(ctx, to, subject, text, htmlBody); err != nil {
		return internalServerError("Error sending %s email", what).withInternal(err)
	}
	return nil
}

// renderActionMail produces the (text, html) pair for a link-carrying email.
// The bodies reproduce upstream's default templates: a headline, one sentence,
// the link, and the OTP so a client that prefers a typed code has it.
func renderActionMail(headline, sentence, link, otp string) (string, string) {
	var text strings.Builder
	text.WriteString(headline + "\n\n" + sentence + "\n\n")
	if link != "" {
		text.WriteString(link + "\n\n")
	}
	if otp != "" {
		text.WriteString("Or enter this code: " + otp + "\n")
	}

	var body strings.Builder
	fmt.Fprintf(&body, "<h2>%s</h2>\n<p>%s</p>\n", html.EscapeString(headline), html.EscapeString(sentence))
	if link != "" {
		fmt.Fprintf(&body, "<p><a href=\"%s\">%s</a></p>\n", html.EscapeString(link), html.EscapeString(headline))
	}
	if otp != "" {
		fmt.Fprintf(&body, "<p>Or enter this code: <strong>%s</strong></p>\n", html.EscapeString(otp))
	}
	return text.String(), body.String()
}

// ---- the six flows ---------------------------------------------------------

// mailToken is what a send produces: the OTP that was mailed, the hash that was
// stored (prefixed for PKCE) and the link that was built. /admin/generate_link
// reports all three; the ordinary endpoints report none of them.
type mailToken struct {
	OTP        string
	Hash       string
	Link       string
	RedirectTo string
}

// sendConfirmation is upstream's sendConfirmation: the signup confirmation mail.
// Persists confirmation_token / confirmation_sent_at and the ConfirmationToken
// one-time token, then mails the link.
func (a *api) sendConfirmation(ctx context.Context, tx querier, r *http.Request, u *User, redirectTo string, pkce bool) (*mailToken, error) {
	return a.sendLinkMail(ctx, tx, r, sendLinkParams{
		user:        u,
		recipient:   u.Email,
		relatesTo:   u.Email,
		actionType:  mailSignup,
		linkType:    mailSignup,
		tokenColumn: "confirmation_token",
		sentColumn:  "confirmation_sent_at",
		tokenType:   tokenTypeConfirmation,
		redirectTo:  redirectTo,
		pkce:        pkce,
		headline:    "Confirm your email address",
		sentence:    "Follow the link below to confirm this email address and finish signing up.",
		what:        "confirmation",
	})
}

// sendInvite is upstream's sendInvite. It additionally stamps users.invited_at.
func (a *api) sendInvite(ctx context.Context, tx querier, r *http.Request, u *User, redirectTo string) (*mailToken, error) {
	tok, err := a.sendLinkMail(ctx, tx, r, sendLinkParams{
		user:        u,
		recipient:   u.Email,
		relatesTo:   u.Email,
		actionType:  mailInvite,
		linkType:    mailInvite,
		tokenColumn: "confirmation_token",
		sentColumn:  "confirmation_sent_at",
		extraSet:    map[string]any{"invited_at": a.now()},
		tokenType:   tokenTypeConfirmation,
		redirectTo:  redirectTo,
		// Upstream never PKCE-prefixes an invite token.
		pkce: false,
		// Upstream's sendInvite has no frequency check (see sendLinkParams).
		skipFrequency: true,
		headline:      "You've been invited",
		sentence:      "You've been invited to create an account. Follow the link below to accept.",
		what:          "invite",
	})
	return tok, err
}

// sendPasswordRecovery is upstream's sendPasswordRecovery.
func (a *api) sendPasswordRecovery(ctx context.Context, tx querier, r *http.Request, u *User, redirectTo string, pkce bool) (*mailToken, error) {
	return a.sendLinkMail(ctx, tx, r, sendLinkParams{
		user:        u,
		recipient:   u.Email,
		relatesTo:   u.Email,
		actionType:  mailRecovery,
		linkType:    mailRecovery,
		tokenColumn: "recovery_token",
		sentColumn:  "recovery_sent_at",
		tokenType:   tokenTypeRecovery,
		redirectTo:  redirectTo,
		pkce:        pkce,
		headline:    "Reset your password",
		sentence:    "We received a request to reset your password. Follow the link below to choose a new one.",
		what:        "recovery",
	})
}

// sendMagicLink is upstream's sendMagicLink. A magic link IS a recovery token
// with a different template — it reuses recovery_token / recovery_sent_at, which
// is also why requesting one invalidates a pending password reset.
func (a *api) sendMagicLink(ctx context.Context, tx querier, r *http.Request, u *User, redirectTo string, pkce bool) (*mailToken, error) {
	return a.sendLinkMail(ctx, tx, r, sendLinkParams{
		user:        u,
		recipient:   u.Email,
		relatesTo:   u.Email,
		actionType:  mailMagicLink,
		linkType:    mailMagicLink,
		tokenColumn: "recovery_token",
		sentColumn:  "recovery_sent_at",
		tokenType:   tokenTypeRecovery,
		redirectTo:  redirectTo,
		pkce:        pkce,
		headline:    "Your sign-in link",
		sentence:    "Follow the link below to sign in. This link expires shortly and can only be used once.",
		what:        "magic link",
	})
}

// sendReauthentication is upstream's sendReauthenticationOtp: a bare 6-digit
// code, no link — the code is posted back as PUT /user {"nonce": ...}.
func (a *api) sendReauthentication(ctx context.Context, tx querier, u *User) error {
	if err := a.checkMailFrequency(ctx, tx, u.ID, tokenTypeReauthentication); err != nil {
		return err
	}
	otp, err := generateOTP(a.cfg.Mailer.OTPLength)
	if err != nil {
		return internalServerError("Error generating one-time token").withInternal(err)
	}
	hash := generateTokenHash(u.Email, otp)
	now := a.now()

	if _, err := updateUserFields(ctx, tx, u.ID, now, map[string]any{
		"reauthentication_token":   hash,
		"reauthentication_sent_at": now,
	}); err != nil {
		return internalServerError("Error sending reauthentication email").withInternal(err)
	}
	if err := issueOneTimeToken(ctx, tx, u.ID, u.Email, hash, tokenTypeReauthentication, now); err != nil {
		return internalServerError("Error sending reauthentication email").withInternal(err)
	}

	text, htmlBody := renderActionMail("Your verification code",
		"Use the code below to verify your identity. It expires shortly.", "", otp)
	return a.deliver(ctx, u.Email, a.subjectFor(mailReauthentication, otp), text, htmlBody, "reauthentication")
}

// sendEmailChange is upstream's sendEmailChange.
//
// It always mints a token for the NEW address (email_change_token_new). When
// Mailer.SecureEmailChangeEnabled is on AND the account already has an address,
// it ALSO mints one for the CURRENT address (email_change_token_current) and
// mails both — the change only lands once both have been followed
// (email_change_confirm_status, see verify.go).
func (a *api) sendEmailChange(ctx context.Context, tx querier, r *http.Request, u *User, newEmail, redirectTo string, pkce bool) (*mailToken, *mailToken, error) {
	if err := a.checkMailFrequency(ctx, tx, u.ID, tokenTypeEmailChangeNew); err != nil {
		return nil, nil, err
	}
	otpNew, err := generateOTP(a.cfg.Mailer.OTPLength)
	if err != nil {
		return nil, nil, internalServerError("Error generating one-time token").withInternal(err)
	}
	hashNew := addFlowPrefix(generateTokenHash(newEmail, otpNew), pkce)

	otpCurrent, hashCurrent := "", ""
	secure := a.cfg.Mailer.SecureEmailChangeEnabled && u.Email != ""
	if secure {
		otpCurrent, err = generateOTP(a.cfg.Mailer.OTPLength)
		if err != nil {
			return nil, nil, internalServerError("Error generating one-time token").withInternal(err)
		}
		hashCurrent = addFlowPrefix(generateTokenHash(u.Email, otpCurrent), pkce)
	}

	now := a.now()
	if _, err := updateUserFields(ctx, tx, u.ID, now, map[string]any{
		"email_change":                newEmail,
		"email_change_token_new":      hashNew,
		"email_change_token_current":  hashCurrent,
		"email_change_sent_at":        now,
		"email_change_confirm_status": zeroConfirmation,
	}); err != nil {
		if isUniqueViolation(err) {
			return nil, nil, unprocessableEntityError(ErrorCodeEmailExists,
				"A user with this email address has already been registered")
		}
		return nil, nil, internalServerError("Error sending email change email").withInternal(err)
	}
	u.EmailChange = newEmail
	u.EmailChangeSentAt = &now

	if err := issueOneTimeToken(ctx, tx, u.ID, newEmail, hashNew, tokenTypeEmailChangeNew, now); err != nil {
		return nil, nil, internalServerError("Error sending email change email").withInternal(err)
	}
	if hashCurrent != "" {
		if err := issueOneTimeToken(ctx, tx, u.ID, u.Email, hashCurrent, tokenTypeEmailChangeCurrent, now); err != nil {
			return nil, nil, internalServerError("Error sending email change email").withInternal(err)
		}
	}

	referrer := a.referrerFor(r, redirectTo)
	subject := a.subjectFor(mailEmailChange, "")

	linkNew, err := a.actionLink(r, mailEmailChange, hashNew, mailEmailChange, referrer)
	if err != nil {
		return nil, nil, internalServerError("Error building email action link").withInternal(err)
	}
	text, htmlBody := renderActionMail("Confirm your new email address",
		"Follow the link below to confirm "+newEmail+" as your new email address.", linkNew, otpNew)
	if err := a.deliver(ctx, newEmail, subject, text, htmlBody, "email change"); err != nil {
		return nil, nil, err
	}
	tokNew := &mailToken{OTP: otpNew, Hash: hashNew, Link: linkNew, RedirectTo: referrer}

	if hashCurrent == "" {
		return tokNew, nil, nil
	}

	linkCurrent, err := a.actionLink(r, mailEmailChange, hashCurrent, mailEmailChange, referrer)
	if err != nil {
		return nil, nil, internalServerError("Error building email action link").withInternal(err)
	}
	text, htmlBody = renderActionMail("Confirm your new email address",
		"Follow the link below to confirm "+newEmail+" as your new email address.", linkCurrent, otpCurrent)
	if err := a.deliver(ctx, u.Email, subject, text, htmlBody, "email change"); err != nil {
		return nil, nil, err
	}
	return tokNew, &mailToken{OTP: otpCurrent, Hash: hashCurrent, Link: linkCurrent, RedirectTo: referrer}, nil
}

// ---- the shared body of the link-carrying flows ---------------------------

type sendLinkParams struct {
	user      *User
	recipient string // who receives the mail
	relatesTo string // what the token is bound to (one_time_tokens.relates_to)

	actionType string // picks the subject and the URL path
	linkType   string // the `type` parameter of the link

	tokenColumn string         // legacy auth.users column to dual-write
	sentColumn  string         // its *_sent_at partner
	extraSet    map[string]any // additional columns (invited_at)
	tokenType   string         // auth.one_time_tokens.token_type

	redirectTo string
	pkce       bool

	// skipFrequency exempts the send from Mailer.MaxFrequency. Only the invite
	// flow sets it, matching upstream: sendInvite is the one send function with
	// no validateSentWithinFrequencyLimit call, because an invite is issued by
	// an ADMIN, not by the anonymous caller the throttle protects against.
	skipFrequency bool

	headline string
	sentence string
	what     string // used in the error message and the log line
}

func (a *api) sendLinkMail(ctx context.Context, tx querier, r *http.Request, p sendLinkParams) (*mailToken, error) {
	if !p.skipFrequency {
		if err := a.checkMailFrequency(ctx, tx, p.user.ID, p.tokenType); err != nil {
			return nil, err
		}
	}
	otp, err := generateOTP(a.cfg.Mailer.OTPLength)
	if err != nil {
		return nil, internalServerError("Error generating one-time token").withInternal(err)
	}
	hash := addFlowPrefix(generateTokenHash(p.relatesTo, otp), p.pkce)
	now := a.now()

	set := map[string]any{p.tokenColumn: hash, p.sentColumn: now}
	for k, v := range p.extraSet {
		set[k] = v
	}
	if _, err := updateUserFields(ctx, tx, p.user.ID, now, set); err != nil {
		return nil, internalServerError("Error sending %s email", p.what).withInternal(err)
	}
	if err := issueOneTimeToken(ctx, tx, p.user.ID, p.relatesTo, hash, p.tokenType, now); err != nil {
		return nil, internalServerError("Error sending %s email", p.what).withInternal(err)
	}
	// Keep the in-memory user consistent with what was just written: /verify
	// reads these to decide expiry.
	switch p.sentColumn {
	case "confirmation_sent_at":
		p.user.ConfirmationSentAt = &now
	case "recovery_sent_at":
		p.user.RecoverySentAt = &now
	}
	if _, ok := p.extraSet["invited_at"]; ok {
		p.user.InvitedAt = &now
	}

	referrer := a.referrerFor(r, p.redirectTo)
	link, err := a.actionLink(r, p.actionType, hash, p.linkType, referrer)
	if err != nil {
		return nil, internalServerError("Error building email action link").withInternal(err)
	}

	text, htmlBody := renderActionMail(p.headline, p.sentence, link, otp)
	if err := a.deliver(ctx, p.recipient, a.subjectFor(p.actionType, otp), text, htmlBody, p.what); err != nil {
		return nil, err
	}
	return &mailToken{OTP: otp, Hash: hash, Link: link, RedirectTo: referrer}, nil
}

// mailSentAt reports when the token guarding an action type was last sent; it is
// the clock /verify measures Mailer.OTPExp against.
func mailSentAt(u *User, actionType string) *time.Time {
	switch actionType {
	case mailSignup, mailInvite:
		return u.ConfirmationSentAt
	case mailRecovery, mailMagicLink:
		return u.RecoverySentAt
	case mailEmailChange:
		return u.EmailChangeSentAt
	case mailReauthentication:
		return u.ReauthenticationSentAt
	}
	return nil
}
