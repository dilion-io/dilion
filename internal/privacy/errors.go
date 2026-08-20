package privacy

// Additional sentinel errors. service.go (the contract) defines ErrNotFound,
// ErrConflict, ErrIdempotencyReplay, ErrLegalHold and ErrPolicyViolation; the
// engine needs one more for malformed input so the API layer can map it to
// httpapi.CodeValidationFailed (422) instead of a 500.
const (
	ErrInvalidInput Error = "privacy: invalid input"
	// ErrUnsupported marks contract surface that wave 1 does not implement
	// (EXPORT request pipeline). Map to 501/validation_failed.
	ErrUnsupported Error = "privacy: unsupported operation"
)
