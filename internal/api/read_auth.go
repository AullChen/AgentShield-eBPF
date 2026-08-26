package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
)

type readAuthorizer struct {
	tokenHash [sha256.Size]byte
}

func newReadAuthorizer(token string) (readAuthorizer, error) {
	if len(token) < 24 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return readAuthorizer{}, errors.New("read token must contain 24-512 non-whitespace bytes")
	}
	return readAuthorizer{tokenHash: sha256.Sum256([]byte(token))}, nil
}

func (authorizer readAuthorizer) authorized(header string) bool {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(digest[:], authorizer.tokenHash[:]) == 1
}
