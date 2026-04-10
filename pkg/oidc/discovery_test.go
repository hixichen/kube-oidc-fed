package oidc

import (
	"strings"
	"testing"
)

func TestNewDiscoveryDocument(t *testing.T) {
	issuer := "https://example.com"
	doc := NewDiscoveryDocument(issuer)

	if doc.Issuer != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, doc.Issuer)
	}
	if doc.JWKSURI != issuer+"/.well-known/jwks.json" {
		t.Errorf("unexpected JWKS URI: %s", doc.JWKSURI)
	}
	if len(doc.ResponseTypesSupported) == 0 {
		t.Error("expected at least one response type")
	}
	if len(doc.SubjectTypesSupported) == 0 {
		t.Error("expected at least one subject type")
	}
	if len(doc.IDTokenSigningAlgValuesSupported) == 0 {
		t.Error("expected at least one signing alg")
	}
	found := false
	for _, alg := range doc.IDTokenSigningAlgValuesSupported {
		if strings.EqualFold(alg, "ES256") {
			found = true
		}
	}
	if !found {
		t.Error("expected ES256 in signing alg values")
	}
}

func TestNewDiscoveryDocumentTrailingSlash(t *testing.T) {
	// Should not double-slash
	doc := NewDiscoveryDocument("https://example.com/")
	if strings.Contains(doc.JWKSURI, "//./") {
		t.Errorf("unexpected double slash in JWKS URI: %s", doc.JWKSURI)
	}
}
