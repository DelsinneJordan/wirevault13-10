package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"wirevault/core/models"
	"wirevault/core/store"
)

func newHandlerTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "data.json")
	mediaDir := filepath.Join(dir, "media")
	st, err := store.New(dataPath, mediaDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	return st
}

func TestHandleUpdatePublicURLFormRequiresOwner(t *testing.T) {
	st := newHandlerTestStore(t)
	h := &Handler{Store: st}
	initialURL := st.GetPublicBaseURL()

	admin := &models.User{Role: models.RoleAdmin}
	adminReq := httptest.NewRequest(http.MethodPost, "/admin/settings", nil)
	adminValues := url.Values{"public_url": {"https://example.com"}}
	adminReq.Form = adminValues
	adminReq.PostForm = adminValues

	msg, msgType, errMsg := h.handleUpdatePublicURLForm(admin, adminReq)
	if errMsg == "" {
		t.Fatalf("expected permission error for admin, got none (msg=%q, type=%q)", msg, msgType)
	}
	if got := st.GetPublicBaseURL(); got != initialURL {
		t.Fatalf("expected base URL to remain %q, got %q", initialURL, got)
	}

	owner := &models.User{Role: models.RoleOwner}
	ownerReq := httptest.NewRequest(http.MethodPost, "/admin/settings", nil)
	ownerValues := url.Values{"public_url": {"https://example.com"}}
	ownerReq.Form = ownerValues
	ownerReq.PostForm = ownerValues

	msg, msgType, errMsg = h.handleUpdatePublicURLForm(owner, ownerReq)
	if errMsg != "" {
		t.Fatalf("unexpected error for owner: %s", errMsg)
	}
	if msg != "Base URL updated" || msgType != "success" {
		t.Fatalf("unexpected response: msg=%q type=%q", msg, msgType)
	}
	if got := st.GetPublicBaseURL(); got != "https://example.com" {
		t.Fatalf("expected updated base URL, got %q", got)
	}
}

func TestHandleUpdateSAMLFormRequiresOwner(t *testing.T) {
	st := newHandlerTestStore(t)
	h := &Handler{Store: st}
	admin := &models.User{Role: models.RoleAdmin}

	adminReq := httptest.NewRequest(http.MethodPost, "/admin/settings", nil)
	adminValues := url.Values{
		"sp_base_url":         {"https://sso.example.com/app"},
		"sp_entity_id":        {"urn:test:app"},
		"email_attribute":     {"mail"},
		"username_attribute":  {"uid"},
		"idp_metadata_url":    {"https://idp.example.com/metadata.xml"},
		"allow_idp_initiated": {"on"},
	}
	adminReq.Form = adminValues
	adminReq.PostForm = adminValues

	initial := st.GetSAMLSettings()

	msg, msgType, errMsg := h.handleUpdateSAMLForm(admin, adminReq)
	if errMsg == "" {
		t.Fatalf("expected permission error for admin, got none (msg=%q, type=%q)", msg, msgType)
	}
	saved := st.GetSAMLSettings()
	if saved != initial {
		t.Fatalf("expected SAML settings to remain unchanged")
	}

	owner := &models.User{Role: models.RoleOwner}
	ownerReq := httptest.NewRequest(http.MethodPost, "/admin/settings", nil)
	ownerValues := url.Values{
		"sp_base_url":        {"https://new.example.com/base"},
		"sp_entity_id":       {"new-entity"},
		"email_attribute":    {"mail"},
		"username_attribute": {"uid"},
		"idp_metadata_url":   {"https://idp.example.com/meta"},
	}
	ownerReq.Form = ownerValues
	ownerReq.PostForm = ownerValues

	msg, msgType, errMsg = h.handleUpdateSAMLForm(owner, ownerReq)
	if errMsg != "" {
		t.Fatalf("unexpected error for owner: %s", errMsg)
	}
	if msg != "SSO disabled" || msgType != "success" {
		t.Fatalf("unexpected response: msg=%q type=%q", msg, msgType)
	}
	updated := st.GetSAMLSettings()
	if updated.Enabled {
		t.Fatalf("expected SSO to remain disabled")
	}
	if updated.AllowIDPInitiated {
		t.Fatalf("expected allow IdP initiated flag to be false")
	}
	if updated.SPBaseURL != "https://new.example.com/base" {
		t.Fatalf("unexpected SP base URL: %q", updated.SPBaseURL)
	}
	if updated.SPEntityID != "new-entity" {
		t.Fatalf("unexpected SP entity ID: %q", updated.SPEntityID)
	}
	if updated.EmailAttribute != "mail" {
		t.Fatalf("unexpected email attribute: %q", updated.EmailAttribute)
	}
	if updated.UsernameAttribute != "uid" {
		t.Fatalf("unexpected username attribute: %q", updated.UsernameAttribute)
	}
	if updated.IDPMetadataURL != "https://idp.example.com/meta" {
		t.Fatalf("unexpected IdP metadata URL: %q", updated.IDPMetadataURL)
	}
}
