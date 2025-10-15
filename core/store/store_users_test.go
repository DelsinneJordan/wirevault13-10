package store_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"wirevault/core/models"
	"wirevault/core/store"
)

func newTestStore(t *testing.T) *store.Store {
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

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestNewCreatesDefaultOwner(t *testing.T) {
	st := newTestStore(t)
	users := st.ListUsers()
	if len(users) != 1 {
		t.Fatalf("expected 1 default user, got %d", len(users))
	}
	owner := users[0]
	if owner.Role != models.RoleOwner {
		t.Fatalf("expected role %q, got %q", models.RoleOwner, owner.Role)
	}
	if owner.Username != "owner" {
		t.Fatalf("expected owner username, got %q", owner.Username)
	}
	if owner.Email != "owner@wirevault.local" {
		t.Fatalf("unexpected owner email: %q", owner.Email)
	}
	if owner.PasswordHash != sha256Hex("admin") {
		t.Fatalf("unexpected default password hash: %q", owner.PasswordHash)
	}
	if owner.CreatedBy != owner.ID {
		t.Fatalf("expected CreatedBy to equal ID, got %q vs %q", owner.CreatedBy, owner.ID)
	}
	if owner.CreatedAt.IsZero() || owner.UpdatedAt.IsZero() {
		t.Fatalf("expected timestamps to be populated")
	}
}

func TestAuthenticateUserMatchesIdentifiers(t *testing.T) {
	st := newTestStore(t)
	user, err := st.SaveUser(&models.User{
		Username: "alice",
		Email:    "alice@example.com",
		Role:     models.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	if err := st.UpdateUserPassword(user.ID, "secret"); err != nil {
		t.Fatalf("failed to set password: %v", err)
	}

	cases := []struct {
		identifier string
		password   string
	}{
		{"alice", "secret"},
		{"ALICE", "secret"},
		{"alice@example.com", "secret"},
		{"ALICE@EXAMPLE.COM", "secret"},
	}
	for _, tc := range cases {
		if _, ok := st.AuthenticateUser(tc.identifier, tc.password); !ok {
			t.Fatalf("expected authentication to succeed for %q", tc.identifier)
		}
	}
	if _, ok := st.AuthenticateUser("alice", "wrong"); ok {
		t.Fatalf("expected wrong password to fail")
	}
	if _, ok := st.AuthenticateUser("unknown", "secret"); ok {
		t.Fatalf("expected unknown user to fail")
	}
}

func TestSaveUserPreservesMetadata(t *testing.T) {
	st := newTestStore(t)
	initial, err := st.SaveUser(&models.User{
		Username:     "sam",
		Email:        "sam@example.com",
		PasswordHash: "first-hash",
		Role:         models.RoleAdmin,
		CreatedBy:    "owner-id",
	})
	if err != nil {
		t.Fatalf("failed to save initial user: %v", err)
	}
	if initial.ID == "" {
		t.Fatalf("expected ID to be assigned")
	}
	if initial.CreatedAt.IsZero() || initial.UpdatedAt.IsZero() {
		t.Fatalf("expected timestamps to be populated")
	}

	beforeUpdatedAt := initial.UpdatedAt
	time.Sleep(time.Millisecond)

	updated, err := st.SaveUser(&models.User{
		ID:       initial.ID,
		Username: "sam",
		Email:    "sam+new@example.com",
		Role:     models.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}
	if updated.PasswordHash != "first-hash" {
		t.Fatalf("expected password hash to be preserved, got %q", updated.PasswordHash)
	}
	if updated.CreatedAt != initial.CreatedAt {
		t.Fatalf("expected CreatedAt to remain unchanged")
	}
	if updated.CreatedBy != initial.CreatedBy {
		t.Fatalf("expected CreatedBy to remain unchanged")
	}
	if !updated.UpdatedAt.After(beforeUpdatedAt) {
		t.Fatalf("expected UpdatedAt to advance")
	}
}

func TestIsUsernameAndEmailTaken(t *testing.T) {
	st := newTestStore(t)
	user, err := st.SaveUser(&models.User{
		Username: "casey",
		Email:    "casey@example.com",
		Role:     models.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	if !st.IsUsernameTaken("CASEY", "") {
		t.Fatalf("expected username to be taken")
	}
	if st.IsUsernameTaken("casey", user.ID) {
		t.Fatalf("expected username to be available when excluded")
	}
	if !st.IsEmailTaken("CASEY@EXAMPLE.COM", "") {
		t.Fatalf("expected email to be taken")
	}
	if st.IsEmailTaken("casey@example.com", user.ID) {
		t.Fatalf("expected email to be available when excluded")
	}
}

func TestDeleteUser(t *testing.T) {
	st := newTestStore(t)
	user, err := st.SaveUser(&models.User{
		Username: "temp",
		Email:    "temp@example.com",
		Role:     models.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	if err := st.DeleteUser(user.ID); err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}
	if _, err := st.GetUserByID(user.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestUpdateUserPasswordHashesValue(t *testing.T) {
	st := newTestStore(t)
	user, err := st.SaveUser(&models.User{
		Username: "drew",
		Email:    "drew@example.com",
		Role:     models.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	if err := st.UpdateUserPassword(user.ID, "secret"); err != nil {
		t.Fatalf("failed to update password: %v", err)
	}
	updated, err := st.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("failed to load user: %v", err)
	}
	if updated.PasswordHash != sha256Hex("secret") {
		t.Fatalf("expected hashed password, got %q", updated.PasswordHash)
	}
}

func TestUpdateSAMLSettingsAppliesDefaults(t *testing.T) {
	st := newTestStore(t)
	err := st.UpdateSAMLSettings(models.SAMLSettings{
		Enabled:           true,
		SPBaseURL:         " https://sp.example.com/ ",
		SPEntityID:        " sp-entity ",
		EmailAttribute:    "",
		UsernameAttribute: "",
	})
	if err != nil {
		t.Fatalf("failed to update SAML settings: %v", err)
	}
	saved := st.GetSAMLSettings()
	if saved.EmailAttribute != "email" {
		t.Fatalf("expected default email attribute, got %q", saved.EmailAttribute)
	}
	if saved.UsernameAttribute != "username" {
		t.Fatalf("expected default username attribute, got %q", saved.UsernameAttribute)
	}
	if saved.SPBaseURL != "https://sp.example.com/" {
		t.Fatalf("expected trimmed SP base URL, got %q", saved.SPBaseURL)
	}
	if saved.SPEntityID != "sp-entity" {
		t.Fatalf("expected trimmed SP entity ID, got %q", saved.SPEntityID)
	}
}
