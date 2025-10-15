package store

import (
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wirevault/core/models"
)

type Store struct {
	mu       sync.RWMutex
	path     string
	mediaDir string
	data     *models.AppData
}

var ErrNotFound = errors.New("not found")

func New(path string, mediaDir string) (*Store, error) {
	st := &Store{path: path, mediaDir: mediaDir}
	if err := st.load(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	_, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		hash := defaultPasswordHash()
		owner := defaultOwnerUser(hash)
		s.data = &models.AppData{
			Sites:  []*models.Site{},
			Tokens: []*models.QRToken{},
			Users:  []*models.User{owner},
			Config: models.Config{
				AdminPasswordHash: hash,
				PublicBaseURL:     "https://wirevault.example.com",
				SAML: models.SAMLSettings{
					EmailAttribute:    "email",
					UsernameAttribute: "username",
					AllowIDPInitiated: true,
				},
			},
		}
		return s.saveLocked()
	}
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var data models.AppData
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	migrated := false
	if data.Config.PublicBaseURL == "" {
		data.Config.PublicBaseURL = "https://wirevault.example.com"
		migrated = true
	}
	if data.Config.AdminPasswordHash == "" {
		data.Config.AdminPasswordHash = defaultPasswordHash()
		migrated = true
	}
	if data.Users == nil {
		data.Users = []*models.User{}
		migrated = true
	}
	if len(data.Users) == 0 {
		hash := data.Config.AdminPasswordHash
		if hash == "" {
			hash = defaultPasswordHash()
		}
		owner := defaultOwnerUser(hash)
		data.Users = []*models.User{owner}
		migrated = true
	}
	if data.Config.SAML.EmailAttribute == "" {
		data.Config.SAML.EmailAttribute = "email"
		migrated = true
	}
	if data.Config.SAML.UsernameAttribute == "" {
		data.Config.SAML.UsernameAttribute = "username"
		migrated = true
	}
	s.data = &data
	if migrated {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func defaultPasswordHash() string {
	return hashPassword("admin")
}

func defaultOwnerUser(hash string) *models.User {
	now := time.Now()
	id := NewID()
	return &models.User{
		ID:           id,
		Username:     "owner",
		Email:        "owner@wirevault.local",
		PasswordHash: hash,
		Role:         models.RoleOwner,
		CreatedBy:    id,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func hashPassword(password string) string {
	sum := sha256Sum(password)
	return fmt.Sprintf("%x", sum)
}

func sha256Sum(input string) [32]byte {
	return sha256.Sum256([]byte(input))
}

func (s *Store) AuthenticateUser(identifier, password string) (*models.User, bool) {
	ident := normalizeIdentifier(identifier)
	if ident == "" {
		return nil, false
	}
	hash := hashPassword(password)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.data.Users {
		if matchesIdentifier(user, ident) && user.PasswordHash != "" && user.PasswordHash == hash {
			return cloneUser(user), true
		}
	}
	return nil, false
}

func (s *Store) UpdateUserPassword(userID, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.data.Users {
		if user.ID == userID {
			user.PasswordHash = hashPassword(password)
			user.UpdatedAt = time.Now()
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) GetPublicBaseURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Config.PublicBaseURL
}

func (s *Store) SetPublicBaseURL(url string) error {
	s.mu.Lock()
	s.data.Config.PublicBaseURL = url
	s.mu.Unlock()
	return s.save()
}

func (s *Store) ListUsers() []*models.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]*models.User, len(s.data.Users))
	for i, user := range s.data.Users {
		users[i] = cloneUser(user)
	}
	return users
}

func (s *Store) GetUserByID(id string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.data.Users {
		if user.ID == id {
			return cloneUser(user), nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) GetUserByIdentifier(identifier string) (*models.User, error) {
	ident := normalizeIdentifier(identifier)
	if ident == "" {
		return nil, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.data.Users {
		if matchesIdentifier(user, ident) {
			return cloneUser(user), nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) SaveUser(user *models.User) (*models.User, error) {
	if user == nil {
		return nil, errors.New("user is nil")
	}
	copyUser := cloneUser(user)
	now := time.Now()
	isNew := copyUser.ID == ""
	if isNew {
		copyUser.ID = NewID()
	}
	if copyUser.CreatedAt.IsZero() {
		copyUser.CreatedAt = now
	}
	if copyUser.CreatedBy == "" && isNew {
		copyUser.CreatedBy = copyUser.ID
	}
	copyUser.UpdatedAt = now

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.data.Users {
		if existing.ID == copyUser.ID {
			copyUser.CreatedAt = existing.CreatedAt
			if copyUser.CreatedBy == "" {
				copyUser.CreatedBy = existing.CreatedBy
			}
			if copyUser.PasswordHash == "" {
				copyUser.PasswordHash = existing.PasswordHash
			}
			s.data.Users[i] = copyUser
			if err := s.saveLocked(); err != nil {
				return nil, err
			}
			return cloneUser(copyUser), nil
		}
	}
	s.data.Users = append(s.data.Users, copyUser)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return cloneUser(copyUser), nil
}

func (s *Store) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.data.Users[:0]
	removed := false
	for _, user := range s.data.Users {
		if user.ID == id {
			removed = true
			continue
		}
		filtered = append(filtered, user)
	}
	if !removed {
		return ErrNotFound
	}
	s.data.Users = filtered
	return s.saveLocked()
}

func (s *Store) IsUsernameTaken(username, excludeID string) bool {
	normalized := normalizeIdentifier(username)
	if normalized == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.data.Users {
		if user.ID == excludeID {
			continue
		}
		if normalizeIdentifier(user.Username) == normalized {
			return true
		}
	}
	return false
}

func (s *Store) IsEmailTaken(email, excludeID string) bool {
	normalized := normalizeIdentifier(email)
	if normalized == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.data.Users {
		if user.ID == excludeID {
			continue
		}
		if normalizeIdentifier(user.Email) == normalized {
			return true
		}
	}
	return false
}

func (s *Store) GetSAMLSettings() models.SAMLSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Config.SAML
}

func (s *Store) UpdateSAMLSettings(settings models.SAMLSettings) error {
	settings.SPBaseURL = strings.TrimSpace(settings.SPBaseURL)
	settings.SPEntityID = strings.TrimSpace(settings.SPEntityID)
	settings.SPKeyPEM = strings.TrimSpace(settings.SPKeyPEM)
	settings.SPCertificatePEM = strings.TrimSpace(settings.SPCertificatePEM)
	settings.IDPMetadataURL = strings.TrimSpace(settings.IDPMetadataURL)
	settings.IDPMetadataXML = strings.TrimSpace(settings.IDPMetadataXML)
	settings.EmailAttribute = strings.TrimSpace(settings.EmailAttribute)
	settings.UsernameAttribute = strings.TrimSpace(settings.UsernameAttribute)
	if settings.EmailAttribute == "" {
		settings.EmailAttribute = "email"
	}
	if settings.UsernameAttribute == "" {
		settings.UsernameAttribute = "username"
	}
	s.mu.Lock()
	s.data.Config.SAML = settings
	s.mu.Unlock()
	return s.save()
}

func (s *Store) ListSites() []*models.Site {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sites := make([]*models.Site, len(s.data.Sites))
	copy(sites, s.data.Sites)
	return sites
}

func (s *Store) GetSiteByID(id string) (*models.Site, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, site := range s.data.Sites {
		if site.ID == id {
			return cloneSite(site), nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) GetSiteByShortID(shortID string) (*models.Site, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, site := range s.data.Sites {
		if site.ShortID == shortID {
			return cloneSite(site), nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) SaveSite(site *models.Site) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.data.Sites {
		if existing.ID == site.ID {
			s.data.Sites[i] = cloneSite(site)
			return s.saveLocked()
		}
	}
	s.data.Sites = append(s.data.Sites, cloneSite(site))
	return s.saveLocked()
}

func (s *Store) IsSiteShortIDTaken(shortID, excludeID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, site := range s.data.Sites {
		if site.ShortID == shortID && site.ID != excludeID {
			return true
		}
	}
	return false
}

func (s *Store) DeleteSite(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.data.Sites[:0]
	for _, site := range s.data.Sites {
		if site.ID == id {
			continue
		}
		filtered = append(filtered, site)
	}
	s.data.Sites = filtered
	for _, token := range s.data.Tokens {
		if token.SiteID == id {
			token.SiteID = ""
			token.Status = models.TokenUnassigned
		}
	}
	return s.saveLocked()
}

func (s *Store) ListTokens() []*models.QRToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens := make([]*models.QRToken, len(s.data.Tokens))
	copy(tokens, s.data.Tokens)
	return tokens
}

func (s *Store) SaveToken(token *models.QRToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.data.Tokens {
		if existing.ID == token.ID {
			s.data.Tokens[i] = cloneToken(token)
			return s.saveLocked()
		}
	}
	s.data.Tokens = append(s.data.Tokens, cloneToken(token))
	return s.saveLocked()
}

func (s *Store) IsTokenShortIDTaken(shortID, excludeID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, token := range s.data.Tokens {
		if token.ShortID == shortID && token.ID != excludeID {
			return true
		}
	}
	return false
}

func (s *Store) GetTokenByShortID(shortID string) (*models.QRToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, token := range s.data.Tokens {
		if token.ShortID == shortID {
			return cloneToken(token), nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) GetTokenByID(id string) (*models.QRToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, token := range s.data.Tokens {
		if token.ID == id {
			return cloneToken(token), nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) AssignTokenToSite(tokenID, siteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.data.Tokens {
		if token.ID == tokenID {
			token.SiteID = siteID
			if token.Status != models.TokenRetired {
				token.Status = models.TokenAssigned
			}
			token.UpdatedAt = time.Now()
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) RemoveTokenFromSite(tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.data.Tokens {
		if token.ID == tokenID {
			token.SiteID = ""
			if token.Status != models.TokenRetired {
				token.Status = models.TokenUnassigned
			}
			token.UpdatedAt = time.Now()
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) DeleteToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.data.Tokens[:0]
	for _, token := range s.data.Tokens {
		if token.ID == id {
			continue
		}
		filtered = append(filtered, token)
	}
	s.data.Tokens = filtered
	return s.saveLocked()
}

func cloneSite(site *models.Site) *models.Site {
	if site == nil {
		return nil
	}
	copySite := *site
	copySite.Boards = make([]*models.Board, len(site.Boards))
	for i, board := range site.Boards {
		copySite.Boards[i] = cloneBoard(board)
	}
	copySite.Appliances = make([]*models.Appliance, len(site.Appliances))
	for i, app := range site.Appliances {
		copySite.Appliances[i] = cloneAppliance(app)
	}
	return &copySite
}

func cloneBoard(board *models.Board) *models.Board {
	if board == nil {
		return nil
	}
	copyBoard := *board
	copyBoard.Documents = make([]*models.Document, len(board.Documents))
	for i, doc := range board.Documents {
		copyBoard.Documents[i] = cloneDocument(doc)
	}
	return &copyBoard
}

func cloneAppliance(appliance *models.Appliance) *models.Appliance {
	if appliance == nil {
		return nil
	}
	copyApp := *appliance
	copyApp.Documents = make([]*models.Document, len(appliance.Documents))
	for i, doc := range appliance.Documents {
		copyApp.Documents[i] = cloneDocument(doc)
	}
	return &copyApp
}

func cloneDocument(doc *models.Document) *models.Document {
	if doc == nil {
		return nil
	}
	copyDoc := *doc
	return &copyDoc
}

func cloneToken(token *models.QRToken) *models.QRToken {
	if token == nil {
		return nil
	}
	copyToken := *token
	return &copyToken
}

func cloneUser(user *models.User) *models.User {
	if user == nil {
		return nil
	}
	copyUser := *user
	return &copyUser
}

func (s *Store) UpsertBoard(siteID string, board *models.Board) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, site := range s.data.Sites {
		if site.ID == siteID {
			found := false
			for i, existing := range site.Boards {
				if existing.ID == board.ID {
					site.Boards[i] = cloneBoard(board)
					found = true
					break
				}
			}
			if !found {
				site.Boards = append(site.Boards, cloneBoard(board))
			}
			site.UpdatedAt = time.Now()
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) DeleteBoard(siteID, boardID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, site := range s.data.Sites {
		if site.ID == siteID {
			filtered := site.Boards[:0]
			for _, board := range site.Boards {
				if board.ID == boardID {
					continue
				}
				filtered = append(filtered, board)
			}
			site.Boards = filtered
			site.UpdatedAt = time.Now()
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) UpsertAppliance(siteID string, appliance *models.Appliance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, site := range s.data.Sites {
		if site.ID == siteID {
			found := false
			for i, existing := range site.Appliances {
				if existing.ID == appliance.ID {
					site.Appliances[i] = cloneAppliance(appliance)
					found = true
					break
				}
			}
			if !found {
				site.Appliances = append(site.Appliances, cloneAppliance(appliance))
			}
			site.UpdatedAt = time.Now()
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) DeleteAppliance(siteID, applianceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, site := range s.data.Sites {
		if site.ID == siteID {
			filtered := site.Appliances[:0]
			for _, app := range site.Appliances {
				if app.ID == applianceID {
					continue
				}
				filtered = append(filtered, app)
			}
			site.Appliances = filtered
			site.UpdatedAt = time.Now()
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) NextTokenShortID() string {
	return randomUppercase(6)
}

func randomUppercase(length int) string {
	letters := []rune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func GeneratePIN() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%05d", rand.Intn(100000))
}

func NewID() string {
	buf := make([]byte, 16)
	if _, err := cryptoRand.Read(buf); err == nil {
		return fmt.Sprintf("%x", buf)
	}
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func normalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func matchesIdentifier(user *models.User, ident string) bool {
	if ident == "" {
		return false
	}
	if normalizeIdentifier(user.Username) == ident {
		return true
	}
	if normalizeIdentifier(user.Email) == ident {
		return true
	}
	return false
}

func (s *Store) MediaPath(parts ...string) string {
	all := append([]string{s.mediaDir}, parts...)
	return filepath.Join(all...)
}

func (s *Store) EnsureMediaDir(parts ...string) error {
	path := s.MediaPath(parts...)
	return os.MkdirAll(path, 0o755)
}

func (s *Store) RemoveFile(path string) error {
	if path == "" {
		return nil
	}
	return os.Remove(path)
}
