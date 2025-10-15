package session

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type SessionManager struct {
	mu            sync.Mutex
	adminSessions map[string]*adminSession
	siteSessions  map[string]*siteSession
	adminTTL      time.Duration
	siteTTL       time.Duration
}

type siteSession struct {
	SiteID  string
	Expires time.Time
}

type adminSession struct {
	UserID  string
	Expires time.Time
}

func New(adminTTL, siteTTL time.Duration) *SessionManager {
	return &SessionManager{
		adminSessions: make(map[string]*adminSession),
		siteSessions:  make(map[string]*siteSession),
		adminTTL:      adminTTL,
		siteTTL:       siteTTL,
	}
}

func (m *SessionManager) randomToken() string {
	buf := make([]byte, 16)
	if _, err := cryptoRand.Read(buf); err != nil {
		return time.Now().Format(time.RFC3339Nano)
	}
	return hex.EncodeToString(buf)
}

func (m *SessionManager) CreateAdminSession(userID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	token := m.randomToken()
	m.adminSessions[token] = &adminSession{UserID: userID, Expires: time.Now().Add(m.adminTTL)}
	return token
}

func (m *SessionManager) ValidateAdmin(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.adminSessions[token]
	if !ok {
		return "", false
	}
	if time.Now().After(sess.Expires) {
		delete(m.adminSessions, token)
		return "", false
	}
	sess.Expires = time.Now().Add(m.adminTTL)
	return sess.UserID, true
}

func (m *SessionManager) RevokeAdmin(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.adminSessions, token)
}

func (m *SessionManager) CreateSiteSession(siteID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	token := m.randomToken()
	m.siteSessions[token] = &siteSession{SiteID: siteID, Expires: time.Now().Add(m.siteTTL)}
	return token
}

func (m *SessionManager) ValidateSite(token string, siteID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.siteSessions[token]
	if !ok {
		return false
	}
	if sess.SiteID != siteID {
		return false
	}
	if time.Now().After(sess.Expires) {
		delete(m.siteSessions, token)
		return false
	}
	sess.Expires = time.Now().Add(m.siteTTL)
	return true
}

func (m *SessionManager) GetSiteID(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.siteSessions[token]
	if !ok {
		return "", false
	}
	if time.Now().After(sess.Expires) {
		delete(m.siteSessions, token)
		return "", false
	}
	sess.Expires = time.Now().Add(m.siteTTL)
	return sess.SiteID, true
}

func (m *SessionManager) RevokeSite(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.siteSessions, token)
}
