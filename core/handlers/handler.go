package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"wirevault/core/models"
	"wirevault/core/session"
	"wirevault/core/store"
)

type Handler struct {
	Store     *store.Store
	Sessions  *session.SessionManager
	Templates *template.Template
	samlMu    sync.RWMutex
	saml      *samlsp.Middleware
}

const (
	adminCookieName = "wv_admin"
	siteCookieName  = "wv_site"
)

type publicSite struct {
	ShortID string
	Address string
}

type applianceGroup struct {
	Category models.ApplianceCategory
	Items    []*models.Appliance
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/access/", h.handleAccess)
	mux.HandleFunc("/site/", h.handleSite)
	mux.HandleFunc("/documents/", h.handleDocument)

	mux.HandleFunc("/admin/login", h.handleAdminLogin)
	mux.HandleFunc("/admin/login/sso", h.handleAdminLoginSSO)
	mux.HandleFunc("/admin/logout", h.handleAdminLogout)
	mux.HandleFunc("/admin/saml/", h.handleAdminSAML)
	mux.HandleFunc("/admin/sites", h.handleAdminSites)
	mux.HandleFunc("/admin/site/", h.handleAdminSiteDetail)
	mux.HandleFunc("/admin/tokens", h.handleAdminTokens)
	mux.HandleFunc("/admin/tokens/generate", h.handleAdminGenerateTokens)
	mux.HandleFunc("/admin/tokens/export", h.handleAdminExportTokens)
	mux.HandleFunc("/admin/settings", h.handleAdminSettings)
}

func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/admin/sites", http.StatusSeeOther)
}

func (h *Handler) render(w http.ResponseWriter, templateName string, data any) {
	var viewData map[string]any
	switch v := data.(type) {
	case map[string]any:
		viewData = v
	case nil:
		viewData = map[string]any{}
	default:
		viewData = map[string]any{"Data": v}
	}
	if _, ok := viewData["Title"]; !ok {
		viewData["Title"] = "WireVault"
	}
	if _, ok := viewData["BodyClass"]; !ok {
		viewData["BodyClass"] = ""
	}
	contentTemplate := templateName + "#content"
	var contentBuf bytes.Buffer
	if err := h.Templates.ExecuteTemplate(&contentBuf, contentTemplate, viewData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	viewData["Content"] = template.HTML(contentBuf.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.Templates.ExecuteTemplate(w, templateName, viewData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) setSAMLMiddleware(mw *samlsp.Middleware) {
	h.samlMu.Lock()
	defer h.samlMu.Unlock()
	h.saml = mw
}

func (h *Handler) getSAMLMiddleware() *samlsp.Middleware {
	h.samlMu.RLock()
	defer h.samlMu.RUnlock()
	return h.saml
}

func (h *Handler) issueAdminSession(w http.ResponseWriter, user *models.User) {
	token := h.Sessions.CreateAdminSession(user.ID)
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
}

func (h *Handler) clearAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   adminCookieName,
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})
}

func toPublicSite(site *models.Site) publicSite {
	return publicSite{
		ShortID: site.ShortID,
		Address: site.Address,
	}
}

func (h *Handler) handleAccess(w http.ResponseWriter, r *http.Request) {
	tokenShortID := strings.TrimPrefix(r.URL.Path, "/access/")
	if tokenShortID == "" {
		http.NotFound(w, r)
		return
	}
	tokenShortID = strings.Trim(tokenShortID, "/")
	token, err := h.Store.GetTokenByShortID(tokenShortID)
	if err != nil {
		h.render(w, "core/pin_entry.html", map[string]any{
			"Title":     "WireVault · Enter PIN",
			"BodyClass": "customer",
			"Error":     "PIN is incorrect.",
		})
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		pin := r.Form.Get("pin")
		if pin == token.PIN && token.Status == models.TokenAssigned && token.SiteID != "" {
			site, err := h.Store.GetSiteByID(token.SiteID)
			if err != nil {
				http.Error(w, "Site not found", http.StatusNotFound)
				return
			}
			sessionToken := h.Sessions.CreateSiteSession(site.ID)
			http.SetCookie(w, &http.Cookie{
				Name:     siteCookieName,
				Value:    sessionToken,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int((20 * time.Minute).Seconds()),
			})
			http.Redirect(w, r, fmt.Sprintf("/site/%s", site.ShortID), http.StatusSeeOther)
			return
		}
		h.render(w, "core/pin_entry.html", map[string]any{
			"Error":   "PIN is incorrect.",
			"TokenID": tokenShortID,
		})
		return
	}

	h.render(w, "core/pin_entry.html", map[string]any{
		"Title":     "WireVault · Enter PIN",
		"BodyClass": "customer",
	})
}

func (h *Handler) handleSite(w http.ResponseWriter, r *http.Request) {
	remainder := strings.TrimPrefix(r.URL.Path, "/site/")
	if remainder == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	siteShortID := parts[0]
	site, err := h.Store.GetSiteByShortID(siteShortID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	cookie, err := r.Cookie(siteCookieName)
	if err != nil || !h.Sessions.ValidateSite(cookie.Value, site.ID) {
		h.render(w, "core/session_expired.html", map[string]any{
			"Title":     "WireVault · Session expired",
			"BodyClass": "customer",
			"TokenURL":  fmt.Sprintf("/access/%s", h.findTokenShortIDForSite(site.ID)),
		})
		return
	}

	if len(parts) == 1 {
		h.render(w, "core/site_overview.html", h.buildSiteOverviewContext(site))
		return
	}

	switch parts[1] {
	case "boards":
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		boardID := parts[2]
		board := findBoard(site, boardID)
		if board == nil {
			http.NotFound(w, r)
			return
		}
		h.render(w, "core/board_detail.html", map[string]any{
			"Title":     fmt.Sprintf("%s · %s", board.Name, site.Address),
			"BodyClass": "customer",
			"Site":      toPublicSite(site),
			"Board":     board,
		})
	case "appliances":
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		applianceID := parts[2]
		appliance := findAppliance(site, applianceID)
		if appliance == nil {
			http.NotFound(w, r)
			return
		}
		h.render(w, "core/appliance_detail.html", map[string]any{
			"Title":     fmt.Sprintf("%s · %s", appliance.Name, site.Address),
			"BodyClass": "customer",
			"Site":      toPublicSite(site),
			"Appliance": appliance,
		})
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) findTokenShortIDForSite(siteID string) string {
	tokens := h.Store.ListTokens()
	for _, token := range tokens {
		if token.SiteID == siteID && token.Status == models.TokenAssigned {
			return token.ShortID
		}
	}
	return ""
}

func (h *Handler) buildSiteOverviewContext(site *models.Site) map[string]any {
	groups := make([]applianceGroup, 0, len(models.ApplianceCategoryOrder))
	for _, category := range models.ApplianceCategoryOrder {
		items := []*models.Appliance{}
		for _, appliance := range site.Appliances {
			if appliance.Category == category {
				items = append(items, appliance)
			}
		}
		groups = append(groups, applianceGroup{Category: category, Items: items})
	}
	return map[string]any{
		"Title":           fmt.Sprintf("%s · WireVault", site.Address),
		"BodyClass":       "customer",
		"Site":            toPublicSite(site),
		"Boards":          site.Boards,
		"ApplianceGroups": groups,
	}
}

func (h *Handler) handleDocument(w http.ResponseWriter, r *http.Request) {
	remainder := strings.TrimPrefix(r.URL.Path, "/documents/")
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}
	kind := parts[0]
	parentID := parts[1]
	docID := parts[2]

	var site *models.Site
	var doc *models.Document
	var err error

	switch kind {
	case "board":
		site, doc, err = h.findBoardDocument(parentID, docID)
	case "appliance":
		site, doc, err = h.findApplianceDocument(parentID, docID)
	default:
		http.NotFound(w, r)
		return
	}

	if err != nil || doc == nil || site == nil {
		http.NotFound(w, r)
		return
	}

	cookie, err := r.Cookie(siteCookieName)
	if err != nil || !h.Sessions.ValidateSite(cookie.Value, site.ID) {
		h.render(w, "core/session_expired.html", map[string]any{
			"Title":     "WireVault · Session expired",
			"BodyClass": "customer",
			"TokenURL":  fmt.Sprintf("/access/%s", h.findTokenShortIDForSite(site.ID)),
		})
		return
	}

	file, err := os.Open(doc.FilePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", doc.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", doc.FileName))
	io.Copy(w, file)
}

func (h *Handler) findBoardDocument(boardID, docID string) (*models.Site, *models.Document, error) {
	sites := h.Store.ListSites()
	for _, site := range sites {
		board := findBoard(site, boardID)
		if board == nil {
			continue
		}
		for _, doc := range board.Documents {
			if doc.ID == docID {
				return site, doc, nil
			}
		}
	}
	return nil, nil, store.ErrNotFound
}

func (h *Handler) findApplianceDocument(applianceID, docID string) (*models.Site, *models.Document, error) {
	sites := h.Store.ListSites()
	for _, site := range sites {
		appliance := findAppliance(site, applianceID)
		if appliance == nil {
			continue
		}
		for _, doc := range appliance.Documents {
			if doc.ID == docID {
				return site, doc, nil
			}
		}
	}
	return nil, nil, store.ErrNotFound
}

func findBoard(site *models.Site, boardID string) *models.Board {
	for _, board := range site.Boards {
		if board.ID == boardID {
			return board
		}
	}
	return nil
}

func findAppliance(site *models.Site, applianceID string) *models.Appliance {
	for _, appliance := range site.Appliances {
		if appliance.ID == applianceID {
			return appliance
		}
	}
	return nil
}

func (h *Handler) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(adminCookieName); err == nil {
		if _, ok := h.Sessions.ValidateAdmin(cookie.Value); ok {
			http.Redirect(w, r, "/admin/sites", http.StatusSeeOther)
			return
		}
	}
	message := strings.TrimSpace(r.URL.Query().Get("msg"))
	messageType := strings.TrimSpace(r.URL.Query().Get("type"))
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		identifier := strings.TrimSpace(r.Form.Get("identifier"))
		password := r.Form.Get("password")
		if user, ok := h.Store.AuthenticateUser(identifier, password); ok {
			h.issueAdminSession(w, user)
			http.Redirect(w, r, "/admin/sites", http.StatusSeeOther)
			return
		}
		h.render(w, "admin/login.html", map[string]any{
			"Title":      "WireVault Admin",
			"BodyClass":  "admin auth",
			"Error":      "Incorrect credentials.",
			"Identifier": identifier,
			"SSOEnabled": h.Store.GetSAMLSettings().Enabled,
		})
		return
	}
	h.render(w, "admin/login.html", map[string]any{
		"Title":       "WireVault Admin",
		"BodyClass":   "admin auth",
		"SSOEnabled":  h.Store.GetSAMLSettings().Enabled,
		"Message":     message,
		"MessageType": messageType,
	})
}

func (h *Handler) handleAdminLoginSSO(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	middleware := h.getSAMLMiddleware()
	if middleware == nil {
		http.Redirect(w, r, "/admin/login?msg=SSO%20is%20not%20configured&type=error", http.StatusSeeOther)
		return
	}
	middleware.HandleStartAuthFlow(w, r)
}

func (h *Handler) handleAdminSAML(w http.ResponseWriter, r *http.Request) {
	middleware := h.getSAMLMiddleware()
	if middleware == nil {
		http.NotFound(w, r)
		return
	}
	middleware.ServeHTTP(w, r)
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) (*models.User, bool) {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return nil, false
	}
	userID, ok := h.Sessions.ValidateAdmin(cookie.Value)
	if !ok {
		h.clearAdminCookie(w)
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return nil, false
	}
	user, err := h.Store.GetUserByID(userID)
	if err != nil {
		h.Sessions.RevokeAdmin(cookie.Value)
		h.clearAdminCookie(w)
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return nil, false
	}
	return user, true
}

func (h *Handler) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(adminCookieName)
	if err == nil {
		h.Sessions.RevokeAdmin(cookie.Value)
	}
	h.clearAdminCookie(w)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (h *Handler) handleAdminSites(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.renderSiteList(w, r, r.URL.Query().Get("msg"), r.URL.Query().Get("type"))
	case http.MethodPost:
		h.createSite(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) renderSiteList(w http.ResponseWriter, r *http.Request, message, messageType string) {
	sites := h.Store.ListSites()
	tokens := h.Store.ListTokens()
	siteTokens := make(map[string][]*models.QRToken)
	for _, token := range tokens {
		if token.SiteID == "" || token.Status != models.TokenAssigned {
			continue
		}
		siteTokens[token.SiteID] = append(siteTokens[token.SiteID], token)
	}
	sort.Slice(sites, func(i, j int) bool {
		return strings.ToLower(sites[i].Address) < strings.ToLower(sites[j].Address)
	})
	h.render(w, "admin/sites.html", map[string]any{
		"Title":       "WireVault Admin · Sites",
		"BodyClass":   "admin dashboard",
		"Sites":       sites,
		"SiteTokens":  siteTokens,
		"Message":     message,
		"MessageType": messageType,
	})
}

func (h *Handler) createSite(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	address := strings.TrimSpace(r.Form.Get("address"))
	if address == "" {
		h.renderSiteList(w, r, "Address is required.", "error")
		return
	}
	shortID := strings.TrimSpace(r.Form.Get("short_id"))
	shortID = sanitizeShortID(shortID)
	if shortID == "" {
		shortID = sanitizeShortID(defaultSiteShortID(address))
	}
	shortID = h.ensureUniqueSiteShortID(shortID, "")
	now := time.Now()
	site := &models.Site{
		ID:           store.NewID(),
		ShortID:      shortID,
		Address:      address,
		CustomerName: strings.TrimSpace(r.Form.Get("customer_name")),
		Notes:        strings.TrimSpace(r.Form.Get("notes")),
		Boards:       []*models.Board{},
		Appliances:   []*models.Appliance{},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := h.Store.SaveSite(site); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Site%%20created&type=success", site.ID), http.StatusSeeOther)
}

func (h *Handler) handleAdminSiteDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	remainder := strings.TrimPrefix(r.URL.Path, "/admin/site/")
	if remainder == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	siteID := parts[0]

	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		h.renderSiteDetail(w, r, siteID, "", "")
	case len(parts) == 1 && r.Method == http.MethodPost:
		h.updateSite(w, r, siteID)
	case len(parts) >= 2 && parts[1] == "boards":
		h.handleBoardActions(w, r, siteID, parts[2:])
	case len(parts) >= 2 && parts[1] == "appliances":
		h.handleApplianceActions(w, r, siteID, parts[2:])
	case len(parts) >= 2 && parts[1] == "tokens":
		h.handleSiteTokenActions(w, r, siteID, parts[2:])
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) renderSiteDetail(w http.ResponseWriter, r *http.Request, siteID string, message string, messageType string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tokens := h.Store.ListTokens()
	assigned := []*models.QRToken{}
	unassigned := []*models.QRToken{}
	for _, token := range tokens {
		if token.SiteID == site.ID && token.Status != models.TokenRetired {
			assigned = append(assigned, token)
		} else if token.SiteID == "" && token.Status == models.TokenUnassigned {
			unassigned = append(unassigned, token)
		}
	}
	if messageType == "" {
		messageType = r.URL.Query().Get("type")
	}
	if message == "" {
		message = r.URL.Query().Get("msg")
	}
	h.render(w, "admin/site_detail.html", map[string]any{
		"Title":           fmt.Sprintf("WireVault Admin · %s", site.Address),
		"BodyClass":       "admin detail",
		"Site":            site,
		"AssignedTokens":  assigned,
		"AvailableTokens": unassigned,
		"Message":         message,
		"MessageType":     messageType,
	})
}

func (h *Handler) updateSite(w http.ResponseWriter, r *http.Request, siteID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	shortID := sanitizeShortID(strings.TrimSpace(r.Form.Get("short_id")))
	if shortID == "" {
		shortID = site.ShortID
	} else if h.Store.IsSiteShortIDTaken(shortID, siteID) {
		h.renderSiteDetail(w, r, siteID, "Short ID is already in use.", "error")
		return
	}
	site.ShortID = shortID
	site.Address = strings.TrimSpace(r.Form.Get("address"))
	site.CustomerName = strings.TrimSpace(r.Form.Get("customer_name"))
	site.Notes = strings.TrimSpace(r.Form.Get("notes"))
	site.UpdatedAt = time.Now()
	if err := h.Store.SaveSite(site); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Site%%20updated&type=success", siteID), http.StatusSeeOther)
}

func (h *Handler) handleBoardActions(w http.ResponseWriter, r *http.Request, siteID string, parts []string) {
	if len(parts) == 0 {
		http.NotFound(w, r)
		return
	}
	switch parts[0] {
	case "new":
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		h.renderBoardForm(w, r, siteID, &models.Board{}, "")
		return
	case "create":
		h.createBoard(w, r, siteID)
		return
	}

	boardID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			h.renderExistingBoard(w, r, siteID, boardID, "")
		case http.MethodPost:
			h.updateBoard(w, r, siteID, boardID)
		default:
			http.NotFound(w, r)
		}
		return
	}

	switch parts[1] {
	case "delete":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		h.deleteBoard(w, r, siteID, boardID)
	case "documents":
		if len(parts) == 2 {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			h.uploadBoardDocument(w, r, siteID, boardID)
			return
		}
		if len(parts) >= 4 && parts[3] == "delete" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			docID := parts[2]
			h.deleteBoardDocument(w, r, siteID, boardID, docID)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleApplianceActions(w http.ResponseWriter, r *http.Request, siteID string, parts []string) {
	if len(parts) == 0 {
		http.NotFound(w, r)
		return
	}
	switch parts[0] {
	case "new":
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		h.renderApplianceForm(w, r, siteID, &models.Appliance{}, "")
		return
	case "create":
		h.createAppliance(w, r, siteID)
		return
	}

	applianceID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			h.renderExistingAppliance(w, r, siteID, applianceID, "")
		case http.MethodPost:
			h.updateAppliance(w, r, siteID, applianceID)
		default:
			http.NotFound(w, r)
		}
		return
	}

	switch parts[1] {
	case "delete":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		h.deleteAppliance(w, r, siteID, applianceID)
	case "documents":
		if len(parts) == 2 {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			h.uploadApplianceDocument(w, r, siteID, applianceID)
			return
		}
		if len(parts) >= 4 && parts[3] == "delete" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			docID := parts[2]
			h.deleteApplianceDocument(w, r, siteID, applianceID, docID)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleSiteTokenActions(w http.ResponseWriter, r *http.Request, siteID string, parts []string) {
	if len(parts) < 1 {
		http.NotFound(w, r)
		return
	}
	action := parts[0]
	switch action {
	case "assign":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		tokenID := r.Form.Get("token_id")
		if tokenID == "" {
			http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Select%%20a%%20token&type=error", siteID), http.StatusSeeOther)
			return
		}
		if err := h.Store.AssignTokenToSite(tokenID, siteID); err != nil {
			http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Unable%%20to%%20assign%%20token&type=error", siteID), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Token%%20assigned&type=success", siteID), http.StatusSeeOther)
	case "remove":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		tokenID := r.Form.Get("token_id")
		if tokenID == "" {
			http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Select%%20a%%20token&type=error", siteID), http.StatusSeeOther)
			return
		}
		if err := h.Store.RemoveTokenFromSite(tokenID); err != nil {
			http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Unable%%20to%%20unassign&type=error", siteID), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Token%%20unassigned&type=success", siteID), http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleAdminTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.renderTokenList(w, r, r.URL.Query().Get("msg"), r.URL.Query().Get("type"))
	case http.MethodPost:
		h.processTokenPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) renderTokenList(w http.ResponseWriter, r *http.Request, message, messageType string) {
	tokens := h.Store.ListTokens()
	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].CreatedAt.After(tokens[j].CreatedAt)
	})
	sites := h.Store.ListSites()
	siteLookup := make(map[string]string)
	for _, site := range sites {
		siteLookup[site.ID] = site.Address
	}
	h.render(w, "admin/token_list.html", map[string]any{
		"Title":       "WireVault Admin · Tokens",
		"BodyClass":   "admin dashboard",
		"Tokens":      tokens,
		"Sites":       sites,
		"SiteLookup":  siteLookup,
		"Message":     message,
		"MessageType": messageType,
	})
}

func (h *Handler) processTokenPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	action := r.Form.Get("action")
	tokenID := r.Form.Get("token_id")
	switch action {
	case "update":
		h.updateToken(w, r, tokenID)
	case "delete":
		if err := h.Store.DeleteToken(tokenID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/tokens?msg=Token%20deleted&type=success", http.StatusSeeOther)
	default:
		http.Error(w, "Unsupported action", http.StatusBadRequest)
	}
}

func (h *Handler) updateToken(w http.ResponseWriter, r *http.Request, tokenID string) {
	token, err := h.Store.GetTokenByID(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}
	shortID := sanitizeShortID(r.Form.Get("short_id"))
	if shortID == "" {
		shortID = token.ShortID
	}
	if h.Store.IsTokenShortIDTaken(shortID, tokenID) {
		h.renderTokenList(w, r, "Short ID already in use.", "error")
		return
	}
	pin := strings.TrimSpace(r.Form.Get("pin"))
	if pin == "" {
		pin = token.PIN
	}
	if len(pin) != 5 || !isDigits(pin) {
		h.renderTokenList(w, r, "PIN must be 5 digits.", "error")
		return
	}
	status := models.QRTokenStatus(strings.ToUpper(strings.TrimSpace(r.Form.Get("status"))))
	switch status {
	case models.TokenAssigned, models.TokenUnassigned, models.TokenRetired:
		// ok
	default:
		status = token.Status
	}
	token.ShortID = shortID
	token.PIN = pin
	token.Status = status
	token.UpdatedAt = time.Now()
	if status == models.TokenUnassigned {
		if token.SiteID != "" {
			h.Store.RemoveTokenFromSite(token.ID)
			token.SiteID = ""
		}
	}
	if err := h.Store.SaveToken(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/tokens?msg=Token%20updated&type=success", http.StatusSeeOther)
}

func (h *Handler) renderBoardForm(w http.ResponseWriter, r *http.Request, siteID string, board *models.Board, message string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, "admin/board_form.html", map[string]any{
		"Title":     fmt.Sprintf("WireVault Admin · %s", site.Address),
		"BodyClass": "admin edit",
		"Site":      site,
		"Board":     board,
		"Message":   message,
	})
}

func (h *Handler) renderExistingBoard(w http.ResponseWriter, r *http.Request, siteID, boardID string, message string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	board := findBoard(site, boardID)
	if board == nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, "admin/board_form.html", map[string]any{
		"Title":     fmt.Sprintf("WireVault Admin · %s", site.Address),
		"BodyClass": "admin edit",
		"Site":      site,
		"Board":     board,
		"Message":   message,
	})
}

func (h *Handler) createBoard(w http.ResponseWriter, r *http.Request, siteID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	now := time.Now()
	board := &models.Board{
		ID:        store.NewID(),
		Documents: []*models.Document{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	populateBoardFromForm(board, r.Form)
	if err := h.Store.UpsertBoard(siteID, board); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/boards/%s?msg=Board%%20saved", siteID, board.ID), http.StatusSeeOther)
}

func (h *Handler) updateBoard(w http.ResponseWriter, r *http.Request, siteID, boardID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	board := findBoard(site, boardID)
	if board == nil {
		http.NotFound(w, r)
		return
	}
	populateBoardFromForm(board, r.Form)
	board.UpdatedAt = time.Now()
	if err := h.Store.UpsertBoard(siteID, board); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/boards/%s?msg=Board%%20updated", siteID, board.ID), http.StatusSeeOther)
}

func (h *Handler) deleteBoard(w http.ResponseWriter, r *http.Request, siteID, boardID string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	board := findBoard(site, boardID)
	if board != nil {
		for _, doc := range board.Documents {
			h.Store.RemoveFile(doc.FilePath)
		}
	}
	if err := h.Store.DeleteBoard(siteID, boardID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Board%%20removed&type=success", siteID), http.StatusSeeOther)
}

func (h *Handler) uploadBoardDocument(w http.ResponseWriter, r *http.Request, siteID, boardID string) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Error(w, "Upload failed", http.StatusBadRequest)
		return
	}
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	board := findBoard(site, boardID)
	if board == nil {
		http.NotFound(w, r)
		return
	}
	file, header, err := r.FormFile("document")
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/boards/%s?msg=Select%%20a%%20file", siteID, boardID), http.StatusSeeOther)
		return
	}
	defer file.Close()

	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		label = header.Filename
	}
	if err := h.Store.EnsureMediaDir("boards", boardID); err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	cleanName := sanitizeFileName(header.Filename)
	if cleanName == "" {
		cleanName = "document"
	}
	ts := time.Now().Format("20060102_150405")
	destPath := h.Store.MediaPath("boards", boardID, ts+"_"+cleanName)
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()
	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	doc := &models.Document{
		ID:         store.NewID(),
		Label:      label,
		FileName:   cleanName,
		MimeType:   mimeType,
		FilePath:   destPath,
		UploadedAt: time.Now(),
	}
	board.Documents = append(board.Documents, doc)
	board.UpdatedAt = time.Now()
	if err := h.Store.UpsertBoard(siteID, board); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/boards/%s?msg=Document%%20uploaded", siteID, boardID), http.StatusSeeOther)
}

func (h *Handler) deleteBoardDocument(w http.ResponseWriter, r *http.Request, siteID, boardID, docID string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	board := findBoard(site, boardID)
	if board == nil {
		http.NotFound(w, r)
		return
	}
	documents := board.Documents[:0]
	for _, doc := range board.Documents {
		if doc.ID == docID {
			h.Store.RemoveFile(doc.FilePath)
			continue
		}
		documents = append(documents, doc)
	}
	board.Documents = documents
	board.UpdatedAt = time.Now()
	if err := h.Store.UpsertBoard(siteID, board); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/boards/%s?msg=Document%%20removed", siteID, boardID), http.StatusSeeOther)
}

func (h *Handler) renderApplianceForm(w http.ResponseWriter, r *http.Request, siteID string, appliance *models.Appliance, message string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, "admin/appliance_form.html", map[string]any{
		"Title":      fmt.Sprintf("WireVault Admin · %s", site.Address),
		"BodyClass":  "admin edit",
		"Site":       site,
		"Appliance":  appliance,
		"Message":    message,
		"Categories": models.ApplianceCategoryOrder,
	})
}

func (h *Handler) renderExistingAppliance(w http.ResponseWriter, r *http.Request, siteID, applianceID string, message string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	appliance := findAppliance(site, applianceID)
	if appliance == nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, "admin/appliance_form.html", map[string]any{
		"Title":      fmt.Sprintf("WireVault Admin · %s", site.Address),
		"BodyClass":  "admin edit",
		"Site":       site,
		"Appliance":  appliance,
		"Message":    message,
		"Categories": models.ApplianceCategoryOrder,
	})
}

func (h *Handler) createAppliance(w http.ResponseWriter, r *http.Request, siteID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	now := time.Now()
	appliance := &models.Appliance{
		ID:        store.NewID(),
		Documents: []*models.Document{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	populateApplianceFromForm(appliance, r.Form)
	if err := h.Store.UpsertAppliance(siteID, appliance); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/appliances/%s?msg=Appliance%%20saved", siteID, appliance.ID), http.StatusSeeOther)
}

func (h *Handler) updateAppliance(w http.ResponseWriter, r *http.Request, siteID, applianceID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	appliance := findAppliance(site, applianceID)
	if appliance == nil {
		http.NotFound(w, r)
		return
	}
	populateApplianceFromForm(appliance, r.Form)
	appliance.UpdatedAt = time.Now()
	if err := h.Store.UpsertAppliance(siteID, appliance); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/appliances/%s?msg=Appliance%%20updated", siteID, appliance.ID), http.StatusSeeOther)
}

func (h *Handler) deleteAppliance(w http.ResponseWriter, r *http.Request, siteID, applianceID string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	appliance := findAppliance(site, applianceID)
	if appliance != nil {
		for _, doc := range appliance.Documents {
			h.Store.RemoveFile(doc.FilePath)
		}
	}
	if err := h.Store.DeleteAppliance(siteID, applianceID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s?msg=Appliance%%20removed&type=success", siteID), http.StatusSeeOther)
}

func (h *Handler) uploadApplianceDocument(w http.ResponseWriter, r *http.Request, siteID, applianceID string) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Error(w, "Upload failed", http.StatusBadRequest)
		return
	}
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	appliance := findAppliance(site, applianceID)
	if appliance == nil {
		http.NotFound(w, r)
		return
	}
	file, header, err := r.FormFile("document")
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/appliances/%s?msg=Select%%20a%%20file", siteID, applianceID), http.StatusSeeOther)
		return
	}
	defer file.Close()

	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		label = header.Filename
	}
	if err := h.Store.EnsureMediaDir("appliances", applianceID); err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	cleanName := sanitizeFileName(header.Filename)
	if cleanName == "" {
		cleanName = "document"
	}
	ts := time.Now().Format("20060102_150405")
	destPath := h.Store.MediaPath("appliances", applianceID, ts+"_"+cleanName)
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()
	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	doc := &models.Document{
		ID:         store.NewID(),
		Label:      label,
		FileName:   cleanName,
		MimeType:   mimeType,
		FilePath:   destPath,
		UploadedAt: time.Now(),
	}
	appliance.Documents = append(appliance.Documents, doc)
	appliance.UpdatedAt = time.Now()
	if err := h.Store.UpsertAppliance(siteID, appliance); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/appliances/%s?msg=Document%%20uploaded", siteID, applianceID), http.StatusSeeOther)
}

func (h *Handler) deleteApplianceDocument(w http.ResponseWriter, r *http.Request, siteID, applianceID, docID string) {
	site, err := h.Store.GetSiteByID(siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	appliance := findAppliance(site, applianceID)
	if appliance == nil {
		http.NotFound(w, r)
		return
	}
	documents := appliance.Documents[:0]
	for _, doc := range appliance.Documents {
		if doc.ID == docID {
			h.Store.RemoveFile(doc.FilePath)
			continue
		}
		documents = append(documents, doc)
	}
	appliance.Documents = documents
	appliance.UpdatedAt = time.Now()
	if err := h.Store.UpsertAppliance(siteID, appliance); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/site/%s/appliances/%s?msg=Document%%20removed", siteID, applianceID), http.StatusSeeOther)
}

func populateBoardFromForm(board *models.Board, form map[string][]string) {
	board.ShortID = strings.TrimSpace(firstValue(form, "short_id"))
	board.Name = strings.TrimSpace(firstValue(form, "name"))
	board.BoardType = strings.TrimSpace(firstValue(form, "board_type"))
	board.SupplyType = strings.TrimSpace(firstValue(form, "supply_type"))
	board.Voltage = strings.TrimSpace(firstValue(form, "voltage"))
	board.EarthingSystem = strings.TrimSpace(firstValue(form, "earthing_system"))
	board.IncomingCable = strings.TrimSpace(firstValue(form, "incoming_cable"))
	board.RatedCurrent = strings.TrimSpace(firstValue(form, "rated_current"))
	board.Frequency = strings.TrimSpace(firstValue(form, "frequency"))
	board.Solar = firstValue(form, "solar") == "on"
	board.Description = strings.TrimSpace(firstValue(form, "description"))
	board.LastInspection = strings.TrimSpace(firstValue(form, "last_inspection"))
	board.NextInspectionDue = strings.TrimSpace(firstValue(form, "next_inspection"))
}

func populateApplianceFromForm(appliance *models.Appliance, form map[string][]string) {
	appliance.Category = models.ApplianceCategory(firstValue(form, "category"))
	appliance.Name = strings.TrimSpace(firstValue(form, "name"))
	appliance.Brand = strings.TrimSpace(firstValue(form, "brand"))
	appliance.Model = strings.TrimSpace(firstValue(form, "model"))
	appliance.SerialNumber = strings.TrimSpace(firstValue(form, "serial_number"))
	appliance.Voltage = strings.TrimSpace(firstValue(form, "voltage"))
	appliance.PowerKW = strings.TrimSpace(firstValue(form, "power_kw"))
	appliance.InstallDate = strings.TrimSpace(firstValue(form, "install_date"))
	appliance.Notes = strings.TrimSpace(firstValue(form, "notes"))
	appliance.MPPTCount = strings.TrimSpace(firstValue(form, "mppt_count"))
	appliance.CapacityKWh = strings.TrimSpace(firstValue(form, "capacity_kwh"))
	appliance.ConnectorType = strings.TrimSpace(firstValue(form, "connector_type"))
	appliance.Phases = strings.TrimSpace(firstValue(form, "phases"))
	appliance.FuelType = strings.TrimSpace(firstValue(form, "fuel_type"))
}

func firstValue(form map[string][]string, key string) string {
	values := form[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func sanitizeFileName(name string) string {
	clean := filepath.Base(name)
	clean = strings.ReplaceAll(clean, " ", "_")
	clean = strings.ReplaceAll(clean, "..", "")
	clean = strings.ReplaceAll(clean, "/", "")
	clean = strings.ReplaceAll(clean, "\\", "")
	return clean
}

func isDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(value) > 0
}

func sanitizeShortID(value string) string {
	upper := strings.ToUpper(value)
	var sb strings.Builder
	for _, r := range upper {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func defaultSiteShortID(address string) string {
	upper := strings.ToUpper(address)
	var sb strings.Builder
	for _, r := range upper {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
		if sb.Len() >= 6 {
			break
		}
	}
	if sb.Len() == 0 {
		id := strings.ToUpper(store.NewID())
		if len(id) > 6 {
			id = id[:6]
		}
		return id
	}
	return sb.String()
}

func (h *Handler) ensureUniqueSiteShortID(candidate, excludeID string) string {
	if candidate == "" {
		id := strings.ToUpper(store.NewID())
		if len(id) > 6 {
			id = id[:6]
		}
		candidate = id
	}
	base := candidate
	suffix := 1
	for h.Store.IsSiteShortIDTaken(candidate, excludeID) {
		candidate = fmt.Sprintf("%s%d", base, suffix)
		suffix++
		if suffix > 99 {
			candidate = fmt.Sprintf("%s%s", base, strings.ToUpper(store.NewID())[:4])
			suffix = 1
		}
	}
	return candidate
}

func buildXLSX(tokens []*models.QRToken, h *Handler) ([]byte, error) {
	rows := [][]string{{"tokenShortId", "pin", "siteShortId", "qrUrl"}}
	baseURL := strings.TrimRight(h.Store.GetPublicBaseURL(), "/")
	for _, token := range tokens {
		siteShort := ""
		if token.SiteID != "" {
			if site, err := h.Store.GetSiteByID(token.SiteID); err == nil {
				siteShort = site.ShortID
			}
		}
		qrURL := fmt.Sprintf("%s/access/%s", baseURL, token.ShortID)
		rows = append(rows, []string{token.ShortID, token.PIN, siteShort, qrURL})
	}
	return createSimpleXLSX(rows)
}

func createSimpleXLSX(rows [][]string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := addZipFile(zw, "[Content_Types].xml", contentTypesXML); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, "_rels/.rels", relsXML); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, "xl/workbook.xml", workbookXML); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, "xl/_rels/workbook.xml.rels", workbookRelsXML); err != nil {
		return nil, err
	}
	sheetXML := buildSheetXML(rows)
	if err := addZipFile(zw, "xl/worksheets/sheet1.xml", sheetXML); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildSheetXML(rows [][]string) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	sb.WriteString(`<sheetData>`)
	for i, row := range rows {
		sb.WriteString(fmt.Sprintf(`<row r="%d">`, i+1))
		for j, value := range row {
			cellRef := fmt.Sprintf(`%s%d`, columnName(j+1), i+1)
			sb.WriteString(fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t>`, cellRef))
			xml.EscapeText(&sb, []byte(value))
			sb.WriteString(`</t></is></c>`)
		}
		sb.WriteString(`</row>`)
	}
	sb.WriteString(`</sheetData></worksheet>`)
	return sb.String()
}

func columnName(n int) string {
	result := ""
	for n > 0 {
		n--
		result = string(rune('A'+n%26)) + result
		n /= 26
	}
	return result
}

func addZipFile(zw *zip.Writer, name string, content string) error {
	writer, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write([]byte(content))
	return err
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`

const relsXML = `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`

const workbookXML = `<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Tokens" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>`

const workbookRelsXML = `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`

func (h *Handler) handleAdminGenerateTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.render(w, "admin/generate_tokens.html", map[string]any{
			"Title":     "WireVault Admin · Generate tokens",
			"BodyClass": "admin dashboard",
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		count, _ := strconv.Atoi(r.Form.Get("count"))
		if count <= 0 {
			count = 1
		}
		if count > 50 {
			count = 50
		}
		now := time.Now()
		for i := 0; i < count; i++ {
			token := &models.QRToken{
				ID:        store.NewID(),
				ShortID:   h.uniqueTokenShortID(),
				PIN:       store.GeneratePIN(),
				Status:    models.TokenUnassigned,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := h.Store.SaveToken(token); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		http.Redirect(w, r, "/admin/tokens?msg=Tokens%%20generated&type=success", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) uniqueTokenShortID() string {
	for {
		candidate := h.Store.NextTokenShortID()
		if !h.Store.IsTokenShortIDTaken(candidate, "") {
			return candidate
		}
	}
}

func (h *Handler) handleAdminExportTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "xlsx" {
		h.exportTokensXLSX(w, r)
		return
	}
	h.exportTokensCSV(w, r)
}

func (h *Handler) exportTokensCSV(w http.ResponseWriter, r *http.Request) {
	tokens := h.Store.ListTokens()
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=token-export.csv")
	writer := csv.NewWriter(w)
	defer writer.Flush()
	writer.Write([]string{"tokenShortId", "pin", "siteShortId", "qrUrl"})
	for _, token := range tokens {
		siteShort := ""
		if token.SiteID != "" {
			if site, err := h.Store.GetSiteByID(token.SiteID); err == nil {
				siteShort = site.ShortID
			}
		}
		qrURL := fmt.Sprintf("%s/access/%s", strings.TrimRight(h.Store.GetPublicBaseURL(), "/"), token.ShortID)
		writer.Write([]string{token.ShortID, token.PIN, siteShort, qrURL})
	}
}

func (h *Handler) exportTokensXLSX(w http.ResponseWriter, r *http.Request) {
	tokens := h.Store.ListTokens()
	data, err := buildXLSX(tokens, h)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", "attachment; filename=token-export.xlsx")
	w.Write(data)
}

func (h *Handler) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	tab := sanitizeSettingsTab(r.URL.Query().Get("tab"))
	if tab == "" {
		tab = "users"
	}
	message := strings.TrimSpace(r.URL.Query().Get("msg"))
	messageType := strings.TrimSpace(r.URL.Query().Get("type"))
	var errorMessage string
	formValues := map[string]string{}
	switch r.Method {
	case http.MethodGet:
		// no-op
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		tab = sanitizeSettingsTab(r.Form.Get("tab"))
		if tab == "" {
			tab = "users"
		}
		intent := r.Form.Get("intent")
		switch intent {
		case "create_user":
			message, messageType, errorMessage, formValues = h.handleCreateUserForm(currentUser, r)
			if errorMessage == "" {
				h.redirectSettings(w, r, tab, message, messageType)
				return
			}
		case "update_user":
			message, messageType, errorMessage = h.handleUpdateUserForm(currentUser, r)
			if errorMessage == "" {
				h.redirectSettings(w, r, tab, message, messageType)
				return
			}
		case "delete_user":
			message, messageType, errorMessage = h.handleDeleteUserForm(currentUser, r)
			if errorMessage == "" {
				h.redirectSettings(w, r, tab, message, messageType)
				return
			}
		case "change_password":
			message, messageType, errorMessage = h.handleChangePasswordForm(currentUser, r)
			if errorMessage == "" {
				h.redirectSettings(w, r, "security", message, messageType)
				return
			}
		case "update_public_url":
			message, messageType, errorMessage = h.handleUpdatePublicURLForm(currentUser, r)
			if errorMessage == "" {
				h.redirectSettings(w, r, "security", message, messageType)
				return
			}
		case "update_saml":
			message, messageType, errorMessage = h.handleUpdateSAMLForm(currentUser, r)
			if errorMessage == "" {
				h.redirectSettings(w, r, "sso", message, messageType)
				return
			}
		default:
			http.Error(w, "Unsupported action", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.renderSettingsPage(w, currentUser, tab, message, messageType, errorMessage, formValues)
}

func sanitizeSettingsTab(tab string) string {
	switch strings.ToLower(strings.TrimSpace(tab)) {
	case "users":
		return "users"
	case "security":
		return "security"
	case "sso":
		return "sso"
	default:
		return ""
	}
}

func (h *Handler) redirectSettings(w http.ResponseWriter, r *http.Request, tab, msg, msgType string) {
	values := url.Values{}
	if tab != "" {
		values.Set("tab", tab)
	}
	if msg != "" {
		values.Set("msg", msg)
	}
	if msgType != "" {
		values.Set("type", msgType)
	}
	target := "/admin/settings"
	if encoded := values.Encode(); encoded != "" {
		target = target + "?" + encoded
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (h *Handler) renderSettingsPage(w http.ResponseWriter, currentUser *models.User, tab, message, messageType, errorMessage string, formValues map[string]string) {
	users := h.visibleUsers(currentUser)
	allUsers := h.Store.ListUsers()
	creatorNames := make(map[string]string)
	for _, user := range allUsers {
		creatorNames[user.ID] = user.Username
	}
	ownerCount := h.countOwners()
	data := map[string]any{
		"Title":         "WireVault Admin · Settings",
		"BodyClass":     "admin settings",
		"PublicBaseURL": h.Store.GetPublicBaseURL(),
		"Users":         users,
		"CurrentUser":   currentUser,
		"ActiveTab":     tab,
		"Message":       message,
		"MessageType":   messageType,
		"Error":         errorMessage,
		"CreatorNames":  creatorNames,
		"OwnerCount":    ownerCount,
		"FormValues":    formValues,
		"SAML":          h.Store.GetSAMLSettings(),
	}
	h.render(w, "admin/settings.html", data)
}

func (h *Handler) visibleUsers(currentUser *models.User) []*models.User {
	all := h.Store.ListUsers()
	filtered := make([]*models.User, 0, len(all))
	for _, user := range all {
		if currentUser.Role == models.RoleOwner || user.CreatedBy == currentUser.ID || user.ID == currentUser.ID {
			filtered = append(filtered, user)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(filtered[i].Username))
		right := strings.ToLower(strings.TrimSpace(filtered[j].Username))
		if left == right {
			return filtered[i].CreatedAt.Before(filtered[j].CreatedAt)
		}
		return left < right
	})
	return filtered
}

func (h *Handler) countOwners() int {
	users := h.Store.ListUsers()
	count := 0
	for _, user := range users {
		if user.Role == models.RoleOwner {
			count++
		}
	}
	return count
}

func canManageUser(current, target *models.User) bool {
	if current.Role == models.RoleOwner {
		return true
	}
	if target.ID == current.ID {
		return true
	}
	return target.CreatedBy == current.ID
}

func (h *Handler) handleCreateUserForm(currentUser *models.User, r *http.Request) (string, string, string, map[string]string) {
	values := map[string]string{
		"username": strings.TrimSpace(r.Form.Get("username")),
		"email":    strings.TrimSpace(r.Form.Get("email")),
		"role":     strings.TrimSpace(r.Form.Get("role")),
	}
	password := r.Form.Get("password")
	confirm := r.Form.Get("confirm_password")
	role := models.RoleAdmin
	if currentUser.Role == models.RoleOwner {
		switch strings.ToUpper(values["role"]) {
		case string(models.RoleOwner):
			role = models.RoleOwner
			values["role"] = string(models.RoleOwner)
		default:
			role = models.RoleAdmin
			values["role"] = string(models.RoleAdmin)
		}
	} else {
		values["role"] = string(models.RoleAdmin)
	}
	if values["username"] == "" {
		return "", "", "Username is required.", values
	}
	if h.Store.IsUsernameTaken(values["username"], "") {
		return "", "", "Username is already in use.", values
	}
	if values["email"] != "" && h.Store.IsEmailTaken(values["email"], "") {
		return "", "", "Email is already in use.", values
	}
	if len(password) < 8 {
		return "", "", "Password must be at least 8 characters.", values
	}
	if password != confirm {
		return "", "", "Passwords do not match.", values
	}
	newUser := &models.User{
		Username:  values["username"],
		Email:     values["email"],
		Role:      role,
		CreatedBy: currentUser.ID,
	}
	saved, err := h.Store.SaveUser(newUser)
	if err != nil {
		return "", "", fmt.Sprintf("Failed to create user: %v", err), values
	}
	if err := h.Store.UpdateUserPassword(saved.ID, password); err != nil {
		return "", "", fmt.Sprintf("Failed to set user password: %v", err), values
	}
	return fmt.Sprintf("User %s created", saved.Username), "success", "", map[string]string{}
}

func (h *Handler) handleUpdateUserForm(currentUser *models.User, r *http.Request) (string, string, string) {
	userID := strings.TrimSpace(r.Form.Get("user_id"))
	if userID == "" {
		return "", "", "User not found"
	}
	target, err := h.Store.GetUserByID(userID)
	if err != nil {
		return "", "", "User not found"
	}
	if !canManageUser(currentUser, target) {
		return "", "", "You do not have permission to manage this user."
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	email := strings.TrimSpace(r.Form.Get("email"))
	if username == "" {
		return "", "", "Username is required."
	}
	if h.Store.IsUsernameTaken(username, target.ID) {
		return "", "", "Username is already in use."
	}
	if email != "" && h.Store.IsEmailTaken(email, target.ID) {
		return "", "", "Email is already in use."
	}
	newRole := target.Role
	requestedRole := strings.ToUpper(strings.TrimSpace(r.Form.Get("role")))
	if currentUser.Role == models.RoleOwner {
		if requestedRole == string(models.RoleOwner) {
			newRole = models.RoleOwner
		} else {
			newRole = models.RoleAdmin
		}
	} else {
		newRole = models.RoleAdmin
	}
	if target.ID == currentUser.ID && newRole != models.RoleOwner {
		return "", "", "You cannot change your own role."
	}
	if target.Role == models.RoleOwner && newRole != models.RoleOwner && h.countOwners() <= 1 {
		return "", "", "At least one owner must remain."
	}
	target.Username = username
	target.Email = email
	target.Role = newRole
	target.UpdatedAt = time.Now()
	if _, err := h.Store.SaveUser(target); err != nil {
		return "", "", fmt.Sprintf("Failed to update user: %v", err)
	}
	return "User updated", "success", ""
}

func (h *Handler) handleDeleteUserForm(currentUser *models.User, r *http.Request) (string, string, string) {
	userID := strings.TrimSpace(r.Form.Get("user_id"))
	if userID == "" {
		return "", "", "User not found"
	}
	target, err := h.Store.GetUserByID(userID)
	if err != nil {
		return "", "", "User not found"
	}
	if target.ID == currentUser.ID {
		return "", "", "You cannot delete your own account."
	}
	if !canManageUser(currentUser, target) {
		return "", "", "You do not have permission to manage this user."
	}
	if target.Role == models.RoleOwner && h.countOwners() <= 1 {
		return "", "", "At least one owner must remain."
	}
	if err := h.Store.DeleteUser(userID); err != nil {
		return "", "", fmt.Sprintf("Failed to delete user: %v", err)
	}
	return "User deleted", "success", ""
}

func (h *Handler) handleChangePasswordForm(currentUser *models.User, r *http.Request) (string, string, string) {
	newPassword := strings.TrimSpace(r.Form.Get("new_password"))
	confirm := strings.TrimSpace(r.Form.Get("confirm_password"))
	if newPassword == "" {
		return "", "", "New password is required."
	}
	if len(newPassword) < 8 {
		return "", "", "Password must be at least 8 characters."
	}
	if newPassword != confirm {
		return "", "", "Passwords do not match."
	}
	if currentUser.PasswordHash != "" {
		current := r.Form.Get("current_password")
		if _, ok := h.Store.AuthenticateUser(currentUser.Username, current); !ok {
			return "", "", "Current password is incorrect."
		}
	}
	if err := h.Store.UpdateUserPassword(currentUser.ID, newPassword); err != nil {
		return "", "", "Failed to update password."
	}
	return "Password updated", "success", ""
}

func (h *Handler) handleUpdatePublicURLForm(currentUser *models.User, r *http.Request) (string, string, string) {
	if currentUser.Role != models.RoleOwner {
		return "", "", "You do not have permission to update the base URL."
	}
	publicURL := strings.TrimSpace(r.Form.Get("public_url"))
	if publicURL == "" {
		return "", "", "Base URL is required."
	}
	if _, err := url.ParseRequestURI(publicURL); err != nil {
		return "", "", "Base URL must be a valid URL."
	}
	if err := h.Store.SetPublicBaseURL(publicURL); err != nil {
		return "", "", "Failed to update base URL."
	}
	return "Base URL updated", "success", ""
}

func (h *Handler) handleUpdateSAMLForm(currentUser *models.User, r *http.Request) (string, string, string) {
	if currentUser.Role != models.RoleOwner {
		return "", "", "You do not have permission to update SSO settings."
	}
	settings := h.Store.GetSAMLSettings()
	settings.Enabled = r.Form.Has("enabled")
	settings.AllowIDPInitiated = r.Form.Has("allow_idp_initiated")
	settings.SPBaseURL = r.Form.Get("sp_base_url")
	settings.SPEntityID = r.Form.Get("sp_entity_id")
	settings.SPKeyPEM = r.Form.Get("sp_key")
	settings.SPCertificatePEM = r.Form.Get("sp_certificate")
	settings.IDPMetadataURL = r.Form.Get("idp_metadata_url")
	settings.IDPMetadataXML = r.Form.Get("idp_metadata_xml")
	settings.EmailAttribute = r.Form.Get("email_attribute")
	settings.UsernameAttribute = r.Form.Get("username_attribute")

	var middleware *samlsp.Middleware
	if settings.Enabled {
		mw, err := h.buildSAMLMiddleware(settings)
		if err != nil {
			return "", "", fmt.Sprintf("Failed to validate SSO settings: %v", err)
		}
		middleware = mw
	}
	if err := h.Store.UpdateSAMLSettings(settings); err != nil {
		return "", "", fmt.Sprintf("Failed to persist SSO settings: %v", err)
	}
	h.setSAMLMiddleware(middleware)
	if settings.Enabled {
		return "SSO settings updated", "success", ""
	}
	return "SSO disabled", "success", ""
}

func (h *Handler) RefreshSAML() error {
	settings := h.Store.GetSAMLSettings()
	mw, err := h.buildSAMLMiddleware(settings)
	if err != nil {
		h.setSAMLMiddleware(nil)
		return err
	}
	h.setSAMLMiddleware(mw)
	return nil
}

func (h *Handler) buildSAMLMiddleware(settings models.SAMLSettings) (*samlsp.Middleware, error) {
	if !settings.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(settings.SPBaseURL) == "" {
		return nil, errors.New("service provider base URL is required")
	}
	if strings.TrimSpace(settings.SPEntityID) == "" {
		return nil, errors.New("service provider entity ID is required")
	}
	baseURL, err := url.Parse(strings.TrimSpace(settings.SPBaseURL))
	if err != nil {
		return nil, fmt.Errorf("invalid service provider base URL: %w", err)
	}
	if baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, errors.New("service provider base URL must include scheme and host")
	}
	key, err := parsePrivateKeyPEM(settings.SPKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid service provider private key: %w", err)
	}
	cert, intermediates, err := parseCertificateChain(settings.SPCertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("invalid service provider certificate: %w", err)
	}
	var metadata *saml.EntityDescriptor
	if strings.TrimSpace(settings.IDPMetadataXML) != "" {
		metadata, err = samlsp.ParseMetadata([]byte(settings.IDPMetadataXML))
		if err != nil {
			return nil, fmt.Errorf("unable to parse IdP metadata XML: %w", err)
		}
	} else if strings.TrimSpace(settings.IDPMetadataURL) != "" {
		metadataURL, err := url.Parse(strings.TrimSpace(settings.IDPMetadataURL))
		if err != nil {
			return nil, fmt.Errorf("invalid IdP metadata URL: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		metadata, err = samlsp.FetchMetadata(ctx, http.DefaultClient, *metadataURL)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch IdP metadata: %w", err)
		}
	} else {
		return nil, errors.New("provide either IdP metadata XML or URL")
	}
	spURL := buildServiceProviderURL(baseURL)
	opts := samlsp.Options{
		EntityID:           settings.SPEntityID,
		URL:                *spURL,
		Key:                key,
		Certificate:        cert,
		Intermediates:      intermediates,
		IDPMetadata:        metadata,
		AllowIDPInitiated:  settings.AllowIDPInitiated,
		DefaultRedirectURI: "/admin/sites",
		CookieName:         "wv_saml",
		CookieSameSite:     http.SameSiteLaxMode,
		SignRequest:        true,
	}
	middleware, err := samlsp.New(opts)
	if err != nil {
		return nil, err
	}
	middleware.Session = &samlSessionProvider{handler: h}
	middleware.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Redirect(w, r, "/admin/login?msg="+url.QueryEscape("SSO login failed: "+err.Error())+"&type=error", http.StatusSeeOther)
	}
	return middleware, nil
}

func buildServiceProviderURL(base *url.URL) *url.URL {
	clone := *base
	pathPart := strings.TrimSuffix(clone.Path, "/")
	pathPart = path.Join(pathPart, "/admin/saml")
	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}
	clone.Path = pathPart
	clone.RawQuery = ""
	clone.Fragment = ""
	return &clone
}

func parsePrivateKeyPEM(pemData string) (crypto.Signer, error) {
	data := []byte(strings.TrimSpace(pemData))
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			signer, ok := parsed.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("unsupported private key type %T", parsed)
			}
			return signer, nil
		}
	}
	return nil, errors.New("no private key found in PEM data")
}

func parseCertificateChain(pemData string) (*x509.Certificate, []*x509.Certificate, error) {
	data := []byte(strings.TrimSpace(pemData))
	var cert *x509.Certificate
	intermediates := []*x509.Certificate{}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		if cert == nil {
			cert = parsed
		} else {
			intermediates = append(intermediates, parsed)
		}
	}
	if cert == nil {
		return nil, nil, errors.New("no certificate found in PEM data")
	}
	return cert, intermediates, nil
}

func assertionAttributeValue(assertion *saml.Assertion, name string) string {
	attrName := strings.TrimSpace(name)
	if attrName == "" {
		return ""
	}
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			if strings.EqualFold(attr.Name, attrName) || strings.EqualFold(attr.FriendlyName, attrName) {
				for _, value := range attr.Values {
					if v := strings.TrimSpace(value.Value); v != "" {
						return v
					}
				}
			}
		}
	}
	return ""
}

func (h *Handler) createAdminSessionFromAssertion(w http.ResponseWriter, assertion *saml.Assertion) error {
	settings := h.Store.GetSAMLSettings()
	identifiers := []string{}
	if v := assertionAttributeValue(assertion, settings.EmailAttribute); v != "" {
		identifiers = append(identifiers, v)
	}
	if v := assertionAttributeValue(assertion, settings.UsernameAttribute); v != "" {
		identifiers = append(identifiers, v)
	}
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		if v := strings.TrimSpace(assertion.Subject.NameID.Value); v != "" {
			identifiers = append(identifiers, v)
		}
	}
	for _, ident := range identifiers {
		user, err := h.Store.GetUserByIdentifier(ident)
		if err == nil {
			h.issueAdminSession(w, user)
			return nil
		}
	}
	return fmt.Errorf("no matching admin user for SSO identity")
}

type samlSessionProvider struct {
	handler *Handler
}

func (p *samlSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	return p.handler.createAdminSessionFromAssertion(w, assertion)
}

func (p *samlSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	p.handler.clearAdminCookie(w)
	return nil
}

func (p *samlSessionProvider) GetSession(r *http.Request) (samlsp.Session, error) {
	return nil, samlsp.ErrNoSession
}
