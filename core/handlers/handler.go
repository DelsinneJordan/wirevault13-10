package handlers

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"wirevault/core/models"
	"wirevault/core/session"
	"wirevault/core/store"
)

type Handler struct {
	Store     *store.Store
	Sessions  *session.SessionManager
	Templates *template.Template
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
	mux.HandleFunc("/admin/logout", h.handleAdminLogout)
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
	viewData["ContentTemplate"] = templateName + "#content"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.Templates.ExecuteTemplate(w, templateName, viewData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		password := r.Form.Get("password")
		if h.Store.VerifyAdminPassword(password) {
			token := h.Sessions.CreateAdminSession()
			http.SetCookie(w, &http.Cookie{
				Name:     adminCookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int((12 * time.Hour).Seconds()),
			})
			http.Redirect(w, r, "/admin/sites", http.StatusSeeOther)
			return
		}
		h.render(w, "admin/login.html", map[string]any{
			"Title":     "WireVault Admin",
			"BodyClass": "admin auth",
			"Error":     "Incorrect password.",
		})
		return
	}
	h.render(w, "admin/login.html", map[string]any{
		"Title":     "WireVault Admin",
		"BodyClass": "admin auth",
	})
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return false
	}
	if !h.Sessions.ValidateAdmin(cookie.Value) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return false
	}
	return true
}

func (h *Handler) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(adminCookieName)
	if err == nil {
		h.Sessions.RevokeAdmin(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   adminCookieName,
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (h *Handler) handleAdminSites(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
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
	sort.Slice(sites, func(i, j int) bool {
		return strings.ToLower(sites[i].Address) < strings.ToLower(sites[j].Address)
	})
	h.render(w, "admin/sites.html", map[string]any{
		"Title":       "WireVault Admin · Sites",
		"BodyClass":   "admin dashboard",
		"Sites":       sites,
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
	if !h.requireAdmin(w, r) {
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
	if !h.requireAdmin(w, r) {
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
	if !h.requireAdmin(w, r) {
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
	if !h.requireAdmin(w, r) {
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
	if !h.requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.render(w, "admin/settings.html", map[string]any{
			"Title":         "WireVault Admin · Settings",
			"BodyClass":     "admin settings",
			"PublicBaseURL": h.Store.GetPublicBaseURL(),
			"Message":       r.URL.Query().Get("msg"),
			"MessageType":   r.URL.Query().Get("type"),
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		if newPassword := strings.TrimSpace(r.Form.Get("new_password")); newPassword != "" {
			if len(newPassword) < 6 {
				h.render(w, "admin/settings.html", map[string]any{
					"Title":         "WireVault Admin · Settings",
					"BodyClass":     "admin settings",
					"PublicBaseURL": h.Store.GetPublicBaseURL(),
					"Error":         "Password must be at least 6 characters.",
				})
				return
			}
			h.Store.UpdateAdminPassword(newPassword)
		}
		if publicURL := strings.TrimSpace(r.Form.Get("public_url")); publicURL != "" {
			h.Store.SetPublicBaseURL(publicURL)
		}
		http.Redirect(w, r, "/admin/settings?msg=Settings%20updated&type=success", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}
