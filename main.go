package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wirevault/core/handlers"
	"wirevault/core/models"
	"wirevault/core/session"
	"wirevault/core/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP network address")
	flag.Parse()

	st, err := store.New(filepath.Join("data", "app.json"), "media")
	if err != nil {
		log.Fatalf("failed to initialise store: %v", err)
	}

	tmpl, err := loadTemplates()
	if err != nil {
		log.Fatalf("failed to load templates: %v", err)
	}

	sessions := session.New(12*time.Hour, 20*time.Minute)

	handler := &handlers.Handler{
		Store:     st,
		Sessions:  sessions,
		Templates: tmpl,
	}

	if err := handler.RefreshSAML(); err != nil {
		log.Printf("SAML configuration not loaded: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Printf("WireVault listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func loadTemplates() (*template.Template, error) {
	funcMap := template.FuncMap{
		"formatDateTime": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.Format("02 Jan 2006 15:04")
		},
		"categoryLabel": func(cat models.ApplianceCategory) string {
			return string(cat)
		},
		"currentYear": func() int {
			return time.Now().Year()
		},
		"assetURL": func(path string) string {
			if path == "" {
				return ""
			}
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			if !strings.HasPrefix(path, "/static/") {
				return path
			}
			relPath := strings.TrimPrefix(path, "/")
			info, err := os.Stat(relPath)
			if err != nil {
				return path
			}
			return fmt.Sprintf("%s?v=%d", path, info.ModTime().Unix())
		},
	}
	files := []string{
		"templates/base.html",
		"templates/home.html",
		"templates/privacy.html",
		"templates/core/pin_entry.html",
		"templates/core/site_lookup.html",
		"templates/core/site_overview.html",
		"templates/core/board_detail.html",
		"templates/core/appliance_detail.html",
		"templates/core/session_expired.html",
		"templates/admin/login.html",
		"templates/admin/sites.html",
		"templates/admin/site_detail.html",
		"templates/admin/board_form.html",
		"templates/admin/appliance_form.html",
		"templates/admin/token_list.html",
		"templates/admin/generate_tokens.html",
		"templates/admin/settings.html",
	}
	tmpl := template.New("base.html").Funcs(funcMap)
	return tmpl.ParseFiles(files...)
}
