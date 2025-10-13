# WireVault

WireVault is a lightweight Go web application that delivers secure, phone-friendly access to mandatory electrical installation documents. Customers unlock a site by scanning its QR code, entering a 5-digit PIN, and browsing boards, appliances, and their documents. Administrators manage all content — sites, boards, appliances, documents, QR tokens, and exports — from a unified dashboard.

## Features

### Customer experience
- **PIN-protected access**: Scan a site QR code, enter the site PIN, and review all boards and appliances.
- **Session security**: 20-minute inactivity timeout ensures access expires automatically.
- **Document library**: Friendly layouts for downloading PDFs or images for each asset.

### Admin experience
- **Site management**: Create sites, edit public/admin-only details, and configure short IDs for URLs.
- **Boards & appliances**: Capture detailed technical metadata and attach documents for every asset.
- **QR tokens**: Batch-generate tokens, edit short IDs or PINs, assign/unassign/retire tokens, and export CSV/XLSX files for sticker production.
- **Document uploads**: Drag-and-drop friendly forms accept PDFs or images; delete outdated files when needed.
- **Simple authentication**: Password-protected admin area with configurable password.

## Technology
- **Language**: Go 1.24 (standard library only).
- **Persistence**: JSON file (`data/app.json`) backed by on-disk media storage (`/media`).
- **Templates**: Go `html/template` with a responsive layout and modern styling.

## Getting started

```bash
# Install Go 1.24 if not present
cd wirevault13-10

# Run the development server
go run ./...
```

The app listens on `http://localhost:8080` by default. Visit `/admin/login` to sign in (default password: `admin`). Generated data and uploaded documents live in `data/` and `media/` respectively.

## Project layout

```
core/
  handlers/        HTTP handlers and routing helpers
  models/          Application data models
  session/         In-memory admin & site session manager
  store/           JSON persistence, document management helpers
static/            Global stylesheet
templates/         Admin & customer page templates
```

## Tests & formatting

```bash
gofmt -w main.go core/**/*.go
# Run application-level checks if desired
```

## Notes
- The admin password defaults to `admin`. Update it immediately from **Settings** in production.
- CSV/XLSX exports include token short IDs, PINs, site short IDs, and fully qualified QR URLs.
- Uploaded media is stored on disk; ensure the `media/` directory is writable in deployment environments.
