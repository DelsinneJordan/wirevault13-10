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
- **Customer access shortcuts**: Jump directly to the customer-facing site page from the site list or detail view by selecting an assigned token.
- **Document uploads**: Drag-and-drop friendly forms accept PDFs or images; delete outdated files when needed.
- **Role-based authentication**: Named administrator accounts with owner/admin roles, password management, and optional SAML SSO.

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
- The admin site list surfaces a token selector that links straight to `/access/{tokenShortId}` for quick verification of customer pages.
- Uploaded media is stored on disk; ensure the `media/` directory is writable in deployment environments.

## Deploying with Docker or Portainer

The repository ships with a production-ready `Dockerfile` and a sample Docker Compose stack at `deploy/docker-compose.yml`. You can either run the stack locally with Docker Compose or import it into Portainer as a stack template.

### Compose / Docker Desktop

```bash
# Build and run WireVault
docker compose -f deploy/docker-compose.yml up -d --build

# Tail logs
docker compose -f deploy/docker-compose.yml logs -f wirevault
```

The stack exposes the application on port `8080` and creates two named volumes, `wirevault_data` and `wirevault_media`, for persistent JSON data and uploaded documents. Override the published port or volume bindings in the Compose file if your environment requires different values.

### Portainer deployment

1. **Create a new stack:** In Portainer, choose *Stacks → Add stack* and paste the contents of `deploy/docker-compose.yml` (or upload the file directly).
2. **Adjust variables if needed:** Change the published port or volume bindings to match your infrastructure. You can also add extra environment variables (for example, `WIREVAULT_SAML_METADATA_URL`) to configure optional integrations.
3. **Deploy the stack:** Portainer will build the image from the included Dockerfile, create the necessary volumes, and start the container. Once the stack is healthy, browse to `http://<your-host>:8080` to reach the PIN entry page.

> **Tip:** If you prefer building images externally, push the image to a registry and replace the `build:` section in the Compose file with an `image:` reference before deploying in Portainer.
