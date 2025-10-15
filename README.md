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

## Deploying with Dokploy

The repository includes a production-ready container definition (`Dockerfile`) and a Dokploy manifest (`deploy/dokploy.yaml`). You can either import the manifest directly in Dokploy or reproduce the steps manually through the UI:

1. **Create a project:** Import this Git repository in Dokploy and choose *Dockerfile* as the deployment method. Point the build context to the repo root and the Dockerfile to `Dockerfile`.
2. **Start command:** Set the start command to `/app/wirevault -addr :8080` (adjust the port if you expose a different internal port).
3. **Expose the web service:** Keep the default HTTP port at `8080`. Dokploy will proxy it through Traefik so you only need to map the internal port.
4. **Persist application data:** Add two Docker volumes and mount them to `/app/data` and `/app/media`. These hold the JSON datastore and uploaded documents respectively.
5. **Health check:** Point Dokploy's health check to `GET /` with a 30-second interval; the route responds with the PIN entry page when healthy.
6. **Deploy:** Trigger a build. Dokploy will compile the Go binary in the first stage, produce the runtime image, and start the container.

If you maintain infrastructure-as-code, check in `deploy/dokploy.yaml` and use Dokploy's Git-based deploys to keep configuration aligned with the repository. The manifest defines the web service, port exposure, persistent volumes, and a basic health probe.
