Mission (what this app must do)

WireVault lets a customer scan a site-level QR code, enter a 5-digit PIN, and then browse a site overview that lists:

Boards (electrical cabinets) with technical details and documents.

Appliances grouped by category (Solar Inverters, ESS, Heat Pumps, Electric Boilers, Gas Boilers, EV Chargers), each with fields and documents.

Admins use a dashboard to manage Sites, Boards, Appliances, Documents, and QR tokens (including batch generation and CSV/XLSX export). This repo already implements a lightweight version of that flow; your job is to extend and maintain it exactly within the ground rules below. 
GitHub

Ground rules (non-negotiables)

Privacy on customer pages
Show only the site address. Never show customer names or other personal data on customer-facing pages. Admin views may see/edit customer info.

QR & PIN policy

QR codes are site-level (not board-level).

Each site can have one or more QR tokens.

PINs are plaintext (not security-critical in this version).

A valid PIN is any active token PIN assigned to the site.

After a valid PIN, start a short-lived site session (~20 min inactivity).

Start fresh (no legacy)
Do not implement or maintain board-level QR routes and do not migrate/backfill legacy data.

Documents everywhere
Every Board or Appliance can have multiple documents (PDF/photos) attached and downloadable.

Origin-safe redirects
When building redirect URLs, derive origin (scheme + host + port) from the incoming request headers (no hardcoded localhost) so LAN/proxy scenarios work.

What success looks like (acceptance checklist)

Customer scans a site QR, enters PIN, and sees a clean site overview (address only) with:

a Boards section (open detail → fields + docs),

an Appliances section grouped by category (open detail → fields + docs).

Admin can:

Create/edit Sites (address + admin-only info); change site shortId.

Create/edit Boards (all electrical fields) and attach documents.

Create/edit Appliances (common & category-specific fields) and attach documents.

Generate tokens in batches, edit token shortId and PIN, assign/unassign/retire, and export CSV/XLSX with tokenShortId, pin, siteShortId (if assigned), and qrUrl.

Sessions expire after inactivity; expired customers must re-enter the PIN.

Customer pages never display personal names; only the site address.

Vocabulary (use these terms precisely)

Site: A physical location. Public pages show address only; customer name is admin-only.

Board: An electrical cabinet at the site; has technical fields and documents.

Appliance: One of: Solar Inverter, ESS, Heat Pump, Electric Boiler, Gas Boiler, EV Charger; has common and category-specific fields, and documents.

QR Token: (tokenShortId, PIN) pair printed on stickers and assigned to a Site. Multiple tokens may point to the same Site.

Documents: PDFs/images attached to Boards or Appliances and downloadable by customers.

Admin behavior (end-to-end expectations)

Sites

Create/Edit: site shortId, address (public), plus customer name + notes (admin-only).

Change the site shortId safely (downstream links/exports should reflect the new value).

Site list entries expose assigned-token shortcuts: keep the "Open customer page" selector and button that navigate to `/access/{tokenShortId}` for a quick public-page check.

Boards

Create/Edit: board shortId, name, and fields:

Type (main distribution / sub-distribution / final circuits)

Supply type (single-phase / three-phase)

Voltage (e.g., 230V, 400V)

Earthing system (TN-S, TN-C-S, TT, IT)

Incoming cable (e.g., 5G6 CCA)

Rated current (In), Frequency (Hz), Solar (Yes/No), Description

Last inspection date, Next inspection due

Upload/Delete Board documents (PDF/photos).

Appliances

Add appliance → pick category. Edit common fields (Name, Brand, Model, Serial, Voltage, Power kW, Install date, Notes) + category extras, for example:

Inverter: MPPT count

ESS: Capacity (kWh)

EV Charger: Connector (Type 2), phases (1P/3P)

Gas boiler: Fuel type

Upload/Delete Appliance documents.

Tokens

Batch-generate tokens (random tokenShortId and 5-digit PIN, plaintext).

Mark tokens UNASSIGNED, ASSIGNED, or RETIRED.

Assign/Unassign tokens to Sites (many tokens per Site).

Site detail views show a "View access page" button beneath each assigned token alongside the Unassign control.

Edit token PIN and tokenShortId at any time.

Export CSV/XLSX including: tokenShortId, pin, siteShortId (if assigned), qrUrl (what the sticker QR points to).

Note: The README in this repo already describes core behaviors (customer PIN flow, admin management, CSV/XLSX exports) and deployment notes. Keep new work consistent with that behavior. 
GitHub

Customer behavior (end-to-end expectations)

Scan a Site QR → enter 5-digit PIN.

If the PIN matches any active token for the Site:

Start a short site session (~20 minutes of inactivity).

Show Site overview with address only at the top.

Overview contains:

Boards list → open detail page for fields + documents.

Appliances grouped by category → open detail page for fields + documents.

Document links download directly. If the session expires, require the PIN again.

Repository map (agent orientation)

core/handlers/ — HTTP handlers and routing helpers.

core/models/ — Application data models.

core/session/ — In-memory session management for admin & site sessions.

core/store/ — JSON persistence helpers and document management.

templates/ — Admin and customer HTML templates.

static/ — CSS and public assets.

deploy/ — Dokploy manifest for containerized deployment.

Dockerfile — Multi-stage build for production image.

README.md — Human-oriented quickstart & deployment notes. 
GitHub

Setup & run (for agents)

Dev server:
From repo root:

go run ./...


The app listens on http://localhost:8080 by default. Admin login is at /admin/login with a default password (see README; change it ASAP in production). Uploaded documents live under media/, app data under data/. 
GitHub

Formatting:

gofmt -w main.go core/**/*.go


(Run this before every commit.) 
GitHub

Container & Dokploy:
This repo includes a production Dockerfile and a Dokploy manifest; Dokploy will build and run the service, proxy port 8080, and mount volumes for /app/data and /app/media. Keep those paths stable. 
GitHub

Agent playbook (how to execute common tasks)

Add a new Appliance category

Extend the allowed category list.

Add any category-specific fields to forms and detail templates.

Ensure create/edit paths validate and persist these fields.

Update overview grouping to list the new category.

Add document upload support (same pattern as other appliances).

Add/edit Board fields

Add fields to forms & templates.

Validate user input and persist.

Ensure public detail page renders the new fields.

If fields affect exports/labels, update those too.

Implement/adjust CSV/XLSX export

Include tokenShortId, pin, siteShortId (if assigned), qrUrl.

For qrUrl, construct the public link that the QR should point to.

Follow the repository’s existing export approach and MIME types.

Fix “customer privacy” regressions

Search templates for customer names on public pages; remove/replace with address.

Keep full details in admin views only.

Origin-safe redirect bug
Use request headers (Host, X-Forwarded-Proto, etc.) to build absolute URLs so it works from LAN or a reverse proxy; do not hardcode localhost.

Quality gates (don’t merge without)

Manual smoke tests

PIN flow: invalid PIN shows friendly error; valid PIN starts session and lands on site overview.

Overview shows address only, lists Boards & Appliances correctly.

Board/Appliance details render fields and allow doc downloads.

Session expiry returns user to PIN prompt.

Admin: can create/edit sites, boards, appliances; upload/delete docs.

Tokens: batch generate, assign/unassign/retire, edit PIN and tokenShortId, export CSV/XLSX; exported qrUrl opens the site PIN page.

Formatting
Run gofmt on touched files.

No hardcoded hosts
Redirects and links must work when accessed from another machine on the LAN and behind a proxy.

Privacy check
Public pages contain no customer names.

PR etiquette (for agents)

Commit style: small, focused commits with clear messages (“feat: export tokens as XLSX”, “fix: address-only header on public pages”).

Before pushing: run gofmt, re-run smoke tests, and update README if you changed operator workflows (exports, paths, or defaults).

PR title: feat|fix|chore: <short description>

PR body: what changed, why, and how to test it.
