# GCP Inventory Scanner

`gcp_inventory_scan.sh` — a dependency-light Bash tool that performs a **deep, read-only inventory** of the current Google Cloud project and produces a self-contained HTML dashboard.

It answers a deceptively hard question: *"Which GCP services are we actually using, and in which regions?"* — without touching Cloud Asset Inventory (no `cloudasset.assets.*` permissions required). It works purely from enabled-API listing plus native `gcloud` calls.

---

## Highlights

- **Read-only.** Every call is a `list`/`get`. No writes, ever.
- **No Cloud Asset Inventory.** Lists enabled APIs via `serviceusage`, then verifies real usage with targeted `gcloud` calls.
- **Three-state classification.** Every service is labelled:
  - **Active** — resources / usage detected
  - **Passive** — API enabled, but no live resources found
  - **Enabled** — API enabled, no deep sub-check exists for it
- **Multi-region identification.** Each deep check records the region, zone, or location of every resource it finds (Vertex AI is probed across all major regions), so the report shows exactly which regions of the project are in use and by which services.
- **Baseline-aware.** Internal / auto-enabled Google APIs are tagged as **System / Baseline** rather than hidden, so nothing ever silently disappears from the inventory.
- **Self-contained report.** One HTML file plus an `icons/` folder — no CDN, no fonts, no internet needed to view it. Dark mode follows your OS automatically.
- **Terminal UI.** A pinned progress banner with a live progress bar and spinner in interactive terminals; clean scrolling logs in CI.

---

## What it checks

| Category | Services (deep-checked) |
|---|---|
| Compute & Containers | Compute Engine, GKE, Cloud Run |
| AI & Machine Learning | Vertex AI / Gemini (endpoints + models, across many regions) |
| Serverless | Cloud Functions (Gen1 + Gen2) |
| Messaging & Integration | Pub/Sub (topics + subscriptions) |
| Databases | Cloud SQL |
| Storage | Cloud Storage |
| Firebase & Mobile | Firebase (association check via REST) |

Beyond these deep checks, **every enabled API** is discovered, grouped into a service category, and rendered — so the report is a full inventory, not just the deep-checked subset.

> Adding a new check is easy: write a `check_x` function and add one row to the `SUBCHECK_APIS` registry. Service categories are driven by editable regex rules (`CATEGORY_RULES`) near the top of the script.

---

## Requirements

- **Bash** (Linux, macOS, or WSL)
- **gcloud CLI**, installed and authenticated (`gcloud auth login`)
- **Read-only IAM permissions** (see below)
- Optional: `curl` (for the Firebase association check), `timeout` (GNU coreutils) for per-command timeouts, and `zip` for report packaging

---

## Quick start

```bash
chmod +x gcp_inventory_scan.sh

# Scan the current gcloud project
./gcp_inventory_scan.sh

# Also package the report + icons into a portable zip
./gcp_inventory_scan.sh --zip
```

This scans **only** the project currently active in your gcloud config. To scan a different project, switch first:

```bash
gcloud config set project PROJECT_ID
```

### Output

- `gcp_services_inventory.html` — the dashboard
- `icons/` — SVG assets referenced by the report (**keep this folder next to the HTML file** when moving it)
- `gcp_services_inventory.zip` — created only with `--zip`

Open the HTML in any browser. The report includes a key-metrics grid, an executive summary (regions-in-use, per-category, and per-project rollups), and tabbed detail views.

---

## Configuration

All knobs live in the **EDITABLE CONFIGURATION** block at the top of the script. The most useful ones:

| Variable | Default | Purpose |
|---|---|---|
| `PROGRESS_MODE` | `auto` | `auto`, `tui` (force the pinned progress display), or `plain` (scrolling logs — best for CI). |
| `VERTEX_REGIONS` | 15 major regions | Regions probed for Vertex AI. Each adds ~2–4 seconds; trim to speed up scans. |
| `API_BLACKLIST` | baseline set | Regex fragments for internal/baseline APIs tagged as **System / Baseline**. |
| `CATEGORY_RULES` | see script | Regex → category mapping that drives the report tabs (first match wins). |
| `HIDE_BASELINE` | `false` | Set `true` to suppress baseline APIs entirely. |
| `ZIP_REPORT` | `false` | Package the report + icons after every scan (same as `--zip`). |
| `REPORT_FILE` | `gcp_services_inventory.html` | Output path for the report. |
| `ASSETS_DIR` | `icons` | Folder for the SVG icons. |
| `CMD_TIMEOUT` | `45` | Per-command timeout in seconds (needs `timeout`; skipped gracefully if absent). |
| `AUTHOR` / `VERSION` | — | Shown in the banner and report footer. |

---

## How it works

1. **Resolve the project** — reads the active project from `gcloud config`.
2. **List enabled APIs** — via `serviceusage.services.list`.
3. **Deep sub-checks** — runs targeted `gcloud` calls per high-value service to confirm real resources, recording the region/zone/location of each one. Every call is wrapped in a helper that applies a timeout and silences errors so a disabled API or missing permission never breaks the loop.
4. **Classify & tally** — marks each service Active / Passive / Enabled, tags baseline APIs, and aggregates a regions-in-use view.
5. **Render** — writes the SVG icons and assembles a single HTML dashboard.

> **Firebase note:** there is no native `gcloud firebase projects list`, so the script queries the Firebase Management REST API directly with the session's access token (an HTTP 200 means the project is Firebase-enabled). This needs `curl`; if it's missing, the check reports gracefully instead of failing.

---

## Minimum IAM permissions

The simplest option is to grant **`roles/viewer`** on the project (or at the folder/org level) — it includes everything below.

For least privilege, a custom role with these permissions is sufficient:

```
resourcemanager.projects.get       # project access
serviceusage.services.list         # enabled API listing
container.clusters.list            # GKE
aiplatform.endpoints.list
aiplatform.models.list             # Vertex AI
firebase.projects.get              # Firebase association check
pubsub.topics.list
pubsub.subscriptions.list          # Pub/Sub
cloudfunctions.functions.list      # Cloud Functions
compute.instances.list             # Compute Engine
storage.buckets.list               # Cloud Storage
run.services.list                  # Cloud Run
cloudsql.instances.list            # Cloud SQL
```

**Not required:** any `cloudasset.assets.*` permission, or any write permission. The scan is 100% read-only.

---

## Notes & limitations

- A **Passive** result means the API is enabled but the deep check found no live resources; an **Enabled** result means no deep check exists for that API yet.
- Vertex AI is probed region by region, so the Vertex check is the main driver of scan time — trim `VERTEX_REGIONS` if you only operate in a few regions.
- Permission and timeout issues are surfaced as warnings rather than failing the scan.
- On stock macOS without GNU `timeout`, per-command timeouts are skipped gracefully.

---

## Companion tool

A matching AWS scanner, `aws_inventory_scan.sh`, mirrors this design for AWS (regions there play the role that the single project plays here).
