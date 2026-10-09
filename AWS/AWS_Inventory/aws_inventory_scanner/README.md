# AWS Inventory Scanner

`aws_inventory_scan.sh` — a dependency-light Bash tool that performs a **deep, read-only inventory** of an AWS account and produces a self-contained HTML dashboard.

It answers a deceptively hard question: *"Which AWS services are we actually using, and in which regions?"* — without touching AWS Config, CloudTrail, or Resource Explorer. It uses nothing but plain `list`/`describe` calls through the AWS CLI.

---

## Highlights

- **Read-only.** Every call is a `list`/`describe`/`get`. No writes, ever.
- **No heavy dependencies.** No AWS Config, CloudTrail, or Resource Explorer — just the AWS CLI v2.
- **Resource-level truth.** For each high-value service it runs a targeted "deep check" to confirm whether resources are actually deployed, rather than just reporting that an API exists.
- **Region-aware.** Scans region by region and reports a per-region rollup, plus a dedicated **Global** tab for account-wide services (S3, CloudFront).
- **Self-contained report.** Emits one HTML file plus an `icons/` folder — no CDN, no fonts, no internet needed to view it. Dark mode follows your OS automatically.
- **Terminal UI.** A pinned progress banner with a live progress bar and spinner in interactive terminals; clean scrolling logs in CI.

---

## What it checks

| Category | Services (deep-checked) |
|---|---|
| Compute & Containers | EC2, EKS, ECS |
| AI & Machine Learning | SageMaker (endpoints + models) |
| Serverless | Lambda |
| Messaging & Integration | SNS, SQS |
| Databases | RDS, DynamoDB |
| Web & Mobile | Amplify |
| Storage & CDN *(Global)* | S3, CloudFront |

Each service is classified as either **Active with Resources** or **No Active Resources Found**. Global services are always scanned once, in their own tab, regardless of the region scope.

> Adding a new check is easy: write a `check_x` function and add one row to the `REGIONAL_CHECKS` (or `GLOBAL_CHECKS`) registry near the top of the script.

---

## Requirements

- **Bash** (Linux, macOS, or WSL)
- **AWS CLI v2**, installed and authenticated (`aws configure` or `aws sso login`)
- **Read-only IAM permissions** (see below)
- Optional: `timeout` (GNU coreutils) for per-command timeouts, and `zip` for report packaging

---

## Quick start

```bash
chmod +x aws_inventory_scan.sh

# Scan the current region + Global services (default)
./aws_inventory_scan.sh

# Scan every enabled region + Global
./aws_inventory_scan.sh --all

# Scan specific regions + Global
./aws_inventory_scan.sh us-east-1 eu-west-1

# Also package the report + icons into a portable zip
./aws_inventory_scan.sh --zip
```

### Output

- `aws_services_inventory.html` — the dashboard
- `icons/` — SVG assets referenced by the report (**keep this folder next to the HTML file** when moving it)
- `aws_services_inventory.zip` — created only with `--zip`

Open the HTML in any browser. The report includes a key-metrics grid, an executive summary (per-category and per-region rollups), and tabbed detail views.

---

## Configuration

All knobs live in the **EDITABLE CONFIGURATION** block at the top of the script. The most useful ones:

| Variable | Default | Purpose |
|---|---|---|
| `SCAN_SCOPE` | `current` | `current` (active region only) or `all` (every enabled region). Command-line arguments always override this. |
| `PROGRESS_MODE` | `auto` | `auto`, `tui` (force the pinned progress display), or `plain` (scrolling logs — best for CI). |
| `HIDE_EMPTY` | `false` | Set `true` to render only services that have resources. |
| `ZIP_REPORT` | `false` | Package the report + icons after every scan (same as `--zip`). |
| `REPORT_FILE` | `aws_services_inventory.html` | Output path for the report. |
| `ASSETS_DIR` | `icons` | Folder for the SVG icons. |
| `CMD_TIMEOUT` | `45` | Per-command timeout in seconds (needs `timeout`; skipped gracefully if absent). |
| `AUTHOR` / `VERSION` | — | Shown in the banner and report footer. |

**Scope precedence:** an explicit region list on the command line wins, then `--all`, then `SCAN_SCOPE`.

---

## How it works

1. **Identify the caller** — resolves the account ID and ARN via `sts get-caller-identity`.
2. **Discover regions** — uses the explicit list, all enabled regions (`ec2 describe-regions`), or the current CLI region depending on scope.
3. **Deep sub-checks** — runs targeted CLI calls per service and counts real resources. Every call is wrapped in a helper that applies a timeout, disables the pager, and silences errors so a denied permission or unsupported region never breaks the loop.
4. **Classify & tally** — marks each service Active or Empty and updates per-region and per-category counters.
5. **Render** — writes the SVG icons and assembles a single HTML dashboard.

---

## Minimum IAM permissions

The simplest option is to attach an AWS-managed read-only policy such as **`ReadOnlyAccess`** (broad) or **`SecurityAudit`** / **`ViewOnlyAccess`** (narrower).

For least privilege, a custom policy `Allow`ing the following on `*` is sufficient:

```
sts:GetCallerIdentity          # account identification
ec2:DescribeRegions            # region discovery (--all mode)
eks:ListClusters               # EKS
sagemaker:ListEndpoints
sagemaker:ListModels           # SageMaker
amplify:ListApps               # Amplify
sns:ListTopics
sqs:ListQueues                 # Messaging
lambda:ListFunctions           # Lambda
ec2:DescribeInstances          # EC2
rds:DescribeDBInstances        # RDS
dynamodb:ListTables            # DynamoDB
ecs:ListClusters               # ECS
s3:ListAllMyBuckets            # S3 (global)
cloudfront:ListDistributions   # CloudFront (global)
```

**Not required:** AWS Config, CloudTrail, Resource Explorer, or any write permission. The scan is 100% read-only.

---

## Notes & limitations

- A "No Active Resources Found" result can also mean the check timed out or a specific permission was denied — permission and timeout issues are surfaced as warnings, not silently.
- Only the services listed above are deep-checked; the tool is intentionally focused on high-value services rather than an exhaustive audit of every AWS API.
- On stock macOS without GNU `timeout`, per-command timeouts are skipped gracefully.

---

## Companion tool

A matching GCP scanner, `gcp_inventory_scan.sh`, mirrors this design for Google Cloud (projects play the role that regions play here).
