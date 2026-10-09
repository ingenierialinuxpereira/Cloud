# AWS Security Assessment

`aws_security_assessment_en_zip.sh` — a **read-only, CIS-aligned security posture assessment** for an AWS account that produces a self-contained, tabbed HTML report.

It answers the question every audit and security review starts with: *"How exposed are we right now?"* — surfacing public resources, weak IAM hygiene, missing encryption, and disabled guardrails across sixteen core services, without enabling any paid security service and without ever changing a thing in the account.

- **Author:** Francisco Gutierrez
- **Version:** 1.0.0

---

## Highlights

- **Strictly read-only.** Every call is a `list`/`describe`/`get`. No resource is created, modified, or deleted — ever.
- **CIS-aligned.** Checks map, where possible, to the CIS AWS Foundations Benchmark, with the relevant control referenced in each finding.
- **Severity-rated findings.** Every issue is classified **Critical**, **Warning**, or **Info**, so the biggest risks rise to the top.
- **Account-wide + regional.** Global services (IAM, S3, Route 53, CloudTrail) are scanned once; regional services are scanned in the selected region — or across every region on request.
- **Interactive.** A simple menu lets you scan everything or pick individual services on demand.
- **Self-contained report.** One HTML file plus an `icons/` folder — no CDN, no internet needed to view it. Tabbed navigation per service, a severity summary, a full service inventory, and light/dark themes.
- **Portable.** `--zip` bundles the report and its icons into a single shareable archive.

---

## What it checks

Sixteen services have a dedicated deep scanner:

| Category | Service | Representative checks |
|---|---|---|
| Identity | **IAM** | Root MFA & access keys, password policy, key age/rotation, unused credentials, console users without MFA, direct/admin policy attachments |
| Storage | **S3** | Public bucket policy/ACL, account & bucket Block Public Access, default encryption, versioning, access logging |
| Compute | **EC2 / EBS** | Public IPs, public AMIs, IMDSv2 enforcement, unencrypted volumes, EBS default-encryption |
| Network | **VPC / Security Groups** | Default security group rules, VPC flow logs |
| Databases | **RDS** | Public accessibility, storage encryption, automated backups, deletion protection |
| Containers | **EKS** | Public API endpoint exposure, control-plane logging, secrets (KMS) encryption |
| Serverless | **Lambda** | Public invoke permissions, deprecated runtimes, VPC attachment, secrets in env vars |
| Registry | **ECR** | Public repository policy, scan-on-push, tag immutability |
| Secrets | **Secrets Manager** | Public resource policy, rotation, customer-managed keys |
| Messaging | **SNS / SQS** | Public topic/queue policy, encryption at rest |
| Encryption | **KMS** | Public key policy, key rotation |
| Audit | **CloudTrail** | Trail existence, multi-region coverage, logging status, log-file validation, KMS encryption |
| Threat detection | **GuardDuty** | Enablement |
| Config | **AWS Config** | Recorder enabled and running |
| DNS | **Route 53** | DNSSEC on public zones |

---

## Requirements

- **Bash 4+** (Linux, macOS, or WSL)
- **AWS CLI v2**, authenticated (`aws configure`, SSO, or an assumed role)
- **jq**
- **Read-only IAM permissions** — the AWS-managed `SecurityAudit` (or `ReadOnlyAccess`) policy covers everything
- Optional: `zip` for the `--zip` packaging flag

---

## Quick start

```bash
chmod +x aws_security_assessment_en_zip.sh

# Scan the current/default region, then pick from the menu
./aws_security_assessment_en_zip.sh

# Target a specific region
./aws_security_assessment_en_zip.sh us-east-1

# Use a named profile
AWS_PROFILE=prod ./aws_security_assessment_en_zip.sh us-east-1

# Run regional scanners across every enabled region
AWS_SCAN_ALL_REGIONS=1 ./aws_security_assessment_en_zip.sh

# Package the report + icons into a portable zip
./aws_security_assessment_en_zip.sh --zip
```

When it starts you'll get a menu:

1. **Scan ALL services**
2. **Scan services ON-DEMAND** (choose specific ones)
3. **Exit**

### Output

- `aws_assessment_<account-id>_<timestamp>.html` — the report
- `icons/` — SVG/PNG assets referenced by the report (**keep it next to the HTML file** when moving it)
- `aws_assessment_<...>.zip` — created only with `--zip`

Open the HTML in any browser. The report opens on a severity summary, with one tab per scanned service and a full **Service Inventory** tab.

---

## Configuration

Most behavior is controlled by flags and environment variables; a few thresholds live as constants near the top of the script:

| Setting | Default | Purpose |
|---|---|---|
| `REGION` (positional arg) | current/default region | Region for regional scanners. |
| `AWS_PROFILE` (env) | — | Standard AWS CLI profile selection. |
| `AWS_SCAN_ALL_REGIONS` (env) | `0` | Set `1` to run regional scanners in every enabled region. |
| `--zip` (flag) | off | Package report + icons into one archive. |
| `ICONS_DIR` (env) | `./icons` next to the script | Location of the icon assets. |
| `KEY_WARN_DAYS` | `90` | Access-key age that triggers a Warning. |
| `KEY_CRIT_DAYS` | `365` | Access-key age that triggers a Critical. |
| `INACTIVE_DAYS` | `90` | Unused-credential age that triggers a Warning. |

---

## How it works

1. **Dependencies & context** — verifies Bash/`aws`/`jq`, then resolves the account and region(s) via `sts get-caller-identity`.
2. **Discovery** — prepares the deep scanners and prints the coverage plan.
3. **Menu** — you choose to scan everything or select services.
4. **Scanning** — each scanner runs read-only API calls, records severity-rated findings, and tolerates denied permissions or empty results without stopping.
5. **Report** — assembles a tabbed HTML dashboard with a severity rollup, per-service findings, and a service inventory, then optionally zips it.

---

## Notes & limitations

- This is a **point-in-time posture assessment** (configuration/CSPM style), complementary to continuous runtime threat detection such as GuardDuty — it reports whether GuardDuty is enabled rather than replacing it.
- A service with no findings is shown as clean; a denied permission is handled gracefully and simply yields no findings for that check.
- CIS references are provided as guidance and are not a substitute for a formal, attested CIS audit.

---

## Companion tools

Part of a small family of read-only cloud scanners: `gcp_security_assessment_en_zip.sh` (the GCP equivalent) and the `aws_inventory_scan.sh` / `gcp_inventory_scan.sh` inventory tools.
