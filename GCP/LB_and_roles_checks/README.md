# 🛡 GCP Security Assessment Scanner

> **Author:** Francisco Gutierrez  
> **Company:** Amrize  
> **Version:** 2.0 — Improved Scanner with HTML / CSV / TXT Reports

---

## 📋 Overview

A production-ready Bash script that performs a comprehensive security assessment across your Google Cloud Organization. It scans all active projects (excluding `legacy` folders), audits external Load Balancer exposure, checks Cloud Armor WAF coverage, and identifies IAM primitive role hygiene risks.

At the end of the scan it generates three report formats:

| Format | File | Contents |
|--------|------|----------|
| 🌐 HTML | `gcp_security_assessment_<date>.html` | Interactive tabbed dashboard with dark theme |
| 📊 CSV | `gcp_lb_cloudarmor_<date>.csv` | Load Balancer & Cloud Armor findings |
| 📊 CSV | `gcp_iam_primitive_<date>.csv` | IAM primitive role bindings |
| 📄 TXT | `gcp_security_summary_<date>.txt` | Plain text executive summary |

---

## 🔍 What It Scans

### 1. Load Balancer & Cloud Armor Assessment
- Detects all **External Load Balancers** (HTTP/HTTPS/SSL Proxy/TCP Proxy) with public-facing IPs
- Maps forwarding rules → target proxies → URL maps → backend services
- Checks whether a **Cloud Armor security policy** is attached to each backend
- Flags unprotected backends as **CRITICAL**

### 2. IAM Hygiene & Blast Radius
- Scans every in-scope project for **primitive roles**: `roles/owner`, `roles/editor`, `roles/viewer`
- Flags **external/personal identities** (gmail.com or non-company domain) as **CRITICAL**
- Flags `roles/owner` or `roles/editor` on user accounts as **HIGH**
- Risk levels: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW`

### 3. Scope Control
- Dynamically resolves the **Organization ID** for `amrize.org`
- Automatically **excludes** all folders named `legacy` and their child projects/subfolders

---

## 🚀 Quick Start

### Prerequisites

1. **gcloud CLI** installed and authenticated:
   ```bash
   gcloud auth login
   gcloud auth application-default login
   ```

2. Your account needs the following **IAM permissions** at org level:
   - `compute.forwardingRules.list`
   - `compute.backendServices.list`
   - `compute.securityPolicies.list`
   - `compute.targetHttpsProxies.list`
   - `compute.urlMaps.list`
   - `resourcemanager.projects.getIamPolicy`
   - `resourcemanager.folders.list`
   - `resourcemanager.projects.list`

   > Recommended role: `roles/viewer` + `roles/securityReviewer` at org level.

3. **python3** must be available in PATH (used for JSON parsing).

---

### Installation

```bash
# Clone or copy the script to your working directory
chmod +x gcp_security_assessment.sh
```

---

### Usage

```bash
# Auto-detect org ID for amrize.org
./gcp_security_assessment.sh

# Specify org ID explicitly (faster)
./gcp_security_assessment.sh --org-id 123456789012

# Specify org ID and custom output directory
./gcp_security_assessment.sh --org-id 123456789012 --output-dir /tmp/gcp-reports
```

---

## ⏱ Preventing Cloud Shell Disconnection

> ⚠️ **Important:** GCP Cloud Shell disconnects after **~20 minutes of inactivity**. For large organizations this scan can take 30–90 minutes. The session can disconnect **before the script starts**, **between API calls**, or **mid-execution**. Use the strategies below to prevent this.

---

### 🏆 Recommended: `tmux` + `nohup` Combined (Safest)

Using both together gives you a reconnectable session **and** a process that survives even if the session is killed:

```bash
# Step 1 — Start a tmux session
tmux new -s gcp-scan

# Step 2 — Inside tmux, run with nohup so it survives even if tmux dies
nohup ./gcp_security_assessment.sh --org-id YOUR_ORG_ID \
  --output-dir ./reports > scan_output.log 2>&1 &

echo "Script running with PID: $!"

# Step 3 — Watch live output
tail -f scan_output.log

# Step 4 — If Cloud Shell disconnects, reconnect and resume watching:
tmux attach -t gcp-scan
tail -f scan_output.log
```

---

### Method 1 — `tmux` (Reconnectable session)

Creates a persistent terminal session that survives browser disconnections.

```bash
# Start session
tmux new -s gcp-scan

# Run script inside it
./gcp_security_assessment.sh --org-id YOUR_ORG_ID

# Detach safely (script keeps running): Ctrl+B then D
# Reconnect anytime:
tmux attach -t gcp-scan

# List active sessions:
tmux ls

# Kill session when done:
tmux kill-session -t gcp-scan
```

> 💡 **Tmux cheat sheet:**
> | Shortcut | Action |
> |----------|--------|
> | `Ctrl+B D` | Detach (leave running) |
> | `Ctrl+B [` | Scroll mode (use arrows, `q` to exit) |
> | `Ctrl+B &` | Kill window |

---

### Method 2 — `nohup` (Background + survives disconnection)

Runs the script fully detached. Output is saved to a log file.

```bash
nohup ./gcp_security_assessment.sh --org-id YOUR_ORG_ID \
  --output-dir ./reports > scan_output.log 2>&1 &

echo "Script running with PID: $!"

# Monitor progress live
tail -f scan_output.log

# Check if still running
ps aux | grep gcp_security_assessment

# After reconnecting to Cloud Shell, resume watching
tail -f scan_output.log
```

---

### Method 3 — `screen` (Alternative to tmux)

```bash
# Start session
screen -S gcp-scan

# Run script inside it
./gcp_security_assessment.sh --org-id YOUR_ORG_ID

# Detach: Ctrl+A then D
# Reconnect:
screen -r gcp-scan

# List sessions:
screen -ls
```

---

### Method 4 — Keep-Alive Loop in a Second Tab

Open a **second Cloud Shell tab** and run this loop. It prevents the session from going idle while your script runs in the first tab:

```bash
# Run this in a SECOND Cloud Shell tab
while true; do
  echo "keep-alive $(date '+%H:%M:%S')"
  sleep 120
done
```

---

### Method 5 — Built-in Keep-Alive (Automatic)

The script automatically spawns a background keep-alive heartbeat process every **4 minutes**. This is always active — no extra steps needed as long as the browser tab stays open:

```
[keep-alive] 14:32:01 — script still running, please keep this tab open...
[keep-alive] 14:36:01 — script still running, please keep this tab open...
```

The heartbeat process is automatically killed when the script finishes.

---

### Method 6 — Disable tmux Lock Timeout (Permanent fix)

Add this to your Cloud Shell `~/.tmux.conf` to disable the auto-lock entirely:

```bash
echo "set -g lock-after-time 0" >> ~/.tmux.conf
tmux source-file ~/.tmux.conf
```

---

### Quick Comparison

| Method | Survives browser close | Reconnectable | Extra setup |
|--------|----------------------|---------------|-------------|
| tmux + nohup | ✅ Yes | ✅ Yes | Minimal |
| tmux only | ✅ Yes | ✅ Yes | Minimal |
| nohup only | ✅ Yes | ⚠️ Log only | None |
| screen | ✅ Yes | ✅ Yes | Minimal |
| Second tab loop | ❌ No | ❌ No | None |
| Built-in heartbeat | ❌ No | ❌ No | None (automatic) |

---

## 📊 HTML Report — Dashboard Preview

The HTML report features a **dark-theme tabbed interface** with:

| Tab | Contents |
|-----|----------|
| 📊 **Overview Dashboard** | Summary cards: Exposed LBs, Unprotected LBs, Primitive IAM bindings, Cloud Armor coverage % |
| 🌐 **Network Exposure & Cloud Armor** | Table: Project, LB Name, Type, Public IP, Backend Service, Policy, Status badge |
| 🔐 **IAM Risk Management** | Table: Project, Identity, Type, Role, Risk Level badge |
| 🔧 **Remediation Playbook** | Copy-paste `gcloud` commands for Cloud Armor WAF deployment and IAM hardening |

### Status Badges
| Badge | Meaning |
|-------|---------|
| ✔ PROTECTED | Cloud Armor policy is attached |
| ✘ UNPROTECTED | No WAF policy — action required |
| ⚠ CRITICAL | External identity or public access with primitive role |
| ▲ HIGH | Owner/Editor on company user |
| ● MEDIUM | Viewer or service account with primitive role |

---

## 🔧 Remediation Playbook (included in HTML Tab 4)

The HTML report includes ready-to-use `gcloud` commands for:

### Cloud Armor
- Create a baseline WAF policy with OWASP Top 10 rules in **count/preview mode** (log without blocking)
- Rules included: SQLi, XSS, LFI, RFI, RCE, Scanner Detection, Protocol Attack, Session Fixation
- Attach the policy to an unprotected backend service
- Promote from preview to enforce mode after analysis

### IAM Hardening
- Remove primitive role bindings from users and service accounts
- Replace `roles/editor` / `roles/owner` with targeted least-privilege predefined roles
- Revoke external/personal identity access immediately

---

## 📁 Output Files

```
reports/
├── gcp_security_assessment_20260923_143000.html   ← Main interactive report
├── gcp_lb_cloudarmor_20260923_143000.csv          ← LB findings spreadsheet
├── gcp_iam_primitive_20260923_143000.csv          ← IAM findings spreadsheet
└── gcp_security_summary_20260923_143000.txt       ← Plain text summary
```

---

## ⚙️ Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `--org-id` | Auto-detected | GCP Organization ID |
| `--output-dir` | `./reports` | Directory to save all report files |
| `COMPANY_DOMAIN` | `amrize.com` | Used to flag non-company identities |
| `EXCLUDED_FOLDER_NAME` | `legacy` | Folder name to exclude from scan |

To change the company domain or excluded folder, edit the `CONFIGURATION` section at the top of the script.

---

## 🛠 Troubleshooting

| Issue | Solution |
|-------|----------|
| `Permission denied` on script | Run `chmod +x gcp_security_assessment.sh` |
| `Could not determine Organization ID` | Pass `--org-id` explicitly or ensure your account has `resourcemanager.organizations.get` |
| `python3 not found` | Install python3: `sudo apt-get install python3` (Cloud Shell has it by default) |
| Empty results for a project | Your account may lack IAM permissions on that project |
| Script killed by Cloud Shell timeout | Use `tmux + nohup` (recommended), `screen`, or second-tab keep-alive loop — see **Preventing Cloud Shell Disconnection** section above |

---

## 📄 License

Internal use — Amrize Security Engineering  
© 2026 Amrize. All rights reserved.
