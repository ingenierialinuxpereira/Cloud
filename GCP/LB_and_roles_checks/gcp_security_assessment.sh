#!/usr/bin/env bash
# =============================================================================
# GCP Security Assessment Script
# =============================================================================
# Author      : Francisco Gutierrez
# Company     : Amrize
# Description : Scans GCP organization for exposed Load Balancers, Cloud Armor
#               coverage gaps, and IAM primitive role hygiene issues.
#               Outputs HTML, CSV, and TXT reports.
#
# Usage       : ./gcp_security_assessment.sh [--org-id <ORG_ID>] [--output-dir <DIR>]
#
# Requirements: gcloud CLI authenticated with org-level read permissions
#               - compute.forwardingRules.list
#               - compute.backendServices.list
#               - compute.securityPolicies.list
#               - resourcemanager.projects.getIamPolicy
#               - resourcemanager.folders.list
#               - resourcemanager.projects.list
#
# ─────────────────────────────────────────────────────────────────────────────
# ⚠  IMPORTANT — PREVENTING CLOUD SHELL SESSION TIMEOUT
# ─────────────────────────────────────────────────────────────────────────────
# GCP Cloud Shell automatically disconnects after ~20 minutes of inactivity.
# This script may take longer than that when scanning large organizations.
#
# RECOMMENDED: Run the script using one of the methods below so it survives
# a disconnection and keeps running in the background:
#
#   METHOD 1 — nohup (simplest, output saved to nohup.out):
#     nohup ./gcp_security_assessment.sh --org-id YOUR_ORG_ID \
#       --output-dir ./reports > nohup.out 2>&1 &
#     echo "PID: $!"          # note the PID to monitor it
#     tail -f nohup.out       # follow live output
#
#   METHOD 2 — screen (reconnectable session):
#     screen -S gcp-scan
#     ./gcp_security_assessment.sh --org-id YOUR_ORG_ID
#     # Detach with Ctrl+A then D  — reconnect with: screen -r gcp-scan
#
#   METHOD 3 — tmux (reconnectable session, preferred):
#     tmux new -s gcp-scan
#     ./gcp_security_assessment.sh --org-id YOUR_ORG_ID
#     # Detach with Ctrl+B then D — reconnect with: tmux attach -t gcp-scan
#
#   METHOD 4 — Direct execution (if you keep the tab open):
#     The script itself spawns an internal keep-alive background process
#     that prints a heartbeat every 4 minutes to prevent idle disconnection.
#     This is automatic — no extra steps needed.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# =============================================================================
# KEEP-ALIVE: Prevent Cloud Shell idle timeout during execution
# Prints a heartbeat every 4 minutes (Cloud Shell timeout is ~20 min).
# The background process is automatically killed when the script exits.
# =============================================================================
_keepalive() {
  while true; do
    sleep 240
    echo "[keep-alive] $(date '+%H:%M:%S') — script still running, please keep this tab open..." >&2
  done
}
_keepalive &
KEEPALIVE_PID=$!
trap 'kill "${KEEPALIVE_PID}" 2>/dev/null; rm -rf "${TMP_DIR:-}" 2>/dev/null' EXIT

# =============================================================================
# CONFIGURATION
# =============================================================================
AUTHOR="Francisco Gutierrez"
COMPANY="Amrize"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')
REPORT_DATE=$(date '+%Y%m%d_%H%M%S')
EXCLUDED_FOLDER_NAME="legacy"

# Output directory (default: current directory)
OUTPUT_DIR="${OUTPUT_DIR:-./reports}"
HTML_REPORT="${OUTPUT_DIR}/gcp_security_assessment_${REPORT_DATE}.html"
CSV_LB_REPORT="${OUTPUT_DIR}/gcp_lb_cloudarmor_${REPORT_DATE}.csv"
CSV_IAM_REPORT="${OUTPUT_DIR}/gcp_iam_primitive_${REPORT_DATE}.csv"
TXT_REPORT="${OUTPUT_DIR}/gcp_security_summary_${REPORT_DATE}.txt"

# Temp files
TMP_DIR=$(mktemp -d)
TMP_LB="${TMP_DIR}/lb_findings.json"
TMP_IAM="${TMP_DIR}/iam_findings.json"

# Colors for terminal output
RED='\033[0;31m'
AMBER='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# =============================================================================
# ARGUMENT PARSING
# =============================================================================
ORG_ID=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org-id)    ORG_ID="$2";    shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${AMBER}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_section() { echo -e "\n${BOLD}${CYAN}========== $* ==========${NC}"; }

# Safely run gcloud and return empty JSON array on failure
safe_gcloud() {
  gcloud "$@" 2>/dev/null || echo "[]"
}

# =============================================================================
# STEP 1 — RESOLVE ORGANIZATION ID
# =============================================================================
resolve_org_id() {
  log_section "Resolving Organization"

  if [[ -z "${ORG_ID}" ]]; then
    log_info "No --org-id provided. Looking up organization for amrize.org..."
    ORG_ID=$(gcloud organizations list \
      --filter="displayName:amrize.org" \
      --format="value(name)" 2>/dev/null | sed 's/organizations\///' | head -1)
  fi

  if [[ -z "${ORG_ID}" ]]; then
    log_error "Could not determine Organization ID. Pass --org-id <ID> explicitly."
    exit 1
  fi

  log_ok "Using Organization ID: ${ORG_ID}"
}

# =============================================================================
# STEP 2 — COLLECT PROJECTS (excluding legacy folders)
# =============================================================================
declare -a SCOPED_PROJECTS=()

get_excluded_folder_ids() {
  # Find all folder IDs named exactly "legacy" anywhere under the org
  gcloud resource-manager folders list \
    --organization="${ORG_ID}" \
    --filter="displayName=${EXCLUDED_FOLDER_NAME}" \
    --format="value(name)" 2>/dev/null | sed 's/folders\///'
}

get_projects_in_folder() {
  local folder_id="$1"
  gcloud projects list \
    --filter="parent.id=${folder_id} AND lifecycleState=ACTIVE" \
    --format="value(projectId)" 2>/dev/null
}

collect_projects() {
  log_section "Collecting Active Projects"

  # Get all excluded folder IDs (legacy + their children)
  local excluded_folder_ids=()
  while IFS= read -r fid; do
    [[ -n "$fid" ]] && excluded_folder_ids+=("$fid")
    # Also get sub-folders of legacy
    while IFS= read -r subfid; do
      [[ -n "$subfid" ]] && excluded_folder_ids+=("$subfid")
    done < <(gcloud resource-manager folders list \
      --folder="$fid" \
      --format="value(name)" 2>/dev/null | sed 's/folders\///')
  done < <(get_excluded_folder_ids)

  log_warn "Excluded folder IDs (legacy): ${excluded_folder_ids[*]:-none}"

  # Get all active projects in the org
  local all_projects=()
  while IFS= read -r proj; do
    [[ -n "$proj" ]] && all_projects+=("$proj")
  done < <(gcloud projects list \
    --filter="parent.type=organization AND parent.id=${ORG_ID} AND lifecycleState=ACTIVE" \
    --format="value(projectId)" 2>/dev/null)

  # Also get projects from non-legacy folders
  while IFS= read -r folder_id; do
    local is_excluded=false
    for excl in "${excluded_folder_ids[@]:-}"; do
      [[ "$folder_id" == "$excl" ]] && is_excluded=true && break
    done
    if [[ "$is_excluded" == "false" ]]; then
      while IFS= read -r proj; do
        [[ -n "$proj" ]] && all_projects+=("$proj")
      done < <(get_projects_in_folder "$folder_id")
    fi
  done < <(gcloud resource-manager folders list \
    --organization="${ORG_ID}" \
    --format="value(name)" 2>/dev/null | sed 's/folders\///')

  # Deduplicate
  while IFS= read -r proj; do
    SCOPED_PROJECTS+=("$proj")
  done < <(printf '%s\n' "${all_projects[@]}" | sort -u)

  log_ok "Total projects in scope: ${#SCOPED_PROJECTS[@]}"
}

# =============================================================================
# STEP 3 — LOAD BALANCER & CLOUD ARMOR ASSESSMENT
# =============================================================================

# Data arrays for LB findings
declare -a LB_ROWS=()
TOTAL_EXPOSED_LBS=0
TOTAL_UNPROTECTED_LBS=0

assess_load_balancers() {
  log_section "Load Balancer & Cloud Armor Assessment"

  for project in "${SCOPED_PROJECTS[@]}"; do
    log_info "Scanning LBs in project: ${project}"

    # Get all external forwarding rules (HTTP/HTTPS/SSL/TCP proxy)
    local fwd_rules
    fwd_rules=$(safe_gcloud compute forwarding-rules list \
      --project="${project}" \
      --filter="loadBalancingScheme=EXTERNAL OR loadBalancingScheme=EXTERNAL_MANAGED" \
      --format="json(name,IPAddress,target,loadBalancingScheme,region)" 2>/dev/null)

    if [[ "${fwd_rules}" == "[]" || -z "${fwd_rules}" ]]; then
      continue
    fi

    # Iterate each forwarding rule
    while IFS= read -r rule_json; do
      local rule_name lb_ip target lb_scheme region lb_type backend_name armor_policy armor_status

      rule_name=$(echo "${rule_json}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name',''))" 2>/dev/null)
      lb_ip=$(echo "${rule_json}"     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('IPAddress',''))" 2>/dev/null)
      target=$(echo "${rule_json}"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('target',''))" 2>/dev/null)
      lb_scheme=$(echo "${rule_json}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('loadBalancingScheme',''))" 2>/dev/null)
      region=$(echo "${rule_json}"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('region','global'))" 2>/dev/null)

      # Determine LB type from target proxy path
      if echo "${target}" | grep -qi "targetHttpsProxies";  then lb_type="HTTPS"
      elif echo "${target}" | grep -qi "targetHttpProxies"; then lb_type="HTTP"
      elif echo "${target}" | grep -qi "targetSslProxies";  then lb_type="SSL Proxy"
      elif echo "${target}" | grep -qi "targetTcpProxies";  then lb_type="TCP Proxy"
      else lb_type="Unknown"
      fi

      TOTAL_EXPOSED_LBS=$((TOTAL_EXPOSED_LBS + 1))

      # Get backend service from URL map via target proxy
      backend_name="N/A"
      armor_policy="None"
      armor_status="UNPROTECTED"

      local proxy_name
      proxy_name=$(basename "${target}")
      local url_map=""

      # Try HTTPS proxy first
      if echo "${target}" | grep -qi "targetHttpsProxies"; then
        url_map=$(safe_gcloud compute target-https-proxies describe "${proxy_name}" \
          --project="${project}" --global \
          --format="value(urlMap)" 2>/dev/null | xargs basename 2>/dev/null || true)
      elif echo "${target}" | grep -qi "targetHttpProxies"; then
        url_map=$(safe_gcloud compute target-http-proxies describe "${proxy_name}" \
          --project="${project}" --global \
          --format="value(urlMap)" 2>/dev/null | xargs basename 2>/dev/null || true)
      fi

      if [[ -n "${url_map}" && "${url_map}" != "N/A" ]]; then
        # Get default backend service from URL map
        backend_name=$(safe_gcloud compute url-maps describe "${url_map}" \
          --project="${project}" --global \
          --format="value(defaultService)" 2>/dev/null | xargs basename 2>/dev/null || echo "N/A")
      fi

      # Check Cloud Armor on the backend service
      if [[ -n "${backend_name}" && "${backend_name}" != "N/A" ]]; then
        local armor_raw
        armor_raw=$(safe_gcloud compute backend-services describe "${backend_name}" \
          --project="${project}" --global \
          --format="value(securityPolicy)" 2>/dev/null || echo "")

        if [[ -n "${armor_raw}" && "${armor_raw}" != "" ]]; then
          armor_policy=$(basename "${armor_raw}")
          armor_status="PROTECTED"
        else
          TOTAL_UNPROTECTED_LBS=$((TOTAL_UNPROTECTED_LBS + 1))
        fi
      else
        TOTAL_UNPROTECTED_LBS=$((TOTAL_UNPROTECTED_LBS + 1))
      fi

      # Store finding
      LB_ROWS+=("${project}|${rule_name}|${lb_type}|${lb_ip}|${backend_name}|${armor_policy}|${armor_status}")
      log_info "  LB: ${rule_name} | IP: ${lb_ip} | Armor: ${armor_status}"

    done < <(echo "${fwd_rules}" | python3 -c "
import sys, json
rules = json.load(sys.stdin)
for r in rules:
    print(json.dumps(r))
" 2>/dev/null)

  done

  log_ok "LB scan complete. Exposed: ${TOTAL_EXPOSED_LBS} | Unprotected: ${TOTAL_UNPROTECTED_LBS}"
}

# =============================================================================
# STEP 4 — IAM PRIMITIVE ROLES ASSESSMENT
# =============================================================================

declare -a IAM_ROWS=()
TOTAL_PRIMITIVE_BINDINGS=0

PRIMITIVE_ROLES=("roles/owner" "roles/editor" "roles/viewer")
COMPANY_DOMAIN="amrize.com"

assess_iam() {
  log_section "IAM Primitive Roles & Identity Assessment"

  for project in "${SCOPED_PROJECTS[@]}"; do
    log_info "Scanning IAM in project: ${project}"

    local iam_policy
    iam_policy=$(safe_gcloud projects get-iam-policy "${project}" \
      --format="json" 2>/dev/null)

    if [[ "${iam_policy}" == "[]" || -z "${iam_policy}" ]]; then
      continue
    fi

    for role in "${PRIMITIVE_ROLES[@]}"; do
      # Extract members for this primitive role
      local members
      members=$(echo "${iam_policy}" | python3 -c "
import sys, json
policy = json.load(sys.stdin)
bindings = policy.get('bindings', [])
for b in bindings:
    if b.get('role') == '${role}':
        for m in b.get('members', []):
            print(m)
" 2>/dev/null || true)

      while IFS= read -r member; do
        [[ -z "${member}" ]] && continue

        TOTAL_PRIMITIVE_BINDINGS=$((TOTAL_PRIMITIVE_BINDINGS + 1))

        # Determine risk level
        local risk_level="MEDIUM"
        local identity_type

        if echo "${member}" | grep -q "^user:"; then
          identity_type="User"
          # Flag personal/external identities
          if echo "${member}" | grep -qi "@gmail.com" || \
             ! echo "${member}" | grep -qi "@${COMPANY_DOMAIN}"; then
            risk_level="CRITICAL"
          elif [[ "${role}" == "roles/owner" || "${role}" == "roles/editor" ]]; then
            risk_level="HIGH"
          fi
        elif echo "${member}" | grep -q "^serviceAccount:"; then
          identity_type="Service Account"
          [[ "${role}" == "roles/owner" ]] && risk_level="HIGH"
        elif echo "${member}" | grep -q "^group:"; then
          identity_type="Group"
        elif echo "${member}" | grep -q "^allUsers\|^allAuthenticatedUsers"; then
          identity_type="Public"
          risk_level="CRITICAL"
        else
          identity_type="Other"
        fi

        IAM_ROWS+=("${project}|${member}|${identity_type}|${role}|${risk_level}")
        log_warn "  ${risk_level}: ${member} has ${role}"

      done <<< "${members}"
    done
  done

  log_ok "IAM scan complete. Primitive bindings found: ${TOTAL_PRIMITIVE_BINDINGS}"
}

# =============================================================================
# STEP 5 — GENERATE REPORTS
# =============================================================================

mkdir -p "${OUTPUT_DIR}"

generate_csv_lb() {
  log_info "Writing LB CSV report: ${CSV_LB_REPORT}"
  echo "Project,LB Name,Type,Public IP,Backend Service,Cloud Armor Policy,Status" > "${CSV_LB_REPORT}"
  for row in "${LB_ROWS[@]:-}"; do
    echo "${row}" | tr '|' ',' >> "${CSV_LB_REPORT}"
  done
}

generate_csv_iam() {
  log_info "Writing IAM CSV report: ${CSV_IAM_REPORT}"
  echo "Project,Identity,Identity Type,Primitive Role,Risk Level" > "${CSV_IAM_REPORT}"
  for row in "${IAM_ROWS[@]:-}"; do
    echo "${row}" | tr '|' ',' >> "${CSV_IAM_REPORT}"
  done
}

generate_txt() {
  log_info "Writing TXT summary: ${TXT_REPORT}"
  cat > "${TXT_REPORT}" << EOF
=============================================================================
GCP SECURITY ASSESSMENT REPORT
=============================================================================
Author    : ${AUTHOR}
Company   : ${COMPANY}
Timestamp : ${TIMESTAMP}
Org ID    : ${ORG_ID}
Projects  : ${#SCOPED_PROJECTS[@]}
=============================================================================

OVERVIEW
--------
Total Exposed Load Balancers       : ${TOTAL_EXPOSED_LBS}
LBs Without Cloud Armor            : ${TOTAL_UNPROTECTED_LBS}
Total Primitive IAM Bindings Found : ${TOTAL_PRIMITIVE_BINDINGS}

=============================================================================
LOAD BALANCER FINDINGS
=============================================================================
$(printf '%-30s %-30s %-12s %-18s %-30s %-30s %-12s\n' \
  "PROJECT" "LB NAME" "TYPE" "PUBLIC IP" "BACKEND" "ARMOR POLICY" "STATUS")
$(printf '%s\n' "${LB_ROWS[@]:-No findings}" | column -t -s '|')

=============================================================================
IAM PRIMITIVE ROLE FINDINGS
=============================================================================
$(printf '%-30s %-50s %-16s %-20s %-10s\n' \
  "PROJECT" "IDENTITY" "TYPE" "ROLE" "RISK")
$(printf '%s\n' "${IAM_ROWS[@]:-No findings}" | column -t -s '|')

=============================================================================
REMEDIATION SUMMARY
=============================================================================
See the HTML report for full remediation gcloud commands.
EOF
}

generate_html() {
  log_info "Writing HTML report: ${HTML_REPORT}"

  # Build LB table rows
  local lb_table_rows=""
  for row in "${LB_ROWS[@]:-}"; do
    IFS='|' read -r proj lb_name lb_type lb_ip backend armor_policy armor_status <<< "${row}"
    local status_class="protected"
    local status_badge='<span class="badge badge-ok">✔ PROTECTED</span>'
    if [[ "${armor_status}" == "UNPROTECTED" ]]; then
      status_class="unprotected"
      status_badge='<span class="badge badge-risk">✘ UNPROTECTED</span>'
    fi
    lb_table_rows+="<tr class=\"${status_class}\">
      <td>${proj}</td><td>${lb_name}</td><td>${lb_type}</td>
      <td><code>${lb_ip}</code></td><td>${backend}</td>
      <td>${armor_policy}</td><td>${status_badge}</td>
    </tr>"
  done
  [[ -z "${lb_table_rows}" ]] && lb_table_rows='<tr><td colspan="7" class="no-data">No exposed Load Balancers found.</td></tr>'

  # Build IAM table rows
  local iam_table_rows=""
  for row in "${IAM_ROWS[@]:-}"; do
    IFS='|' read -r proj identity id_type role risk_level <<< "${row}"
    local risk_class risk_badge
    case "${risk_level}" in
      CRITICAL) risk_class="critical"; risk_badge='<span class="badge badge-critical">⚠ CRITICAL</span>' ;;
      HIGH)     risk_class="high";     risk_badge='<span class="badge badge-high">▲ HIGH</span>' ;;
      MEDIUM)   risk_class="medium";   risk_badge='<span class="badge badge-medium">● MEDIUM</span>' ;;
      *)        risk_class="low";      risk_badge='<span class="badge badge-low">▼ LOW</span>' ;;
    esac
    iam_table_rows+="<tr class=\"${risk_class}\">
      <td>${proj}</td><td><code>${identity}</code></td><td>${id_type}</td>
      <td><code>${role}</code></td><td>${risk_badge}</td>
    </tr>"
  done
  [[ -z "${iam_table_rows}" ]] && iam_table_rows='<tr><td colspan="5" class="no-data">No primitive IAM bindings found.</td></tr>'

  cat > "${HTML_REPORT}" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>GCP Security Assessment — ${COMPANY}</title>
  <style>
    :root {
      --bg-primary:    #0f1117;
      --bg-secondary:  #1a1d2e;
      --bg-card:       #20243a;
      --bg-table-odd:  #1e2235;
      --bg-table-even: #181b2c;
      --border:        #2e3352;
      --text-primary:  #e2e8f0;
      --text-muted:    #8892b0;
      --accent-cyan:   #64ffda;
      --accent-blue:   #4a9eff;
      --green:         #00e676;
      --amber:         #ffb300;
      --red:           #ff1744;
      --orange:        #ff6d00;
      --purple:        #7c4dff;
      --tab-active:    #64ffda;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
    }

    /* ── Header ── */
    .header {
      background: linear-gradient(135deg, #0d1b2a 0%, #1a2744 50%, #0d2137 100%);
      border-bottom: 2px solid var(--accent-cyan);
      padding: 2rem 3rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .header-left h1 {
      font-size: 1.8rem;
      font-weight: 700;
      color: var(--accent-cyan);
      letter-spacing: 0.05em;
    }
    .header-left p { color: var(--text-muted); font-size: 0.9rem; margin-top: 0.3rem; }
    .header-meta {
      text-align: right;
      font-size: 0.85rem;
      color: var(--text-muted);
      line-height: 1.8;
    }
    .header-meta span { color: var(--text-primary); font-weight: 600; }

    /* ── Tabs ── */
    .tabs-nav {
      display: flex;
      gap: 0;
      background: var(--bg-secondary);
      border-bottom: 2px solid var(--border);
      padding: 0 2rem;
    }
    .tab-btn {
      padding: 1rem 1.8rem;
      border: none;
      background: transparent;
      color: var(--text-muted);
      font-size: 0.95rem;
      font-weight: 500;
      cursor: pointer;
      border-bottom: 3px solid transparent;
      transition: all 0.2s ease;
      letter-spacing: 0.03em;
    }
    .tab-btn:hover { color: var(--text-primary); background: rgba(100,255,218,0.05); }
    .tab-btn.active {
      color: var(--tab-active);
      border-bottom-color: var(--tab-active);
      background: rgba(100,255,218,0.08);
    }
    .tab-content { display: none; padding: 2rem 3rem; animation: fadeIn 0.3s ease; }
    .tab-content.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }

    /* ── Summary Cards ── */
    .cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2.5rem;
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      position: relative;
      overflow: hidden;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .card:hover { transform: translateY(-3px); box-shadow: 0 8px 30px rgba(0,0,0,0.4); }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
    }
    .card.blue::before   { background: var(--accent-blue); }
    .card.red::before    { background: var(--red); }
    .card.amber::before  { background: var(--amber); }
    .card.green::before  { background: var(--green); }
    .card.purple::before { background: var(--purple); }
    .card-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 0.8rem; }
    .card-value { font-size: 2.5rem; font-weight: 700; line-height: 1; }
    .card.blue .card-value   { color: var(--accent-blue); }
    .card.red .card-value    { color: var(--red); }
    .card.amber .card-value  { color: var(--amber); }
    .card.green .card-value  { color: var(--green); }
    .card.purple .card-value { color: var(--purple); }
    .card-sub { font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem; }

    /* ── Section Title ── */
    .section-title {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--accent-cyan);
      border-left: 3px solid var(--accent-cyan);
      padding-left: 0.8rem;
      margin: 2rem 0 1rem;
    }

    /* ── Tables ── */
    .table-wrap { overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    thead tr { background: var(--bg-card); }
    thead th {
      padding: 0.9rem 1rem;
      text-align: left;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    tbody tr { transition: background 0.15s; }
    tbody tr:nth-child(odd)  { background: var(--bg-table-odd); }
    tbody tr:nth-child(even) { background: var(--bg-table-even); }
    tbody tr:hover { background: rgba(100,255,218,0.05); }
    tbody td { padding: 0.8rem 1rem; border-bottom: 1px solid rgba(46,51,82,0.5); vertical-align: middle; }
    tbody tr:last-child td { border-bottom: none; }
    code { background: rgba(255,255,255,0.07); padding: 0.15rem 0.4rem; border-radius: 4px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.82rem; color: var(--accent-cyan); }
    .no-data { text-align: center; color: var(--text-muted); padding: 2rem; font-style: italic; }

    /* ── Badges ── */
    .badge { padding: 0.25rem 0.7rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600; display: inline-block; white-space: nowrap; }
    .badge-ok       { background: rgba(0,230,118,0.15);  color: var(--green);  border: 1px solid rgba(0,230,118,0.3); }
    .badge-risk     { background: rgba(255,23,68,0.15);  color: var(--red);    border: 1px solid rgba(255,23,68,0.3); }
    .badge-critical { background: rgba(255,23,68,0.2);   color: var(--red);    border: 1px solid rgba(255,23,68,0.4); }
    .badge-high     { background: rgba(255,109,0,0.15);  color: var(--orange); border: 1px solid rgba(255,109,0,0.3); }
    .badge-medium   { background: rgba(255,179,0,0.15);  color: var(--amber);  border: 1px solid rgba(255,179,0,0.3); }
    .badge-low      { background: rgba(74,158,255,0.15); color: var(--accent-blue); border: 1px solid rgba(74,158,255,0.3); }

    /* ── Remediation Code Blocks ── */
    .remediation-block {
      background: #0a0e1a;
      border: 1px solid var(--border);
      border-left: 4px solid var(--accent-cyan);
      border-radius: 8px;
      padding: 1.2rem 1.5rem;
      margin: 1rem 0 1.5rem;
      overflow-x: auto;
    }
    .remediation-block pre {
      font-family: 'Cascadia Code', 'Fira Code', 'Courier New', monospace;
      font-size: 0.82rem;
      color: #a8ff78;
      white-space: pre;
      line-height: 1.6;
    }
    .remediation-block .comment { color: #546e7a; }
    .step-header {
      font-size: 1rem;
      font-weight: 600;
      color: var(--text-primary);
      margin: 1.5rem 0 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .step-header .num {
      background: var(--accent-cyan);
      color: var(--bg-primary);
      width: 24px; height: 24px;
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 0.75rem; font-weight: 700; flex-shrink: 0;
    }

    /* ── Footer ── */
    .footer {
      text-align: center;
      padding: 1.5rem;
      border-top: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.8rem;
      margin-top: 3rem;
    }

    /* ── Responsive ── */
    @media (max-width: 768px) {
      .header { padding: 1.5rem; }
      .tab-content { padding: 1.5rem; }
      .tabs-nav { padding: 0 0.5rem; }
      .tab-btn { padding: 0.8rem 1rem; font-size: 0.85rem; }
    }
  </style>
</head>
<body>

<!-- ═══════════════════════════ HEADER ═══════════════════════════ -->
<header class="header">
  <div class="header-left">
    <h1>🛡 GCP Security Assessment</h1>
    <p>Organization Security Posture — Load Balancers &amp; IAM</p>
  </div>
  <div class="header-meta">
    <div>Author: <span>${AUTHOR}</span></div>
    <div>Company: <span>${COMPANY}</span></div>
    <div>Organization ID: <span>${ORG_ID}</span></div>
    <div>Generated: <span>${TIMESTAMP}</span></div>
    <div>Projects Scanned: <span>${#SCOPED_PROJECTS[@]}</span></div>
  </div>
</header>

<!-- ═══════════════════════════ TABS NAV ═══════════════════════════ -->
<nav class="tabs-nav">
  <button class="tab-btn active" onclick="showTab('overview', this)">📊 Overview Dashboard</button>
  <button class="tab-btn" onclick="showTab('network', this)">🌐 Network Exposure &amp; Cloud Armor</button>
  <button class="tab-btn" onclick="showTab('iam', this)">🔐 IAM Risk Management</button>
  <button class="tab-btn" onclick="showTab('remediation', this)">🔧 Remediation Playbook</button>
</nav>

<!-- ═══════════════════════════ TAB 1: OVERVIEW ═══════════════════════════ -->
<div id="tab-overview" class="tab-content active">
  <h2 class="section-title">Executive Summary</h2>
  <div class="cards-grid">
    <div class="card blue">
      <div class="card-label">Projects Scanned</div>
      <div class="card-value">${#SCOPED_PROJECTS[@]}</div>
      <div class="card-sub">Active, non-legacy projects</div>
    </div>
    <div class="card amber">
      <div class="card-label">Exposed Load Balancers</div>
      <div class="card-value">${TOTAL_EXPOSED_LBS}</div>
      <div class="card-sub">External-facing LBs detected</div>
    </div>
    <div class="card red">
      <div class="card-label">Unprotected by Cloud Armor</div>
      <div class="card-value">${TOTAL_UNPROTECTED_LBS}</div>
      <div class="card-sub">LBs with no WAF policy attached</div>
    </div>
    <div class="card purple">
      <div class="card-label">Primitive IAM Bindings</div>
      <div class="card-value">${TOTAL_PRIMITIVE_BINDINGS}</div>
      <div class="card-sub">owner / editor / viewer roles found</div>
    </div>
    <div class="card green">
      <div class="card-label">Cloud Armor Coverage</div>
      <div class="card-value">$(( TOTAL_EXPOSED_LBS > 0 ? (TOTAL_EXPOSED_LBS - TOTAL_UNPROTECTED_LBS) * 100 / TOTAL_EXPOSED_LBS : 0 ))%</div>
      <div class="card-sub">Of exposed LBs are protected</div>
    </div>
  </div>

  <h2 class="section-title">Risk Summary</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Assessment Area</th>
          <th>Finding</th>
          <th>Count</th>
          <th>Risk Level</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>External Load Balancers</td>
          <td>Public-facing LBs detected</td>
          <td>${TOTAL_EXPOSED_LBS}</td>
          <td><span class="badge badge-medium">● MEDIUM</span></td>
          <td>Ensure all LBs are covered by Cloud Armor</td>
        </tr>
        <tr>
          <td>Cloud Armor</td>
          <td>LBs without WAF policy</td>
          <td>${TOTAL_UNPROTECTED_LBS}</td>
          <td><span class="badge badge-critical">⚠ CRITICAL</span></td>
          <td>Deploy baseline Cloud Armor policy immediately</td>
        </tr>
        <tr>
          <td>IAM Hygiene</td>
          <td>Primitive roles in use</td>
          <td>${TOTAL_PRIMITIVE_BINDINGS}</td>
          <td><span class="badge badge-high">▲ HIGH</span></td>
          <td>Replace with least-privilege predefined roles</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ═══════════════════════════ TAB 2: NETWORK ═══════════════════════════ -->
<div id="tab-network" class="tab-content">
  <h2 class="section-title">External Load Balancers — Cloud Armor Coverage</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Project</th>
          <th>LB Name</th>
          <th>Type</th>
          <th>Public IP</th>
          <th>Backend Service</th>
          <th>Cloud Armor Policy</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${lb_table_rows}
      </tbody>
    </table>
  </div>
</div>

<!-- ═══════════════════════════ TAB 3: IAM ═══════════════════════════ -->
<div id="tab-iam" class="tab-content">
  <h2 class="section-title">IAM Primitive Role Bindings</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Project</th>
          <th>Identity</th>
          <th>Identity Type</th>
          <th>Primitive Role</th>
          <th>Risk Level</th>
        </tr>
      </thead>
      <tbody>
        ${iam_table_rows}
      </tbody>
    </table>
  </div>
</div>

<!-- ═══════════════════════════ TAB 4: REMEDIATION ═══════════════════════════ -->
<div id="tab-remediation" class="tab-content">

  <h2 class="section-title">☁ Cloud Armor — Baseline WAF Deployment (Count/Preview Mode)</h2>

  <div class="step-header"><span class="num">1</span> Create a baseline Cloud Armor security policy</div>
  <div class="remediation-block"><pre>
<span class="comment"># Create the baseline security policy</span>
gcloud compute security-policies create baseline-waf-policy \
  --description="Baseline WAF policy — OWASP Top 10 (preview/count mode)" \
  --project=YOUR_PROJECT_ID
</pre></div>

  <div class="step-header"><span class="num">2</span> Add OWASP Top 10 pre-configured WAF rules in COUNT (preview) mode</div>
  <div class="remediation-block"><pre>
<span class="comment"># SQLi — SQL Injection detection (count mode = log only, no block)</span>
gcloud compute security-policies rules create 1000 \
  --security-policy=baseline-waf-policy \
  --expression="evaluatePreconfiguredExpr('sqli-v33-stable')" \
  --action=deny-403 \
  --preview \
  --description="OWASP SQLi protection — count mode" \
  --project=YOUR_PROJECT_ID

<span class="comment"># XSS — Cross-Site Scripting detection (count mode)</span>
gcloud compute security-policies rules create 1001 \
  --security-policy=baseline-waf-policy \
  --expression="evaluatePreconfiguredExpr('xss-v33-stable')" \
  --action=deny-403 \
  --preview \
  --description="OWASP XSS protection — count mode" \
  --project=YOUR_PROJECT_ID

<span class="comment"># LFI — Local File Inclusion (count mode)</span>
gcloud compute security-policies rules create 1002 \
  --security-policy=baseline-waf-policy \
  --expression="evaluatePreconfiguredExpr('lfi-v33-stable')" \
  --action=deny-403 \
  --preview \
  --description="OWASP LFI protection — count mode" \
  --project=YOUR_PROJECT_ID

<span class="comment"># RFI — Remote File Inclusion (count mode)</span>
gcloud compute security-policies rules create 1003 \
  --security-policy=baseline-waf-policy \
  --expression="evaluatePreconfiguredExpr('rfi-v33-stable')" \
  --action=deny-403 \
  --preview \
  --description="OWASP RFI protection — count mode" \
  --project=YOUR_PROJECT_ID

<span class="comment"># RCE — Remote Code Execution (count mode)</span>
gcloud compute security-policies rules create 1004 \
  --security-policy=baseline-waf-policy \
  --expression="evaluatePreconfiguredExpr('rce-v33-stable')" \
  --action=deny-403 \
  --preview \
  --description="OWASP RCE protection — count mode" \
  --project=YOUR_PROJECT_ID

<span class="comment"># Scanner detection (count mode)</span>
gcloud compute security-policies rules create 1005 \
  --security-policy=baseline-waf-policy \
  --expression="evaluatePreconfiguredExpr('scannerdetection-v33-stable')" \
  --action=deny-403 \
  --preview \
  --description="Scanner detection — count mode" \
  --project=YOUR_PROJECT_ID

<span class="comment"># Protocol attack (count mode)</span>
gcloud compute security-policies rules create 1006 \
  --security-policy=baseline-waf-policy \
  --expression="evaluatePreconfiguredExpr('protocolattack-v33-stable')" \
  --action=deny-403 \
  --preview \
  --description="Protocol attack protection — count mode" \
  --project=YOUR_PROJECT_ID

<span class="comment"># Session fixation (count mode)</span>
gcloud compute security-policies rules create 1007 \
  --security-policy=baseline-waf-policy \
  --expression="evaluatePreconfiguredExpr('sessionfixation-v33-stable')" \
  --action=deny-403 \
  --preview \
  --description="Session fixation protection — count mode" \
  --project=YOUR_PROJECT_ID
</pre></div>

  <div class="step-header"><span class="num">3</span> Attach the policy to an unprotected backend service</div>
  <div class="remediation-block"><pre>
<span class="comment"># Replace BACKEND_SERVICE_NAME with the actual backend service name from Tab 2</span>
gcloud compute backend-services update BACKEND_SERVICE_NAME \
  --security-policy=baseline-waf-policy \
  --global \
  --project=YOUR_PROJECT_ID

<span class="comment"># Verify attachment</span>
gcloud compute backend-services describe BACKEND_SERVICE_NAME \
  --global \
  --format="value(securityPolicy)" \
  --project=YOUR_PROJECT_ID
</pre></div>

  <div class="step-header"><span class="num">4</span> Promote from COUNT to ENFORCE mode (after analysis period)</div>
  <div class="remediation-block"><pre>
<span class="comment"># Remove --preview flag from each rule to enforce blocking</span>
<span class="comment"># Example for SQLi rule (repeat for each rule priority 1000–1007)</span>
gcloud compute security-policies rules update 1000 \
  --security-policy=baseline-waf-policy \
  --no-preview \
  --project=YOUR_PROJECT_ID
</pre></div>

  <h2 class="section-title">🔐 IAM Hardening — Remove Primitive Roles</h2>

  <div class="step-header"><span class="num">5</span> Remove a primitive role binding from a user</div>
  <div class="remediation-block"><pre>
<span class="comment"># Replace PROJECT_ID, USER_EMAIL, and ROLE with values from Tab 3</span>
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member="user:USER_EMAIL" \
  --role="roles/owner" \
  --project=PROJECT_ID

<span class="comment"># For service accounts</span>
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:SA_EMAIL" \
  --role="roles/editor"
</pre></div>

  <div class="step-header"><span class="num">6</span> Replace primitive roles with least-privilege predefined roles</div>
  <div class="remediation-block"><pre>
<span class="comment"># Example: replace roles/editor with a targeted predefined role</span>
<span class="comment"># Step 1 — Remove the primitive role</span>
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member="user:USER_EMAIL" \
  --role="roles/editor"

<span class="comment"># Step 2 — Grant a targeted predefined role instead</span>
<span class="comment"># Examples of least-privilege alternatives:</span>
<span class="comment">#   roles/compute.instanceAdmin.v1  — manage compute instances only</span>
<span class="comment">#   roles/storage.objectAdmin       — manage GCS objects only</span>
<span class="comment">#   roles/container.developer       — GKE developer access only</span>
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:USER_EMAIL" \
  --role="roles/compute.instanceAdmin.v1"
</pre></div>

  <div class="step-header"><span class="num">7</span> Revoke external / personal identities (gmail.com or non-company)</div>
  <div class="remediation-block"><pre>
<span class="comment"># Immediately revoke any gmail.com or personal accounts with primitive roles</span>
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member="user:personal@gmail.com" \
  --role="roles/owner"

<span class="comment"># Audit all org-level bindings for external identities</span>
gcloud organizations get-iam-policy ORG_ID \
  --format=json | python3 -c "
import sys, json
p = json.load(sys.stdin)
for b in p.get('bindings', []):
    for m in b.get('members', []):
        if 'gmail.com' in m or 'user:' in m:
            print(b['role'], m)
"
</pre></div>

</div>
<!-- end remediation tab -->

<footer class="footer">
  GCP Security Assessment &mdash; Generated by ${AUTHOR} &bull; ${COMPANY} &bull; ${TIMESTAMP}
</footer>

<script>
  function showTab(name, btn) {
    // Hide all tab content
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    // Deactivate all buttons
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    // Show selected tab
    document.getElementById('tab-' + name).classList.add('active');
    btn.classList.add('active');
  }
</script>

</body>
</html>
HTMLEOF
}

# =============================================================================
# MAIN
# =============================================================================
main() {
  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║       GCP Security Assessment Script                 ║"
  echo "║       Author : ${AUTHOR}              ║"
  echo "║       Company: ${COMPANY}                              ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  resolve_org_id
  collect_projects
  assess_load_balancers
  assess_iam

  log_section "Generating Reports"
  generate_csv_lb
  generate_csv_iam
  generate_txt
  generate_html

  echo ""
  log_ok "Assessment complete! Reports saved to: ${OUTPUT_DIR}/"
  echo ""
  echo -e "  📊 HTML Report : ${CYAN}${HTML_REPORT}${NC}"
  echo -e "  📋 LB CSV      : ${CYAN}${CSV_LB_REPORT}${NC}"
  echo -e "  📋 IAM CSV     : ${CYAN}${CSV_IAM_REPORT}${NC}"
  echo -e "  📄 TXT Summary : ${CYAN}${TXT_REPORT}${NC}"
  echo ""
  echo -e "${BOLD}Summary:${NC}"
  echo -e "  Exposed Load Balancers       : ${AMBER}${TOTAL_EXPOSED_LBS}${NC}"
  echo -e "  Unprotected by Cloud Armor   : ${RED}${TOTAL_UNPROTECTED_LBS}${NC}"
  echo -e "  Primitive IAM Bindings Found : ${RED}${TOTAL_PRIMITIVE_BINDINGS}${NC}"
  echo ""
}

main "$@"
