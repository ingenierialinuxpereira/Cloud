#!/usr/bin/env bash
#
# ==============================================================================
#  GCP Security Assessment  ·  Security posture evaluation for GCP
# ------------------------------------------------------------------------------
#  Author  : Francisco Gutierrez
#  Requires: gcloud SDK + jq  (NO Cloud Asset Inventory, NO Org-level perms)
#            Optional: bq CLI (enables the BigQuery deep scan)
#  Scope   : PROJECT-level scan using exclusively native gcloud commands and
#            each service's standard APIs.
#
#  Deep scanners (v2.1):
#    Compute/VPC · Storage · IAM · Cloud SQL · GKE · Cloud Functions · Cloud Run
#    Pub/Sub · Secret Manager · Artifact Registry · Cloud KMS · BigQuery
#    Cloud DNS · API Keys · Load Balancing (NEW)
#  Checks are aligned where possible with the CIS GCP Foundations Benchmark.
#
#  Usage:
#     ./gcp_security_assessment.sh [--zip] [PROJECT_ID]
#     ./gcp_security_assessment.sh --zip my-project   # zip report + icons/
#
#  Flags:
#     --zip   After generating the HTML report, package it together with a
#             copy of the icons/ folder into <report>.zip so the report
#             carries its images anywhere it is downloaded or shared.
#
#  Phases:
#     1) Dynamic auto-discovery of enabled APIs
#     2) Interactive menu (all / on-demand / exit)
#     3) Per-service scanning logic (only if the service is active)
#     4) Self-contained HTML report with tabs
# ==============================================================================

set -uo pipefail   # -e intentionally omitted: gcloud may fail and we handle it

# ------------------------------------------------------------------------------
#  CONSTANTS AND GLOBAL STATE
# ------------------------------------------------------------------------------
readonly SCRIPT_NAME="GCP Security Assessment"
readonly SCRIPT_VERSION="2.1.0"
readonly DELIM=$'\037'            # Unit Separator: safe delimiter for findings
readonly KEY_WARN_DAYS=90         # SA keys > 90 days  -> WARNING
readonly KEY_CRIT_DAYS=365        # SA keys > 365 days -> CRITICAL

PROJECT_ID=""
REPORT_FILE=""
ZIP_REPORT=false                  # --zip: package report + icons/ into a portable zip

# Icons/emojis folder (next to the script; overridable via the ICONS_DIR env
# var). The HTML report does NOT embed the icons: it references them with
# <img src="icons/<name>.<ext>"> tags. Supported formats: svg png jpg jpeg
# gif webp. A copy of the folder is placed next to the report automatically,
# and it must stay next to the HTML file when the report is moved or shared.
ICONS_DIR="${ICONS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/icons}"

# Findings: each element = "SEV<US>CAT<US>TITLE<US>RESOURCE<US>DETAIL"
declare -a FINDINGS=()
declare -a ENABLED_SERVICES=()      # all enabled APIs
declare -a DETECTED_SCANNABLE=()    # enabled APIs this script knows how to scan
declare -a SCANNED_CATEGORIES=()    # categories actually executed (for the tabs)

# Counters by severity
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0

# Active services WITHOUT a deep scanner (inventory only). Filled in discover.
declare -a UNSCANNED_SERVICES=()

# Fixed order of APIs with a deep scanner (associative arrays don't preserve order)
readonly KNOWN_SCANNABLE_ORDER=(
    "compute.googleapis.com"
    "storage.googleapis.com"
    "iam.googleapis.com"
    "sqladmin.googleapis.com"
    "container.googleapis.com"
    "cloudfunctions.googleapis.com"
    "run.googleapis.com"
    "pubsub.googleapis.com"
    "secretmanager.googleapis.com"
    "artifactregistry.googleapis.com"
    "cloudkms.googleapis.com"
    "bigquery.googleapis.com"
    "dns.googleapis.com"
    "apikeys.googleapis.com"
    "networkservices.googleapis.com"   # Load Balancing (LB uses compute + networkservices)
)

# API -> internal category
declare -A API_TO_CATEGORY=(
    ["compute.googleapis.com"]="COMPUTE"
    ["storage.googleapis.com"]="STORAGE"
    ["iam.googleapis.com"]="IAM"
    ["sqladmin.googleapis.com"]="SQL"
    ["container.googleapis.com"]="GKE"
    ["cloudfunctions.googleapis.com"]="FUNCTIONS"
    ["run.googleapis.com"]="RUN"
    ["pubsub.googleapis.com"]="PUBSUB"
    ["secretmanager.googleapis.com"]="SECRETS"
    ["artifactregistry.googleapis.com"]="ARTIFACTS"
    ["cloudkms.googleapis.com"]="KMS"
    ["bigquery.googleapis.com"]="BIGQUERY"
    ["dns.googleapis.com"]="DNS"
    ["apikeys.googleapis.com"]="APIKEYS"
    ["networkservices.googleapis.com"]="LOADBALANCER"
)

# API -> scan function
declare -A API_TO_SCANNER=(
    ["compute.googleapis.com"]="scan_compute"
    ["storage.googleapis.com"]="scan_storage"
    ["iam.googleapis.com"]="scan_iam"
    ["sqladmin.googleapis.com"]="scan_sql"
    ["container.googleapis.com"]="scan_gke"
    ["cloudfunctions.googleapis.com"]="scan_functions"
    ["run.googleapis.com"]="scan_run"
    ["pubsub.googleapis.com"]="scan_pubsub"
    ["secretmanager.googleapis.com"]="scan_secrets"
    ["artifactregistry.googleapis.com"]="scan_artifacts"
    ["cloudkms.googleapis.com"]="scan_kms"
    ["bigquery.googleapis.com"]="scan_bigquery"
    ["dns.googleapis.com"]="scan_dns"
    ["apikeys.googleapis.com"]="scan_apikeys"
    ["networkservices.googleapis.com"]="scan_loadbalancer"
)

# API -> human-readable label (for menus and console)
declare -A API_TO_LABEL=(
    ["compute.googleapis.com"]="Compute Engine · VPC / Firewall"
    ["storage.googleapis.com"]="Cloud Storage"
    ["iam.googleapis.com"]="IAM · Service Accounts"
    ["sqladmin.googleapis.com"]="Cloud SQL"
    ["container.googleapis.com"]="Google Kubernetes Engine"
    ["cloudfunctions.googleapis.com"]="Cloud Functions"
    ["run.googleapis.com"]="Cloud Run"
    ["pubsub.googleapis.com"]="Pub/Sub"
    ["secretmanager.googleapis.com"]="Secret Manager"
    ["artifactregistry.googleapis.com"]="Artifact Registry"
    ["cloudkms.googleapis.com"]="Cloud KMS"
    ["bigquery.googleapis.com"]="BigQuery"
    ["dns.googleapis.com"]="Cloud DNS"
    ["apikeys.googleapis.com"]="API Keys"
    ["networkservices.googleapis.com"]="Cloud Load Balancing"
)

# Category metadata for the report (order, title and icon)
readonly CAT_ORDER=(COMPUTE LOADBALANCER STORAGE IAM SQL GKE FUNCTIONS RUN PUBSUB SECRETS ARTIFACTS KMS BIGQUERY DNS APIKEYS)
declare -A CAT_TITLE=(
    [COMPUTE]="Compute / VPC"
    [LOADBALANCER]="Load Balancing"
    [STORAGE]="Cloud Storage"
    [IAM]="IAM & SA"
    [SQL]="Cloud SQL"
    [GKE]="GKE"
    [FUNCTIONS]="Cloud Functions"
    [RUN]="Cloud Run"
    [PUBSUB]="Pub/Sub"
    [SECRETS]="Secret Manager"
    [ARTIFACTS]="Artifact Registry"
    [KMS]="Cloud KMS"
    [BIGQUERY]="BigQuery"
    [DNS]="Cloud DNS"
    [APIKEYS]="API Keys"
)

# ------------------------------------------------------------------------------
#  COLORS / CONSOLE LOGGING
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
    C_BLU=$'\033[34m'; C_MAG=$'\033[35m'; C_CYN=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_CYN=""
fi

log_info()    { printf '%s[·]%s %s\n'  "$C_CYN"  "$C_RESET" "$*"; }
log_step()    { printf '%s[»]%s %s\n'  "$C_MAG"  "$C_RESET" "$*"; }
log_ok()      { printf '%s[✓]%s %s\n'  "$C_GRN"  "$C_RESET" "$*"; }
log_warn()    { printf '%s[!]%s %s\n'  "$C_YEL"  "$C_RESET" "$*"; }
log_error()   { printf '%s[✗]%s %s\n'  "$C_RED"  "$C_RESET" "$*" >&2; }
log_crit()    { printf '%s[✗ CRITICAL]%s %s\n' "$C_RED$C_BOLD" "$C_RESET" "$*"; }

hr()          { printf '%s%s%s\n' "$C_DIM" "──────────────────────────────────────────────────────────────" "$C_RESET"; }

print_banner() {
    printf '%s' "$C_CYN$C_BOLD"
    cat <<'BANNER'
   ____  ____  ____    ____                       _ _
  / ___|/ ___||  _ \  / ___|  ___  ___ _   _ _ __(_) |_ _   _
 | |  _| |    | |_) | \___ \ / _ \/ __| | | | '__| | __| | | |
 | |_| | |___ |  __/   ___) |  __/ (__| |_| | |  | | |_| |_| |
  \____|\____||_|     |____/ \___|\___|\__,_|_|  |_|\__|\__, |
                                                        |___/
BANNER
    printf '%s' "$C_RESET"
    printf '   %s%s v%s%s\n' "$C_DIM" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$C_RESET"
    printf '   %sProject-level scan · native gcloud only · no Org / no CAI%s\n\n' "$C_DIM" "$C_RESET"
}

# ------------------------------------------------------------------------------
#  UTILITIES
# ------------------------------------------------------------------------------

html_escape() {
    local s="${1-}"
    s="${s//&/\&}"
    s="${s//</\<}"
    s="${s//>/\>}"
    s="${s//\"/\"}"
    printf '%s' "$s"
}

readonly ICON_EXTS=(svg png jpg jpeg gif webp)
html_icon() {
    local name="$1" fallback="${2:-}" ext
    for ext in "${ICON_EXTS[@]}"; do
        if [[ -f "${ICONS_DIR}/${name}.${ext}" ]]; then
            printf '<img class="ico-svg" src="icons/%s.%s" alt="%s">' \
                "$name" "$ext" "$(html_escape "$name")"
            return 0
        fi
    done
    printf '%s' "$fallback"
}

stage_icons() {
    local report_dir dest
    report_dir="$(cd "$(dirname "$REPORT_FILE")" && pwd)"
    dest="${report_dir}/icons"
    if [[ ! -d "$ICONS_DIR" ]]; then
        log_warn "Icons folder not found: ${ICONS_DIR} - the report will use text fallbacks"
        return 0
    fi
    if [[ "$(cd "$ICONS_DIR" && pwd)" != "$dest" ]]; then
        mkdir -p "$dest"
        cp -f "${ICONS_DIR}"/*.{svg,png,jpg,jpeg,gif,webp} "$dest"/ 2>/dev/null || true
        log_info "Icons copied next to the report: ${dest}/"
    fi
}

zip_report() {
    [[ "$ZIP_REPORT" == true ]] || return 0
    if ! command -v zip >/dev/null 2>&1; then
        log_warn "'zip' is not installed - skipping packaging."
        return 0
    fi
    local report_dir report_name zip_name
    report_dir="$(cd "$(dirname "$REPORT_FILE")" && pwd)"
    report_name="$(basename "$REPORT_FILE")"
    zip_name="${report_name%.html}.zip"
    (
        cd "$report_dir" || exit 1
        rm -f "$zip_name"
        if [[ -d icons ]]; then
            zip -q -r "$zip_name" "$report_name" icons
        else
            zip -q "$zip_name" "$report_name"
        fi
    )
    if [[ -f "${report_dir}/${zip_name}" ]]; then
        log_ok "Portable package: ${C_BOLD}${zip_name}${C_RESET}  (HTML + icons/ in one zip)"
    else
        log_warn "Could not create ${zip_name}"
    fi
}

add_finding() {
    local sev="$1" cat="$2" title="$3" resource="$4" detail="$5"
    FINDINGS+=("${sev}${DELIM}${cat}${DELIM}${title}${DELIM}${resource}${DELIM}${detail}")
    case "$sev" in
        CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        WARNING)  WARNING_COUNT=$((WARNING_COUNT + 1)) ;;
        INFO)     INFO_COUNT=$((INFO_COUNT + 1)) ;;
    esac
}

mark_category_scanned() {
    local cat="$1" c
    for c in "${SCANNED_CATEGORIES[@]:-}"; do
        [[ "$c" == "$cat" ]] && return 0
    done
    SCANNED_CATEGORIES+=("$cat")
}

reset_state() {
    FINDINGS=()
    SCANNED_CATEGORIES=()
    CRITICAL_COUNT=0
    WARNING_COUNT=0
    INFO_COUNT=0
}

is_service_enabled() {
    local api="$1" s
    for s in "${ENABLED_SERVICES[@]:-}"; do
        [[ "$s" == "$api" ]] && return 0
    done
    return 1
}

# ------------------------------------------------------------------------------
#  PHASE 0: DEPENDENCIES AND CONTEXT
# ------------------------------------------------------------------------------
check_dependencies() {
    log_step "Checking dependencies and context..."

    if (( BASH_VERSINFO[0] < 4 )); then
        log_error "Bash 4 or higher is required (detected ${BASH_VERSION})."
        exit 1
    fi

    local missing=0
    if ! command -v gcloud >/dev/null 2>&1; then
        log_error "'gcloud' is not installed or not on PATH."
        missing=1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        log_error "'jq' is not installed. Install it (e.g. 'apt-get install jq')."
        missing=1
    fi
    (( missing )) && exit 1

    local active_account
    active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)
    if [[ -z "$active_account" ]]; then
        log_error "No active gcloud account. Run: gcloud auth login"
        exit 1
    fi
    log_ok "Authenticated as: ${C_BOLD}${active_account}${C_RESET}"
}

resolve_project() {
    PROJECT_ID="${1:-}"
    if [[ -z "$PROJECT_ID" ]]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
        [[ "$PROJECT_ID" == "(unset)" ]] && PROJECT_ID=""
    fi
    if [[ -z "$PROJECT_ID" ]]; then
        read -rp "$(printf '%s[?]%s Enter the PROJECT_ID to audit: ' "$C_YEL" "$C_RESET")" PROJECT_ID
    fi
    if [[ -z "$PROJECT_ID" ]]; then
        log_error "No project defined. Aborting."
        exit 1
    fi

    if ! gcloud projects describe "$PROJECT_ID" --format="value(projectId)" >/dev/null 2>&1; then
        log_error "Cannot access project '${PROJECT_ID}' (permissions or invalid ID)."
        exit 1
    fi
    log_ok "Target project: ${C_BOLD}${PROJECT_ID}${C_RESET}"

    REPORT_FILE="gcp_assessment_${PROJECT_ID}_$(date +%Y%m%d_%H%M%S).html"
}

# ------------------------------------------------------------------------------
#  PHASE 1: DYNAMIC AUTO-DISCOVERY
# ------------------------------------------------------------------------------
discover_services() {
    log_step "Phase 1 · Auto-discovery of enabled APIs..."

    local raw
    raw=$(gcloud services list --enabled \
            --project="$PROJECT_ID" \
            --format="value(config.name)" 2>/dev/null)

    if [[ -z "$raw" ]]; then
        log_warn "No enabled APIs detected (or missing serviceusage.services.list permission)."
        ENABLED_SERVICES=()
    else
        mapfile -t ENABLED_SERVICES <<< "$raw"
    fi
    log_ok "Enabled APIs detected: ${C_BOLD}${#ENABLED_SERVICES[@]}${C_RESET}"

    # The LB scanner uses compute.googleapis.com resources (forwarding-rules,
    # backend-services, ssl-policies, etc.) so we also treat it as enabled
    # when compute is active, even if networkservices isn't listed separately.
    local compute_active=0
    is_service_enabled "compute.googleapis.com" && compute_active=1
    if (( compute_active )) && ! is_service_enabled "networkservices.googleapis.com"; then
        ENABLED_SERVICES+=("networkservices.googleapis.com")
    fi

    DETECTED_SCANNABLE=()
    local api
    for api in "${KNOWN_SCANNABLE_ORDER[@]}"; do
        if is_service_enabled "$api"; then
            DETECTED_SCANNABLE+=("$api")
        fi
    done

    UNSCANNED_SERVICES=()
    for api in "${ENABLED_SERVICES[@]:-}"; do
        [[ -z "$api" ]] && continue
        if [[ -z "${API_TO_SCANNER[$api]:-}" ]]; then
            UNSCANNED_SERVICES+=("$api")
        fi
    done

    hr
    log_info "Analysis coverage:"
    printf '      %s• Total active services : %s%d%s\n' "$C_DIM" "$C_BOLD" "${#ENABLED_SERVICES[@]}" "$C_RESET"
    printf '      %s• With deep scan        : %s%d%s\n' "$C_DIM" "$C_GRN"  "${#DETECTED_SCANNABLE[@]}" "$C_RESET"
    printf '      %s• Inventory only        : %s%d%s\n' "$C_DIM" "$C_YEL"  "${#UNSCANNED_SERVICES[@]}" "$C_RESET"
    hr
    if (( ${#DETECTED_SCANNABLE[@]} == 0 )); then
        log_warn "None of the deep-scannable services are active."
    else
        log_info "Active services with a deep scan available:"
        local n=1
        for api in "${DETECTED_SCANNABLE[@]}"; do
            printf '      %s%2d.%s %-32s %s(%s)%s\n' \
                "$C_GRN" "$n" "$C_RESET" "${API_TO_LABEL[$api]}" "$C_DIM" "$api" "$C_RESET"
            n=$((n + 1))
        done
    fi
    hr
}

# ------------------------------------------------------------------------------
#  PHASE 3: SECURITY SCANNERS
# ------------------------------------------------------------------------------

# Sensitive TCP ports that should never be exposed to 0.0.0.0/0.
readonly SENSITIVE_PORTS_REGEX=':(22|23|21|3389|3306|5432|1433|1521|27017|6379|9200|9300|5601|11211|2375|2376|5900|5984|8020|9000|9092|2181|5000|8080|8443|10250|6443)([,]|$)'

# --- Compute Engine + VPC -----------------------------------------------------
scan_compute() {
    log_step "Scanning Compute Engine (instances, firewall, VPC)..."
    mark_category_scanned "COMPUTE"

    log_info "  → Checking project-wide metadata (OS Login)..."
    local proj_meta proj_oslogin
    proj_meta=$(gcloud compute project-info describe --project="$PROJECT_ID" --format=json 2>/dev/null)
    proj_oslogin=$(jq -r '[.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value] | .[0] // "unset"' <<< "$proj_meta" 2>/dev/null)
    if [[ "${proj_oslogin,,}" != "true" ]]; then
        add_finding "WARNING" "COMPUTE" "OS Login not enforced project-wide" \
            "project/${PROJECT_ID}" \
            "Project metadata enable-oslogin=${proj_oslogin}. OS Login centralizes SSH access via IAM and 2FA; enable it project-wide (CIS 4.4)."
        log_warn "    project OS Login = ${proj_oslogin}"
    fi

    log_info "  → Auditing VM instances (public IP, hardening, service accounts)..."
    local instances
    instances=$(gcloud compute instances list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -n "$instances" && "$instances" != "[]" ]]; then

        while IFS=$'\t' read -r name zone ip; do
            [[ -z "$name" ]] && continue
            add_finding "WARNING" "COMPUTE" "VM with a public IP address" \
                "${name} (${zone})" \
                "The instance exposes external IP ${ip}. Reduce the attack surface using IAP/Cloud NAT or a bastion host."
            log_warn "    Public IP: ${name} → ${ip}"
        done < <(jq -r '.[]
                    | select(.name | test("^gke-") | not)
                    | select(any(.networkInterfaces[]?.accessConfigs[]?; .natIP != null))
                    | [ .name, (.zone | split("/") | last),
                        ([.networkInterfaces[].accessConfigs[]?.natIP] | map(select(. != null)) | join(",")) ]
                    | @tsv' <<< "$instances")

        while IFS=$'\t' read -r name zone; do
            [[ -z "$name" ]] && continue
            add_finding "WARNING" "COMPUTE" "IP forwarding enabled" \
                "${name} (${zone})" \
                "canIpForward=true lets the VM route/spoof traffic for other addresses. Disable unless it is a NAT/router appliance (CIS 4.5)."
            log_warn "    IP forwarding: ${name}"
        done < <(jq -r '.[] | select(.canIpForward==true)
                    | [ .name, (.zone | split("/") | last) ] | @tsv' <<< "$instances")

        while IFS=$'\t' read -r name zone; do
            [[ -z "$name" ]] && continue
            add_finding "WARNING" "COMPUTE" "Shielded VM features incomplete" \
                "${name} (${zone})" \
                "Secure Boot / vTPM / integrity monitoring not all enabled. Shielded VM protects against boot- and kernel-level rootkits (CIS 4.8)."
            log_warn "    Shielded VM off: ${name}"
        done < <(jq -r '.[]
                    | select(.name | test("^gke-") | not)
                    | select((.shieldedInstanceConfig.enableSecureBoot // false)==false
                          or (.shieldedInstanceConfig.enableVtpm // false)==false
                          or (.shieldedInstanceConfig.enableIntegrityMonitoring // false)==false)
                    | [ .name, (.zone | split("/") | last) ] | @tsv' <<< "$instances")

        while IFS=$'\t' read -r name zone; do
            [[ -z "$name" ]] && continue
            add_finding "WARNING" "COMPUTE" "Serial-port access enabled" \
                "${name} (${zone})" \
                "Metadata serial-port-enable=true exposes the interactive serial console, which bypasses network controls. Disable it (CIS 4.6)."
            log_warn "    Serial port: ${name}"
        done < <(jq -r '.[]
                    | select([.metadata.items[]? | select(.key=="serial-port-enable") | (.value|ascii_downcase)] | .[0]=="true")
                    | [ .name, (.zone | split("/") | last) ] | @tsv' <<< "$instances")

        if [[ "${proj_oslogin,,}" != "true" ]]; then
            while IFS=$'\t' read -r name zone; do
                [[ -z "$name" ]] && continue
                add_finding "INFO" "COMPUTE" "OS Login not enabled on instance" \
                    "${name} (${zone})" \
                    "Neither project nor instance metadata enables OS Login. SSH keys are managed in metadata rather than via IAM."
            done < <(jq -r '.[]
                        | select(.name | test("^gke-") | not)
                        | select(([.metadata.items[]? | select(.key=="enable-oslogin") | (.value|ascii_downcase)] | .[0] // "unset") != "true")
                        | [ .name, (.zone | split("/") | last) ] | @tsv' <<< "$instances")
        fi

        while IFS=$'\t' read -r name zone sa scopes; do
            [[ -z "$name" ]] && continue
            local is_default="false"
            [[ "$sa" == *-compute@developer.gserviceaccount.com ]] && is_default="true"
            local full_scope="false"
            [[ "$scopes" == *"cloud-platform"* ]] && full_scope="true"
            if [[ "$is_default" == "true" && "$full_scope" == "true" ]]; then
                add_finding "CRITICAL" "COMPUTE" "Default SA with full API scope" \
                    "${name} (${zone})" \
                    "Instance runs as the default compute SA (${sa}) with the cloud-platform scope: a compromise grants project-wide API access. Use a dedicated least-privilege SA (CIS 4.1/4.2)."
                log_crit "    ${name}: default SA + full scope"
            elif [[ "$is_default" == "true" ]]; then
                add_finding "WARNING" "COMPUTE" "Instance uses default service account" \
                    "${name} (${zone})" \
                    "Instance runs as the default compute SA (${sa}). Prefer a dedicated SA with minimal roles (CIS 4.1)."
                log_warn "    ${name}: default SA"
            elif [[ "$full_scope" == "true" ]]; then
                add_finding "WARNING" "COMPUTE" "Instance has full cloud-platform scope" \
                    "${name} (${zone})" \
                    "The attached SA (${sa}) is granted the broad cloud-platform scope. Scope access down to the specific APIs needed (CIS 4.2)."
                log_warn "    ${name}: full scope"
            fi
        done < <(jq -r '.[]
                    | select(.name | test("^gke-") | not)
                    | select((.serviceAccounts // []) | length > 0)
                    | [ .name, (.zone | split("/") | last),
                        (.serviceAccounts[0].email // "none"),
                        ((.serviceAccounts[0].scopes // []) | join(",")) ]
                    | @tsv' <<< "$instances")

        while IFS=$'\t' read -r name zone; do
            [[ -z "$name" ]] && continue
            add_finding "INFO" "COMPUTE" "Project-wide SSH keys not blocked" \
                "${name} (${zone})" \
                "block-project-ssh-keys is not true; project-level SSH keys can log in to this VM. Set it to restrict access to instance-level keys (CIS 4.3)."
        done < <(jq -r '.[]
                    | select(.name | test("^gke-") | not)
                    | select(([.metadata.items[]? | select(.key=="block-project-ssh-keys") | (.value|ascii_downcase)] | .[0] // "false") != "true")
                    | [ .name, (.zone | split("/") | last) ] | @tsv' <<< "$instances")
    fi

    log_info "  → Looking for open firewall rules (0.0.0.0/0)..."
    local fw
    fw=$(gcloud compute firewall-rules list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -n "$fw" && "$fw" != "[]" ]]; then
        while IFS=$'\t' read -r name proto_ports; do
            [[ -z "$name" ]] && continue
            local sev="WARNING"
            if [[ "$proto_ports" == *"all"* || "$proto_ports" == *":*"* ]] \
               || [[ "$proto_ports" =~ $SENSITIVE_PORTS_REGEX ]]; then
                sev="CRITICAL"
            fi
            add_finding "$sev" "COMPUTE" "Firewall rule open to the Internet" \
                "$name" \
                "Ingress allowed from 0.0.0.0/0. Protocols/ports: ${proto_ports:-unspecified}. Restrict source ranges to known CIDRs or use IAP."
            if [[ "$sev" == "CRITICAL" ]]; then
                log_crit "    ${name} exposes ${proto_ports} to the world"
            else
                log_warn "    ${name} open to 0.0.0.0/0 (${proto_ports})"
            fi
        done < <(jq -r '.[]
                    | select((.direction // "INGRESS") == "INGRESS")
                    | select((.disabled // false) == false)
                    | select((.sourceRanges // []) | index("0.0.0.0/0"))
                    | [ .name,
                        ([.allowed[]? | .IPProtocol
                            + (if (.ports // []) | length > 0 then ":" + (.ports | join(",")) else ":*" end)]
                         | join(" ")) ]
                    | @tsv' <<< "$fw")
    fi

    log_info "  → Reviewing VPC networks..."
    local nets
    nets=$(gcloud compute networks list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -n "$nets" && "$nets" != "[]" ]]; then
        if jq -e '.[] | select(.name=="default")' <<< "$nets" >/dev/null 2>&1; then
            add_finding "WARNING" "COMPUTE" "Default VPC network present" \
                "default" \
                "The auto-created default network ships with permissive firewall rules. Use custom-mode VPCs (CIS 3.1)."
            log_warn "    default network exists"
        fi
        while IFS= read -r nname; do
            [[ -z "$nname" ]] && continue
            add_finding "WARNING" "COMPUTE" "Legacy network in use" \
                "$nname" \
                "Legacy (non-subnet) networks lack subnet-level controls and flow logs. Migrate to a subnet-mode VPC (CIS 3.2)."
            log_warn "    legacy network: ${nname}"
        done < <(jq -r '.[] | select(has("IPv4Range")) | .name' <<< "$nets")
    fi

    log_info "  → Reviewing subnets (flow logs, Private Google Access)..."
    local subnets
    subnets=$(gcloud compute networks subnets list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -n "$subnets" && "$subnets" != "[]" ]]; then
        while IFS=$'\t' read -r sname region; do
            [[ -z "$sname" ]] && continue
            add_finding "WARNING" "COMPUTE" "VPC flow logs disabled on subnet" \
                "${sname} (${region})" \
                "enableFlowLogs is false. Flow logs are essential for network forensics and anomaly detection (CIS 3.9)."
            log_warn "    flow logs off: ${sname}"
        done < <(jq -r '.[]
                    | select((.purpose // "PRIVATE")=="PRIVATE")
                    | select((.enableFlowLogs // false)==false)
                    | [ .name, (.region | split("/") | last) ] | @tsv' <<< "$subnets")

        while IFS=$'\t' read -r sname region; do
            [[ -z "$sname" ]] && continue
            add_finding "INFO" "COMPUTE" "Private Google Access disabled" \
                "${sname} (${region})" \
                "privateIpGoogleAccess is false; VMs without external IPs cannot reach Google APIs privately."
        done < <(jq -r '.[]
                    | select((.purpose // "PRIVATE")=="PRIVATE")
                    | select((.privateIpGoogleAccess // false)==false)
                    | [ .name, (.region | split("/") | last) ] | @tsv' <<< "$subnets")
    fi

    log_ok "Compute Engine / VPC done."
}

# ==============================================================================
#  LOAD BALANCING SCANNER  (v2.1 - new)
# ==============================================================================
# Checks:
#   1. Forwarding rules  – external vs internal, ports exposed
#   2. Backend services  – logging enabled, Cloud Armor policy attached, IAP state,
#                          connection draining, health-check configuration
#   3. SSL policies      – minimum TLS version, weak cipher suites (COMPATIBLE profile)
#   4. Target HTTPS/SSL  – proxies referencing a (possibly missing) SSL policy
#   5. Backend buckets   – public/private bucket backing, Cloud Armor
#   6. URL maps          – default route catch-all exposure
# ==============================================================================
scan_loadbalancer() {
    log_step "Scanning Cloud Load Balancing (forwarding rules, backends, SSL policies)..."
    mark_category_scanned "LOADBALANCER"

    # ------------------------------------------------------------------
    # 1. FORWARDING RULES
    # ------------------------------------------------------------------
    log_info "  → Auditing forwarding rules..."
    local fwd_rules
    fwd_rules=$(gcloud compute forwarding-rules list --project="$PROJECT_ID" --format=json 2>/dev/null)

    if [[ -z "$fwd_rules" || "$fwd_rules" == "[]" ]]; then
        log_info "  → No forwarding rules found. Skipping LB checks."
        log_ok "Load Balancing done."
        return 0
    fi

    # Track which backend services / SSL policies to inspect later
    declare -A LB_BACKEND_SERVICES=()
    declare -A LB_TARGET_HTTPS_PROXIES=()
    declare -A LB_TARGET_SSL_PROXIES=()

    while IFS=$'\t' read -r name region lb_scheme ports target; do
        [[ -z "$name" ]] && continue

        local scope="${region:-global}"

        # External LB: any forwarding rule with EXTERNAL or EXTERNAL_MANAGED scheme
        if [[ "$lb_scheme" == "EXTERNAL" || "$lb_scheme" == "EXTERNAL_MANAGED" ]]; then
            add_finding "INFO" "LOADBALANCER" "External forwarding rule detected" \
                "${name} (${scope})" \
                "Load balancer type: ${lb_scheme}. Ports exposed: ${ports:-all}. Verify that only intended ports are forwarded and that a Cloud Armor policy is attached."
            log_info "    External LB rule: ${name} ports=${ports:-all}"

            # Flag plain HTTP (port 80) on an external LB
            if [[ "$ports" == "80" || "$ports" == *",80,"* || "$ports" == *",80" || "$ports" == "80,"* ]]; then
                add_finding "WARNING" "LOADBALANCER" "External LB forwarding plain HTTP (port 80)" \
                    "${name} (${scope})" \
                    "Port 80 is exposed externally without TLS. Redirect HTTP to HTTPS at the load balancer or via a URL map."
                log_warn "    ${name}: external HTTP on port 80"
            fi
        fi

        # Collect targets for deeper inspection
        if [[ "$target" == *"targetHttpsProxies"* ]]; then
            LB_TARGET_HTTPS_PROXIES["${target##*/}"]="$scope"
        elif [[ "$target" == *"targetSslProxies"* ]]; then
            LB_TARGET_SSL_PROXIES["${target##*/}"]="$scope"
        fi

    done < <(jq -r '.[]
                | [ .name,
                    (if .region then (.region | split("/") | last) else "global" end),
                    (.loadBalancingScheme // "UNKNOWN"),
                    (.portRange // (.ports // []) | if type=="array" then join(",") else . end // ""),
                    (.target // "") ]
                | @tsv' <<< "$fwd_rules")

    # ------------------------------------------------------------------
    # 2. BACKEND SERVICES
    # ------------------------------------------------------------------
    log_info "  → Auditing backend services (logging, Cloud Armor, IAP, health checks)..."
    local backends
    backends=$(gcloud compute backend-services list --project="$PROJECT_ID" --format=json 2>/dev/null)

    if [[ -n "$backends" && "$backends" != "[]" ]]; then
        while IFS=$'\t' read -r name scope protocol logging armor iap cdn timeout; do
            [[ -z "$name" ]] && continue
            log_info "    → Backend service: ${name} (${scope}) proto=${protocol}"

            # Logging disabled on backend service
            if [[ "$logging" != "true" ]]; then
                add_finding "WARNING" "LOADBALANCER" "Backend service logging disabled" \
                    "${name} (${scope})" \
                    "Access logging is not enabled for this backend service. Enable it to audit traffic, detect anomalies, and support incident response."
                log_warn "    ${name}: backend logging off"
            fi

            # No Cloud Armor security policy
            if [[ -z "$armor" || "$armor" == "null" || "$armor" == "None" ]]; then
                add_finding "WARNING" "LOADBALANCER" "No Cloud Armor policy attached" \
                    "${name} (${scope})" \
                    "The backend service has no Cloud Armor security policy. Without it, the backend is unprotected against DDoS, OWASP top-10, and volumetric attacks."
                log_warn "    ${name}: no Cloud Armor"
            fi

            # IAP (Identity-Aware Proxy) check
            if [[ "$iap" != "true" ]]; then
                add_finding "INFO" "LOADBALANCER" "Identity-Aware Proxy (IAP) not enabled" \
                    "${name} (${scope})" \
                    "IAP is disabled on this backend. For internal corporate applications, enabling IAP enforces identity-based access control without a VPN."
            fi

            # HTTP backend on an external-facing service (protocol)
            if [[ "$protocol" == "HTTP" ]]; then
                add_finding "INFO" "LOADBALANCER" "Backend uses plain HTTP protocol" \
                    "${name} (${scope})" \
                    "The backend service communicates with backends over plain HTTP. Consider using HTTPS to encrypt traffic between the load balancer and the backends."
            fi

        done < <(jq -r '.[]
                    | [ .name,
                        (if .region then (.region | split("/") | last) else "global" end),
                        (.protocol // "UNKNOWN"),
                        ((.logConfig.enable // false) | tostring),
                        (.securityPolicy // "null"),
                        ((.iap.enabled // false) | tostring),
                        ((.cdnPolicy != null) | tostring),
                        (.timeoutSec // 30 | tostring) ]
                    | @tsv' <<< "$backends")
    fi

    # ------------------------------------------------------------------
    # 3. SSL POLICIES
    # ------------------------------------------------------------------
    log_info "  → Auditing SSL policies (TLS version, cipher profile)..."
    local ssl_policies
    ssl_policies=$(gcloud compute ssl-policies list --project="$PROJECT_ID" --format=json 2>/dev/null)

    if [[ -n "$ssl_policies" && "$ssl_policies" != "[]" ]]; then
        while IFS=$'\t' read -r name min_tls profile; do
            [[ -z "$name" ]] && continue

            # Weak minimum TLS version
            if [[ "$min_tls" == "TLS_1_0" || "$min_tls" == "TLS_1_1" ]]; then
                add_finding "CRITICAL" "LOADBALANCER" "SSL policy allows weak TLS version" \
                    "$name" \
                    "Minimum TLS version is ${min_tls}. TLS 1.0 and 1.1 are deprecated (RFC 8996) and vulnerable to POODLE/BEAST. Set minTlsVersion to TLS_1_2 or higher."
                log_crit "    SSL policy ${name}: min TLS = ${min_tls}"
            fi

            # COMPATIBLE profile enables many legacy/weak cipher suites
            if [[ "$profile" == "COMPATIBLE" ]]; then
                add_finding "WARNING" "LOADBALANCER" "SSL policy uses COMPATIBLE cipher profile" \
                    "$name" \
                    "The COMPATIBLE profile enables legacy cipher suites (e.g. 3DES, RC4) to support old clients. Use MODERN or RESTRICTED to enforce stronger ciphers."
                log_warn "    SSL policy ${name}: COMPATIBLE profile"
            fi

            # Custom profile — flag for review
            if [[ "$profile" == "CUSTOM" ]]; then
                add_finding "INFO" "LOADBALANCER" "SSL policy uses CUSTOM cipher profile" \
                    "$name" \
                    "A CUSTOM cipher profile requires manual review to ensure no weak ciphers are included."
            fi

        done < <(jq -r '.[]
                    | [ .name,
                        (.minTlsVersion // "TLS_1_0"),
                        (.profile // "COMPATIBLE") ]
                    | @tsv' <<< "$ssl_policies")
    else
        # No SSL policies defined — HTTPS/SSL proxies will use the default (COMPATIBLE / TLS 1.0)
        add_finding "WARNING" "LOADBALANCER" "No SSL policies defined (using GCP defaults)" \
            "project/${PROJECT_ID}" \
            "No custom SSL policies exist. GCP's default SSL policy uses the COMPATIBLE profile with TLS 1.0 as minimum, which allows legacy/weak cipher suites. Create a policy with at least TLS_1_2 and the MODERN profile."
        log_warn "    No SSL policies — GCP default allows TLS 1.0 + weak ciphers"
    fi

    # ------------------------------------------------------------------
    # 4. TARGET HTTPS PROXIES — SSL policy attached?
    # ------------------------------------------------------------------
    log_info "  → Checking target HTTPS proxies for SSL policy assignment..."
    local https_proxies
    https_proxies=$(gcloud compute target-https-proxies list --project="$PROJECT_ID" --format=json 2>/dev/null)

    if [[ -n "$https_proxies" && "$https_proxies" != "[]" ]]; then
        while IFS=$'\t' read -r name ssl_policy; do
            [[ -z "$name" ]] && continue
            if [[ -z "$ssl_policy" || "$ssl_policy" == "null" || "$ssl_policy" == "None" ]]; then
                add_finding "WARNING" "LOADBALANCER" "HTTPS proxy has no SSL policy" \
                    "$name" \
                    "No custom SSL policy is assigned to this target HTTPS proxy. It falls back to the GCP default (COMPATIBLE profile, TLS 1.0+). Assign an SSL policy that enforces TLS 1.2+ and a MODERN or RESTRICTED cipher profile."
                log_warn "    HTTPS proxy ${name}: no SSL policy"
            fi
        done < <(jq -r '.[]
                    | [ .name,
                        (.sslPolicy // "null") ]
                    | @tsv' <<< "$https_proxies")
    fi

    # ------------------------------------------------------------------
    # 5. TARGET SSL PROXIES — SSL policy attached?
    # ------------------------------------------------------------------
    log_info "  → Checking target SSL proxies for SSL policy assignment..."
    local ssl_proxies
    ssl_proxies=$(gcloud compute target-ssl-proxies list --project="$PROJECT_ID" --format=json 2>/dev/null)

    if [[ -n "$ssl_proxies" && "$ssl_proxies" != "[]" ]]; then
        while IFS=$'\t' read -r name ssl_policy; do
            [[ -z "$name" ]] && continue
            if [[ -z "$ssl_policy" || "$ssl_policy" == "null" || "$ssl_policy" == "None" ]]; then
                add_finding "WARNING" "LOADBALANCER" "SSL proxy has no SSL policy" \
                    "$name" \
                    "No custom SSL policy is assigned to this target SSL proxy. Assign an SSL policy that enforces TLS 1.2+ and MODERN/RESTRICTED ciphers."
                log_warn "    SSL proxy ${name}: no SSL policy"
            fi
        done < <(jq -r '.[]
                    | [ .name,
                        (.sslPolicy // "null") ]
                    | @tsv' <<< "$ssl_proxies")
    fi

    # ------------------------------------------------------------------
    # 6. BACKEND BUCKETS — public access?
    # ------------------------------------------------------------------
    log_info "  → Checking backend buckets..."
    local backend_buckets
    backend_buckets=$(gcloud compute backend-buckets list --project="$PROJECT_ID" --format=json 2>/dev/null)

    if [[ -n "$backend_buckets" && "$backend_buckets" != "[]" ]]; then
        while IFS=$'\t' read -r name bucket_name cdn armor; do
            [[ -z "$name" ]] && continue

            add_finding "INFO" "LOADBALANCER" "Backend bucket detected" \
                "${name} → gs://${bucket_name}" \
                "A GCS bucket is serving content via the load balancer. Ensure the bucket has Public Access Prevention enforced and that the IAM policy does not grant allUsers any role."

            # Cloud Armor on backend bucket
            if [[ -z "$armor" || "$armor" == "null" || "$armor" == "None" ]]; then
                add_finding "WARNING" "LOADBALANCER" "Backend bucket has no Cloud Armor policy" \
                    "${name} → gs://${bucket_name}" \
                    "No Cloud Armor security policy is attached to this backend bucket. Static assets served over the internet benefit from DDoS protection and WAF rules."
                log_warn "    backend bucket ${name}: no Cloud Armor"
            fi

        done < <(jq -r '.[]
                    | [ .name,
                        (.bucketName // "unknown"),
                        ((.cdnPolicy != null) | tostring),
                        (.edgeSecurityPolicy // "null") ]
                    | @tsv' <<< "$backend_buckets")
    fi

    # ------------------------------------------------------------------
    # 7. URL MAPS — default service / catch-all route
    # ------------------------------------------------------------------
    log_info "  → Checking URL maps for catch-all / default route exposure..."
    local url_maps
    url_maps=$(gcloud compute url-maps list --project="$PROJECT_ID" --format=json 2>/dev/null)

    if [[ -n "$url_maps" && "$url_maps" != "[]" ]]; then
        while IFS=$'\t' read -r name default_svc; do
            [[ -z "$name" ]] && continue
            if [[ -n "$default_svc" && "$default_svc" != "null" ]]; then
                add_finding "INFO" "LOADBALANCER" "URL map has a default backend service (catch-all route)" \
                    "$name" \
                    "Default service: ${default_svc##*/}. Unmatched paths route to this backend. Verify the default backend is intentional and not exposing unintended endpoints."
            fi
        done < <(jq -r '.[]
                    | [ .name,
                        (.defaultService // "null") ]
                    | @tsv' <<< "$url_maps")
    fi

    log_ok "Load Balancing done."
}

# --- Cloud Storage -------------------------------------------------------------
scan_storage() {
    log_step "Scanning Cloud Storage (buckets)..."
    mark_category_scanned "STORAGE"

    local buckets
    buckets=$(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)" 2>/dev/null)
    if [[ -z "$buckets" ]]; then
        log_info "  → No buckets detected."
        log_ok "Cloud Storage done."
        return 0
    fi

    local bucket
    while IFS= read -r bucket; do
        [[ -z "$bucket" ]] && continue
        log_info "  → Analyzing gs://${bucket}"

        local public_roles
        public_roles=$(gcloud storage buckets get-iam-policy "gs://${bucket}" \
                          --format=json 2>/dev/null \
                       | jq -r '.bindings[]?
                                 | select((.members // []) | any(. == "allUsers" or . == "allAuthenticatedUsers"))
                                 | .role' 2>/dev/null | paste -sd', ' -)
        if [[ -n "$public_roles" ]]; then
            add_finding "CRITICAL" "STORAGE" "Bucket with public access" \
                "gs://${bucket}" \
                "Granted to allUsers/allAuthenticatedUsers with roles: ${public_roles}."
            log_crit "    ${bucket} is PUBLIC (${public_roles})"
        fi

        local meta kms pap ubla ver logbucket retention
        meta=$(gcloud storage buckets describe "gs://${bucket}" --format=json 2>/dev/null)
        kms=$(jq -r '(.default_kms_key // .defaultKmsKeyName // .encryption.defaultKmsKeyName // "None")' <<< "$meta" 2>/dev/null)
        pap=$(jq -r '(.public_access_prevention // .publicAccessPrevention // "inherited")' <<< "$meta" 2>/dev/null)
        ubla=$(jq -r '(.uniform_bucket_level_access.enabled // .iamConfiguration.uniformBucketLevelAccess.enabled // false) | tostring' <<< "$meta" 2>/dev/null)
        ver=$(jq -r '(.versioning.enabled // .versioning // false) | tostring' <<< "$meta" 2>/dev/null)
        logbucket=$(jq -r '(.logging.logBucket // .logging.log_bucket // "None")' <<< "$meta" 2>/dev/null)
        retention=$(jq -r '(.retentionPolicy.retentionPeriod // .retention_policy.retention_period // "None")' <<< "$meta" 2>/dev/null)

        if [[ -z "$kms" || "$kms" == "None" || "$kms" == "null" ]]; then
            add_finding "INFO" "STORAGE" "No CMEK (Google-managed encryption)" \
                "gs://${bucket}" "For regulated data, consider a CMEK key."
        fi
        if [[ "$pap" != "enforced" ]]; then
            add_finding "WARNING" "STORAGE" "Public Access Prevention not enforced" \
                "gs://${bucket}" "Current state: ${pap:-inherited}. Set it to 'enforced' (CIS 5.1)."
            log_warn "    ${bucket}: PAP=${pap:-inherited}"
        fi
        if [[ "$ubla" != "true" ]]; then
            add_finding "WARNING" "STORAGE" "Uniform bucket-level access disabled" \
                "gs://${bucket}" "Object-level ACLs bypass IAM. Enable uniform bucket-level access (CIS 5.2)."
            log_warn "    ${bucket}: UBLA off"
        fi
        if [[ "$ver" != "true" ]]; then
            add_finding "INFO" "STORAGE" "Object versioning disabled" \
                "gs://${bucket}" "Versioning is off; overwritten or deleted objects cannot be recovered."
        fi
        if [[ -z "$logbucket" || "$logbucket" == "None" || "$logbucket" == "null" ]]; then
            add_finding "INFO" "STORAGE" "Access/usage logging not configured" \
                "gs://${bucket}" "No logging.logBucket is set; data-access to this bucket is not logged."
        fi
        if [[ -z "$retention" || "$retention" == "None" || "$retention" == "null" ]]; then
            add_finding "INFO" "STORAGE" "No retention policy / bucket lock" \
                "gs://${bucket}" "No retention policy is set. For audit/compliance data, a locked retention policy prevents premature deletion."
        fi
    done <<< "$buckets"

    log_ok "Cloud Storage done."
}

# --- IAM -----------------------------------------------------------------------
scan_iam() {
    log_step "Scanning IAM (service accounts + policies)..."
    mark_category_scanned "IAM"

    log_info "  → Auditing service account keys..."
    local sas sa
    sas=$(gcloud iam service-accounts list --project="$PROJECT_ID" --format="value(email)" 2>/dev/null)
    if [[ -n "$sas" ]]; then
        while IFS= read -r sa; do
            [[ -z "$sa" ]] && continue
            local keys
            keys=$(gcloud iam service-accounts keys list --iam-account="$sa" \
                      --managed-by=user --format=json 2>/dev/null)
            [[ -z "$keys" || "$keys" == "[]" ]] && continue

            local key_count
            key_count=$(jq 'length' <<< "$keys" 2>/dev/null || echo 0)
            if (( key_count > 0 )); then
                add_finding "INFO" "IAM" "User-managed SA key present" \
                    "$sa" \
                    "${key_count} user-managed key(s) exist. Prefer Workload Identity Federation or short-lived tokens (CIS 1.4)."
            fi

            while IFS=$'\t' read -r key_id valid_after; do
                [[ -z "$key_id" ]] && continue
                local created_epoch age_days=""
                created_epoch=$(date -d "$valid_after" +%s 2>/dev/null || echo "")
                if [[ -n "$created_epoch" ]]; then
                    age_days=$(( ( $(date +%s) - created_epoch ) / 86400 ))
                fi
                [[ -z "$age_days" ]] && continue

                local short_id="${key_id:0:12}…"
                if (( age_days > KEY_CRIT_DAYS )); then
                    add_finding "CRITICAL" "IAM" "Very old SA key" \
                        "$sa" "Key ${short_id} is ${age_days} days old (> ${KEY_CRIT_DAYS}). Rotate immediately."
                    log_crit "    ${sa}: ${age_days}d old key"
                elif (( age_days > KEY_WARN_DAYS )); then
                    add_finding "WARNING" "IAM" "Old SA key" \
                        "$sa" "Key ${short_id} is ${age_days} days old (> ${KEY_WARN_DAYS}). Plan its rotation."
                    log_warn "    ${sa}: ${age_days}d old key"
                fi
            done < <(jq -r '.[] | [ (.name | split("/") | last), .validAfterTime ] | @tsv' <<< "$keys")
        done <<< "$sas"
    fi

    log_info "  → Evaluating project-level roles..."
    local policy
    policy=$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -n "$policy" ]]; then
        while IFS=$'\t' read -r role member; do
            [[ -z "$role" ]] && continue
            add_finding "CRITICAL" "IAM" "Role granted to a public identity" \
                "$member" "The public principal is assigned ${role} over the project."
            log_crit "    ${member} → ${role}"
        done < <(jq -r '.bindings[]?
                        | .role as $r | .members[]?
                        | select(. == "allUsers" or . == "allAuthenticatedUsers")
                        | [ $r, . ] | @tsv' <<< "$policy")

        while IFS=$'\t' read -r role member; do
            [[ -z "$role" ]] && continue
            local sev="WARNING"
            [[ "$role" == "roles/owner" && "$member" == user:* ]] && sev="CRITICAL"
            add_finding "$sev" "IAM" "Excessive primitive role" \
                "$member" "Assignment of ${role}. Apply least privilege."
            if [[ "$sev" == "CRITICAL" ]]; then log_crit "    ${member} is OWNER"
            else log_warn "    ${member} → ${role}"; fi
        done < <(jq -r '.bindings[]?
                        | select(.role == "roles/owner" or .role == "roles/editor")
                        | .role as $r | .members[]?
                        | select(. != "allUsers" and . != "allAuthenticatedUsers")
                        | [ $r, . ] | @tsv' <<< "$policy")

        log_info "  → Checking for privilege-escalation roles..."
        while IFS=$'\t' read -r role member; do
            [[ -z "$role" ]] && continue
            add_finding "WARNING" "IAM" "Privilege-escalation-prone role" \
                "$member" "Holds ${role}, which enables SA impersonation or IAM policy control."
            log_warn "    ${member} → ${role}"
        done < <(jq -r '.bindings[]?
                        | select(.role | test("serviceAccountTokenCreator|serviceAccountUser|serviceAccountKeyAdmin|serviceAccountAdmin|iam\\.securityAdmin|iam\\.roleAdmin|resourcemanager\\..*(Admin|IamAdmin)"))
                        | .role as $r | .members[]?
                        | select(. != "allUsers" and . != "allAuthenticatedUsers")
                        | [ $r, . ] | @tsv' <<< "$policy")

        while IFS=$'\t' read -r role member; do
            [[ -z "$role" ]] && continue
            add_finding "WARNING" "IAM" "Default SA with primitive role" \
                "$member" "A Google-created default SA holds ${role}. Remove the primitive grant (CIS 1.5)."
            log_warn "    default SA ${member} → ${role}"
        done < <(jq -r '.bindings[]?
                        | select(.role == "roles/owner" or .role == "roles/editor")
                        | .role as $r | .members[]?
                        | select(test("-compute@developer\\.gserviceaccount\\.com$") or test("@appspot\\.gserviceaccount\\.com$"))
                        | [ $r, . ] | @tsv' <<< "$policy")

        while IFS=$'\t' read -r role member; do
            [[ -z "$role" ]] && continue
            add_finding "WARNING" "IAM" "Personal account granted access" \
                "$member" "A gmail.com account holds ${role}. Use managed identities (CIS 1.1)."
            log_warn "    personal account ${member} → ${role}"
        done < <(jq -r '.bindings[]?
                        | .role as $r | .members[]?
                        | select(test("^user:.*@gmail\\.com$"))
                        | [ $r, . ] | @tsv' <<< "$policy")

        log_info "  → Checking data-access audit logging..."
        local audit_all
        audit_all=$(jq -r '[.auditConfigs[]? | select(.service=="allServices")
                            | .auditLogConfigs[]?.logType] | sort | join(",")' <<< "$policy" 2>/dev/null)
        if [[ "$audit_all" != *"DATA_READ"* || "$audit_all" != *"DATA_WRITE"* ]]; then
            add_finding "WARNING" "IAM" "Data-access audit logs not fully enabled" \
                "project/${PROJECT_ID}" \
                "allServices audit config does not enable both DATA_READ and DATA_WRITE (found: ${audit_all:-none}). Enable them (CIS 2.1)."
            log_warn "    audit logging incomplete: ${audit_all:-none}"
        fi
    fi

    log_ok "IAM done."
}

# --- Cloud SQL -----------------------------------------------------------------
scan_sql() {
    log_step "Scanning Cloud SQL (instances)..."
    mark_category_scanned "SQL"

    local sql
    sql=$(gcloud sql instances list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -z "$sql" || "$sql" == "[]" ]]; then
        log_info "  → No Cloud SQL instances detected."
        log_ok "Cloud SQL done."
        return 0
    fi

    while IFS=$'\t' read -r name has_public networks ssl_mode engine backups pitr delprot cmek flags; do
        [[ -z "$name" ]] && continue
        log_info "  → Analyzing ${name} (${engine})"

        if [[ "$networks" == *"0.0.0.0/0"* ]]; then
            add_finding "CRITICAL" "SQL" "Cloud SQL open to the Internet" \
                "$name" "Authorized network 0.0.0.0/0 detected (CIS 6.5)."
            log_crit "    ${name} authorizes 0.0.0.0/0"
        elif [[ "$has_public" == "true" ]]; then
            add_finding "WARNING" "SQL" "Instance with a public IP" \
                "$name" "Public IPv4 enabled. Authorized networks: ${networks:-none}. Prefer private IP (CIS 6.6)."
            log_warn "    ${name} has a public IP"
        fi

        if [[ "$has_public" == "true" && ( "$ssl_mode" == "false" || "$ssl_mode" == "ALLOW_UNENCRYPTED_AND_ENCRYPTED" ) ]]; then
            add_finding "WARNING" "SQL" "Non-TLS connections allowed" \
                "$name" "Public instance accepting unencrypted connections (CIS 6.4)."
            log_warn "    ${name} allows non-TLS connections"
        fi
        if [[ "$backups" != "true" ]]; then
            add_finding "WARNING" "SQL" "Automated backups disabled" "$name" "Enable automated backups (CIS 6.7)."
        fi
        if [[ "$pitr" != "true" ]]; then
            add_finding "INFO" "SQL" "Point-in-time recovery disabled" "$name" "PITR is off."
        fi
        if [[ "$delprot" != "true" ]]; then
            add_finding "INFO" "SQL" "Deletion protection disabled" "$name" "Enable deletion protection for production."
        fi
        if [[ -z "$cmek" || "$cmek" == "None" || "$cmek" == "null" ]]; then
            add_finding "INFO" "SQL" "No CMEK encryption" "$name" "Uses Google-managed encryption."
        fi

        _sql_flag() { jq -r --arg f "$1" '(.[$f] // "unset")' <<< "$flags" 2>/dev/null; }
        if [[ "$engine" == POSTGRES* ]]; then
            [[ "$(_sql_flag log_checkpoints)"    == "off" ]] && add_finding "INFO"    "SQL" "PostgreSQL flag: log_checkpoints=off"       "$name" "Enable log_checkpoints (CIS 6.2.x)."
            [[ "$(_sql_flag log_connections)"    != "on"  ]] && add_finding "WARNING" "SQL" "PostgreSQL flag: log_connections not on"     "$name" "log_connections should be on (CIS 6.2.x)."
            [[ "$(_sql_flag log_disconnections)" != "on"  ]] && add_finding "WARNING" "SQL" "PostgreSQL flag: log_disconnections not on"  "$name" "log_disconnections should be on (CIS 6.2.x)."
            [[ "$(_sql_flag "cloudsql.enable_pgaudit")" != "on" ]] && add_finding "INFO" "SQL" "PostgreSQL flag: pgAudit not enabled"    "$name" "Enable pgAudit (CIS 6.2.x)."
        elif [[ "$engine" == MYSQL* ]]; then
            [[ "$(_sql_flag local_infile)"       == "on"  ]] && add_finding "WARNING" "SQL" "MySQL flag: local_infile=on"                "$name" "Disable local_infile (CIS 6.1.2)."
            [[ "$(_sql_flag skip_show_database)" != "on"  ]] && add_finding "INFO"    "SQL" "MySQL flag: skip_show_database not on"      "$name" "Enable skip_show_database (CIS 6.1.x)."
        elif [[ "$engine" == SQLSERVER* ]]; then
            [[ "$(_sql_flag "external scripts enabled")"         == "on" ]] && add_finding "WARNING" "SQL" "SQL Server: external scripts enabled"          "$name" "Disable external scripts (CIS 6.3.x)."
            [[ "$(_sql_flag "cross db ownership chaining")"      == "on" ]] && add_finding "WARNING" "SQL" "SQL Server: cross db ownership chaining"       "$name" "Disable cross-db ownership chaining (CIS 6.3.1)."
            [[ "$(_sql_flag "contained database authentication")" == "on" ]] && add_finding "INFO"    "SQL" "SQL Server: contained database authentication" "$name" "Review contained database authentication (CIS 6.3.x)."
        fi
        unset -f _sql_flag
    done < <(jq -r '.[]
                | [ .name,
                    ((.settings.ipConfiguration.ipv4Enabled // false) | tostring),
                    ([.settings.ipConfiguration.authorizedNetworks[]?.value] | join(",")),
                    ((.settings.ipConfiguration.sslMode // .settings.ipConfiguration.requireSsl // "unknown") | tostring),
                    (.databaseVersion // "UNKNOWN"),
                    ((.settings.backupConfiguration.enabled // false) | tostring),
                    ((.settings.backupConfiguration.pointInTimeRecoveryEnabled // .settings.backupConfiguration.binaryLogEnabled // false) | tostring),
                    ((.settings.deletionProtectionEnabled // false) | tostring),
                    (.diskEncryptionConfiguration.kmsKeyName // "None"),
                    ((reduce (.settings.databaseFlags[]? ) as $f ({}; .[$f.name] = $f.value)) | tojson) ]
                | @tsv' <<< "$sql")

    log_ok "Cloud SQL done."
}

# --- GKE -----------------------------------------------------------------------
scan_gke() {
    log_step "Scanning Google Kubernetes Engine (clusters + node pools)..."
    mark_category_scanned "GKE"

    local clusters
    clusters=$(gcloud container clusters list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -z "$clusters" || "$clusters" == "[]" ]]; then
        log_info "  → No GKE clusters detected."
        log_ok "GKE done."
        return 0
    fi

    while IFS=$'\t' read -r name priv_endpoint man_networks dashboard_disabled legacy_abac \
                            netpol wi shielded binauthz basic_auth client_cert dbenc \
                            priv_nodes intranode channel logging monitoring; do
        [[ -z "$name" ]] && continue
        log_info "  → Analyzing cluster ${name}"

        if [[ "$priv_endpoint" != "true" ]]; then
            if [[ "$man_networks" != "true" ]]; then
                add_finding "CRITICAL" "GKE" "Public endpoint without authorized networks" \
                    "$name" "Control plane reachable from any IP (CIS 5.6.x)."
                log_crit "    ${name}: control plane open to the world"
            else
                add_finding "WARNING" "GKE" "Public control-plane endpoint" \
                    "$name" "Public endpoint with authorized networks. Consider a private cluster."
                log_warn "    ${name}: public endpoint (restricted)"
            fi
        fi
        [[ "$dashboard_disabled" == "false" ]] && { add_finding "CRITICAL" "GKE" "Kubernetes Dashboard enabled" "$name" "Deprecated, history of RCE. Disable it (CIS 5.10.1)."; log_crit "    ${name}: dashboard"; }
        [[ "$legacy_abac" == "true"          ]] && { add_finding "WARNING"  "GKE" "Legacy ABAC enabled"         "$name" "Undermines RBAC. Disable it (CIS 5.8.4)."; log_warn "    ${name}: legacy ABAC"; }
        [[ "$basic_auth" == "true"           ]] && { add_finding "CRITICAL" "GKE" "Basic authentication enabled" "$name" "Static password auth. Disable (CIS 5.8.1)."; log_crit "    ${name}: basic auth"; }
        [[ "$client_cert" == "true"          ]] && { add_finding "WARNING"  "GKE" "Client certificate auth enabled" "$name" "Cannot be revoked easily. Disable (CIS 5.8.2)."; log_warn "    ${name}: client cert"; }
        [[ "$netpol" != "true"               ]] && { add_finding "WARNING"  "GKE" "Network Policy disabled"     "$name" "Pods unrestricted. Enable NetworkPolicy (CIS 5.6.7)."; log_warn "    ${name}: netpol off"; }
        [[ -z "$wi" || "$wi" == "None" || "$wi" == "null" ]] && { add_finding "WARNING" "GKE" "Workload Identity not configured" "$name" "Enable Workload Identity (CIS 5.2.2)."; log_warn "    ${name}: no WI"; }
        [[ "$shielded" != "true"             ]] && { add_finding "WARNING"  "GKE" "Shielded GKE nodes disabled"  "$name" "Enable shielded nodes (CIS 5.5.x)."; log_warn "    ${name}: shielded off"; }
        [[ -z "$binauthz" || "$binauthz" == "DISABLED" || "$binauthz" == "null" || "$binauthz" == "None" ]] && add_finding "INFO" "GKE" "Binary Authorization disabled" "$name" "Unsigned images can be deployed (CIS 5.10.4)."
        [[ "$dbenc" != "ENCRYPTED"           ]] && { add_finding "WARNING"  "GKE" "Application-layer secrets encryption off" "$name" "Enable KMS secrets encryption (CIS 5.3.1)."; log_warn "    ${name}: secrets unencrypted"; }
        [[ "$priv_nodes" != "true"           ]] && add_finding "INFO" "GKE" "Nodes have public IPs" "$name" "Use private cluster to remove direct node exposure."
        [[ "$intranode" != "true"            ]] && add_finding "INFO" "GKE" "Intranode visibility disabled" "$name" "Pod-to-pod traffic invisible to flow logs (CIS 5.6.4)."
        [[ -z "$channel" || "$channel" == "None" || "$channel" == "null" || "$channel" == "UNSPECIFIED" ]] && add_finding "INFO" "GKE" "Not enrolled in a release channel" "$name" "Security patches not auto-applied (CIS 5.5.x)."
        [[ "$logging" == "none" || "$logging" == "None" || -z "$logging"         ]] && { add_finding "WARNING" "GKE" "Cloud Logging disabled"    "$name" "Cluster logging off (CIS 5.7.1)."; log_warn "    ${name}: logging off"; }
        [[ "$monitoring" == "none" || "$monitoring" == "None" || -z "$monitoring" ]] && add_finding "INFO" "GKE" "Cloud Monitoring disabled" "$name" "Cluster monitoring off (CIS 5.7.1)."

        while IFS=$'\t' read -r pool autoupg autorep legacy_meta node_sa node_scopes; do
            [[ -z "$pool" ]] && continue
            [[ "$autoupg" != "true"      ]] && { add_finding "WARNING" "GKE" "Node auto-upgrade disabled"           "${name}/${pool}" "Enable auto-upgrade (CIS 5.5.2)."; log_warn "    ${name}/${pool}: auto-upgrade off"; }
            [[ "$autorep" != "true"      ]] && add_finding "INFO"    "GKE" "Node auto-repair disabled"             "${name}/${pool}" "Enable auto-repair (CIS 5.5.3)."
            [[ "$legacy_meta" != "true"  ]] && { add_finding "WARNING" "GKE" "Legacy metadata endpoints reachable" "${name}/${pool}" "Disable legacy metadata API (CIS 5.4.1)."; log_warn "    ${name}/${pool}: legacy metadata"; }
            [[ "$node_sa" == "default"   ]] && { add_finding "WARNING" "GKE" "Node pool uses default compute SA"   "${name}/${pool}" "Use a dedicated minimal SA (CIS 5.2.1)."; log_warn "    ${name}/${pool}: default node SA"; }
            [[ "$node_scopes" == *"cloud-platform"* || "$node_scopes" == *"compute-rw"* ]] && { add_finding "WARNING" "GKE" "Node pool has overly broad OAuth scopes" "${name}/${pool}" "Restrict scopes (CIS 5.2.1)."; log_warn "    ${name}/${pool}: broad scopes"; }
        done < <(jq -r --arg c "$name" '.[] | select(.name==$c) | .nodePools[]?
                    | [ .name,
                        ((.management.autoUpgrade // false) | tostring),
                        ((.management.autoRepair // false) | tostring),
                        (([.config.metadata["disable-legacy-endpoints"]] | .[0] // "false") | tostring),
                        (if (.config.serviceAccount // "default")=="default" then "default" else "custom" end),
                        ((.config.oauthScopes // []) | join(",")) ]
                    | @tsv' <<< "$clusters")

    done < <(jq -r '.[]
                | [ .name,
                    ((.privateClusterConfig.enablePrivateEndpoint // false) | tostring),
                    ((.masterAuthorizedNetworksConfig.enabled // false) | tostring),
                    ((.addonsConfig.kubernetesDashboard.disabled // true) | tostring),
                    ((.legacyAbac.enabled // false) | tostring),
                    ((.networkPolicy.enabled // false) | tostring),
                    (.workloadIdentityConfig.workloadPool // "None"),
                    ((.shieldedNodes.enabled // false) | tostring),
                    (.binaryAuthorization.evaluationMode // (if (.binaryAuthorization.enabled // false) then "ENABLED" else "DISABLED" end)),
                    ((.masterAuth.username // "" | length > 0) | tostring),
                    ((.masterAuth.clientCertificateConfig.issueClientCertificate // false) | tostring),
                    (.databaseEncryption.state // "DECRYPTED"),
                    ((.privateClusterConfig.enablePrivateNodes // false) | tostring),
                    ((.networkConfig.enableIntraNodeVisibility // false) | tostring),
                    (.releaseChannel.channel // "None"),
                    (.loggingService // "none"),
                    (.monitoringService // "none") ]
                | @tsv' <<< "$clusters")

    log_ok "GKE done."
}

public_roles_from_policy() {
    jq -r '.bindings[]?
            | select((.members // []) | any(. == "allUsers" or . == "allAuthenticatedUsers"))
            | .role' 2>/dev/null | paste -sd', ' -
}

# --- Cloud Functions -----------------------------------------------------------
scan_functions() {
    log_step "Scanning Cloud Functions..."
    mark_category_scanned "FUNCTIONS"

    local fns
    fns=$(gcloud functions list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -z "$fns" || "$fns" == "[]" ]]; then
        log_info "  → No functions detected."
        log_ok "Cloud Functions done."
        return 0
    fi

    while IFS=$'\t' read -r fname region ingress runtime sa envsecrets vpc; do
        [[ -z "$fname" ]] && continue
        log_info "  → Analyzing ${fname} (${region})"
        local roles
        roles=$(gcloud functions get-iam-policy "$fname" --region="$region" \
                    --project="$PROJECT_ID" --format=json 2>/dev/null | public_roles_from_policy)
        [[ -n "$roles" ]] && { add_finding "CRITICAL" "FUNCTIONS" "Publicly invokable function" "${fname} (${region})" "Granted to allUsers/allAuthenticatedUsers: ${roles}."; log_crit "    ${fname} is PUBLIC"; }
        [[ "$ingress" == "ALLOW_ALL" ]] && { add_finding "WARNING" "FUNCTIONS" "Open ingress (ALLOW_ALL)" "${fname} (${region})" "Accepts traffic from any source."; log_warn "    ${fname}: ALLOW_ALL"; }
        if [[ "$runtime" =~ ^(nodejs([468]|10|12|14)|python3[567]|go1(11|13|14|15)|ruby2[567]|php74|dotnet3|java11)$ ]]; then
            add_finding "WARNING" "FUNCTIONS" "Deprecated/EOL runtime" "${fname} (${region})" "Runtime '${runtime}' is EOL. Upgrade."
        fi
        [[ "$sa" == *-compute@developer.gserviceaccount.com || "$sa" == *@appspot.gserviceaccount.com ]] && { add_finding "WARNING" "FUNCTIONS" "Function uses default service account" "${fname} (${region})" "Assign a dedicated least-privilege SA."; log_warn "    ${fname}: default SA"; }
        [[ "$envsecrets" == "true" ]] && { add_finding "WARNING" "FUNCTIONS" "Possible secret in environment variable" "${fname} (${region})" "Store secrets in Secret Manager."; log_warn "    ${fname}: secret-like env var"; }
        [[ -z "$vpc" || "$vpc" == "None" || "$vpc" == "null" ]] && add_finding "INFO" "FUNCTIONS" "No VPC connector" "${fname} (${region})" "Egress not routed through VPC."
    done < <(jq -r '.[]
                | [ (.name | split("/") | last),
                    (.name | split("/") | .[3]),
                    ((.serviceConfig.ingressSettings // .ingressSettings // "unknown") | tostring),
                    (.buildConfig.runtime // .runtime // "unknown"),
                    (.serviceConfig.serviceAccountEmail // .serviceAccountEmail // "unknown"),
                    (((.serviceConfig.environmentVariables // .environmentVariables // {}) | keys
                        | any(test("(?i)(pass|secret|token|api[_-]?key|credential|private[_-]?key)"))) | tostring),
                    (.serviceConfig.vpcConnector // .vpcConnector // "None") ]
                | @tsv' <<< "$fns")

    log_ok "Cloud Functions done."
}

# --- Cloud Run -----------------------------------------------------------------
scan_run() {
    log_step "Scanning Cloud Run..."
    mark_category_scanned "RUN"

    local svcs
    svcs=$(gcloud run services list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -z "$svcs" || "$svcs" == "[]" ]]; then
        log_info "  → No Cloud Run services detected."
        log_ok "Cloud Run done."
        return 0
    fi

    while IFS=$'\t' read -r name region ingress sa envsecrets vpc; do
        [[ -z "$name" ]] && continue
        log_info "  → Analyzing ${name} (${region})"
        local roles
        roles=$(gcloud run services get-iam-policy "$name" --region="$region" \
                    --project="$PROJECT_ID" --format=json 2>/dev/null | public_roles_from_policy)
        [[ -n "$roles" ]] && { add_finding "CRITICAL" "RUN" "Publicly invokable service" "${name} (${region})" "Granted to allUsers/allAuthenticatedUsers: ${roles}."; log_crit "    ${name} is PUBLIC"; }
        [[ "$ingress" == "all" ]] && add_finding "INFO" "RUN" "Ingress = all" "${name} (${region})" "Accepts internet traffic."
        [[ -z "$sa" || "$sa" == "null" || "$sa" == *-compute@developer.gserviceaccount.com ]] && { add_finding "WARNING" "RUN" "Service uses default compute SA" "${name} (${region})" "Assign a least-privilege SA."; log_warn "    ${name}: default SA"; }
        [[ "$envsecrets" == "true" ]] && { add_finding "WARNING" "RUN" "Possible secret in environment variable" "${name} (${region})" "Use Secret Manager."; log_warn "    ${name}: secret-like env var"; }
        [[ -z "$vpc" || "$vpc" == "None" || "$vpc" == "null" ]] && add_finding "INFO" "RUN" "No VPC connector configured" "${name} (${region})" "Egress bypasses VPC controls."
    done < <(jq -r '.[]
                | [ .metadata.name,
                    (.metadata.labels["cloud.googleapis.com/location"] // "unknown"),
                    (.metadata.annotations["run.googleapis.com/ingress"] // "all"),
                    (.spec.template.spec.serviceAccountName // "null"),
                    (([.spec.template.spec.containers[]?.env[]?.name // empty]
                        | any(test("(?i)(pass|secret|token|api[_-]?key|credential|private[_-]?key)"))) | tostring),
                    (.spec.template.metadata.annotations["run.googleapis.com/vpc-access-connector"] // "None") ]
                | @tsv' <<< "$svcs")

    log_ok "Cloud Run done."
}

# --- Pub/Sub -------------------------------------------------------------------
scan_pubsub() {
    log_step "Scanning Pub/Sub..."
    mark_category_scanned "PUBSUB"

    local topics subs name short roles
    topics=$(gcloud pubsub topics list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -n "$topics" && "$topics" != "[]" ]]; then
        while IFS=$'\t' read -r name kms; do
            [[ -z "$name" ]] && continue
            short="${name##*/}"
            roles=$(gcloud pubsub topics get-iam-policy "$name" --project="$PROJECT_ID" --format=json 2>/dev/null | public_roles_from_policy)
            [[ -n "$roles" ]] && { add_finding "CRITICAL" "PUBSUB" "Topic with public access" "$short" "Roles: ${roles}."; log_crit "    topic ${short} PUBLIC"; }
            [[ -z "$kms" || "$kms" == "None" || "$kms" == "null" ]] && add_finding "INFO" "PUBSUB" "Topic without CMEK" "$short" "Uses Google-managed encryption."
        done < <(jq -r '.[] | [ .name, (.kmsKeyName // "None") ] | @tsv' <<< "$topics")
    fi

    subs=$(gcloud pubsub subscriptions list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -n "$subs" && "$subs" != "[]" ]]; then
        while IFS=$'\t' read -r name deadletter expiry; do
            [[ -z "$name" ]] && continue
            short="${name##*/}"
            roles=$(gcloud pubsub subscriptions get-iam-policy "$name" --project="$PROJECT_ID" --format=json 2>/dev/null | public_roles_from_policy)
            [[ -n "$roles" ]] && { add_finding "CRITICAL" "PUBSUB" "Subscription with public access" "$short" "Roles: ${roles}."; log_crit "    subscription ${short} PUBLIC"; }
            [[ "$deadletter" != "true" ]] && add_finding "INFO" "PUBSUB" "Subscription without dead-letter topic" "$short" "Undeliverable messages lost after retries."
        done < <(jq -r '.[] | [ .name, ((.deadLetterPolicy != null) | tostring), (.expirationPolicy.ttl // "never") ] | @tsv' <<< "$subs")
    fi

    log_ok "Pub/Sub done."
}

# --- Secret Manager ------------------------------------------------------------
scan_secrets() {
    log_step "Scanning Secret Manager..."
    mark_category_scanned "SECRETS"

    local secrets
    secrets=$(gcloud secrets list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -z "$secrets" || "$secrets" == "[]" ]]; then
        log_info "  → No secrets detected."
        log_ok "Secret Manager done."
        return 0
    fi

    local short roles
    while IFS=$'\t' read -r name rotation expiry cmek autorepl; do
        [[ -z "$name" ]] && continue
        short="${name##*/}"
        roles=$(gcloud secrets get-iam-policy "$short" --project="$PROJECT_ID" --format=json 2>/dev/null | public_roles_from_policy)
        [[ -n "$roles" ]] && { add_finding "CRITICAL" "SECRETS" "Secret with public access" "$short" "Roles: ${roles}. Revoke immediately."; log_crit "    secret ${short} PUBLIC"; }
        [[ "$rotation" == "none" ]] && add_finding "INFO" "SECRETS" "No rotation policy" "$short" "Long-lived secrets increase blast radius."
        [[ "$cmek" == "google-managed" ]] && add_finding "INFO" "SECRETS" "Uses Google-managed encryption" "$short" "Consider CMEK for regulated data."
    done < <(jq -r '.[]
                | [ .name,
                    (if (.rotation != null) then "set" else "none" end),
                    (.expireTime // "none"),
                    (if ((.. | .customerManagedEncryption? // empty) | length > 0) or ((.. | .kmsKeyName? // empty) | length > 0) then "cmek" else "google-managed" end),
                    ((.replication.automatic != null) | tostring) ]
                | @tsv' <<< "$secrets")

    log_ok "Secret Manager done."
}

# --- Artifact Registry ---------------------------------------------------------
scan_artifacts() {
    log_step "Scanning Artifact Registry..."
    mark_category_scanned "ARTIFACTS"

    local repos
    repos=$(gcloud artifacts repositories list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -z "$repos" || "$repos" == "[]" ]]; then
        log_info "  → No repositories detected."
        log_ok "Artifact Registry done."
        return 0
    fi

    while IFS=$'\t' read -r short location fmt cmek cleanup; do
        [[ -z "$short" ]] && continue
        local roles
        roles=$(gcloud artifacts repositories get-iam-policy "$short" --location="$location" --project="$PROJECT_ID" --format=json 2>/dev/null | public_roles_from_policy)
        [[ -n "$roles" ]] && { add_finding "CRITICAL" "ARTIFACTS" "Repository with public access" "${short} (${location})" "Roles: ${roles}."; log_crit "    repo ${short} PUBLIC"; }
        [[ -z "$cmek" || "$cmek" == "None" || "$cmek" == "null" ]] && add_finding "INFO" "ARTIFACTS" "Repository without CMEK" "${short} (${location})" "Uses Google-managed encryption."
        [[ "$cleanup" == "0" ]] && add_finding "INFO" "ARTIFACTS" "No cleanup policies" "${short} (${location})" "Stale/vulnerable image versions accumulate."
    done < <(jq -r '.[]
                | [ (.name | split("/") | last),
                    (.name | split("/") | .[3]),
                    (.format // "UNKNOWN"),
                    (.kmsKeyName // "None"),
                    ((.cleanupPolicies // {}) | length | tostring) ]
                | @tsv' <<< "$repos")

    log_ok "Artifact Registry done."
}

# --- Cloud KMS -----------------------------------------------------------------
scan_kms() {
    log_step "Scanning Cloud KMS (key rings + keys)..."
    mark_category_scanned "KMS"

    local locations loc rings ring keys
    locations=$(gcloud kms locations list --project="$PROJECT_ID" --format="value(locationId)" 2>/dev/null)
    if [[ -z "$locations" ]]; then
        log_info "  → No KMS locations available."
        log_ok "Cloud KMS done."
        return 0
    fi

    while IFS= read -r loc; do
        [[ -z "$loc" ]] && continue
        rings=$(gcloud kms keyrings list --location="$loc" --project="$PROJECT_ID" --format="value(name)" 2>/dev/null)
        [[ -z "$rings" ]] && continue
        while IFS= read -r ring; do
            [[ -z "$ring" ]] && continue
            local ring_short="${ring##*/}"
            keys=$(gcloud kms keys list --keyring="$ring" --location="$loc" --project="$PROJECT_ID" --format=json 2>/dev/null)
            [[ -z "$keys" || "$keys" == "[]" ]] && continue
            while IFS=$'\t' read -r kname purpose rotation prot; do
                [[ -z "$kname" ]] && continue
                local kshort="${kname##*/}" res="${loc}/${ring_short}/${kname##*/}"
                if [[ "$purpose" == "ENCRYPT_DECRYPT" ]]; then
                    if [[ "$rotation" == "none" ]]; then
                        add_finding "WARNING" "KMS" "Key without rotation policy" "$res" "Set rotation ≤ 90 days (CIS 1.9)."
                        log_warn "    KMS ${res}: no rotation"
                    else
                        local secs="${rotation%s}"
                        if [[ "$secs" =~ ^[0-9]+$ ]] && (( secs > 7776000 )); then
                            add_finding "WARNING" "KMS" "Key rotation period > 90 days" "$res" "Rotation ${rotation} > 90 days (CIS 1.9)."
                        fi
                    fi
                fi
                local kroles
                kroles=$(gcloud kms keys get-iam-policy "$kshort" --keyring="$ring" --location="$loc" --project="$PROJECT_ID" --format=json 2>/dev/null | public_roles_from_policy)
                [[ -n "$kroles" ]] && { add_finding "CRITICAL" "KMS" "KMS key publicly accessible" "$res" "Roles: ${kroles} (CIS 1.10)."; log_crit "    KMS ${res} PUBLIC"; }
            done < <(jq -r '.[] | [ .name, (.purpose // "UNKNOWN"), (.rotationPeriod // "none"), (.versionTemplate.protectionLevel // "SOFTWARE") ] | @tsv' <<< "$keys")
        done <<< "$rings"
    done <<< "$locations"

    log_ok "Cloud KMS done."
}

# --- BigQuery ------------------------------------------------------------------
scan_bigquery() {
    log_step "Scanning BigQuery (datasets)..."
    mark_category_scanned "BIGQUERY"

    if ! command -v bq >/dev/null 2>&1; then
        add_finding "INFO" "BIGQUERY" "BigQuery CLI (bq) not available" "project/${PROJECT_ID}" "'bq' not installed; dataset ACLs/CMEK not inspected."
        log_warn "  → 'bq' not found; skipping BigQuery deep scan."
        return 0
    fi

    local datasets ds
    datasets=$(bq ls --format=json --project_id="$PROJECT_ID" 2>/dev/null)
    if [[ -z "$datasets" || "$datasets" == "[]" ]]; then
        log_info "  → No datasets detected."
        log_ok "BigQuery done."
        return 0
    fi

    while IFS= read -r ds; do
        [[ -z "$ds" ]] && continue
        local info public cmek
        info=$(bq show --format=prettyjson "${PROJECT_ID}:${ds}" 2>/dev/null)
        [[ -z "$info" ]] && continue
        public=$(jq -r '[.access[]? | select((.specialGroup=="allAuthenticatedUsers") or (.iamMember=="allUsers") or (.iamMember=="allAuthenticatedUsers"))] | length' <<< "$info" 2>/dev/null)
        [[ "$public" =~ ^[0-9]+$ ]] && (( public > 0 )) && { add_finding "CRITICAL" "BIGQUERY" "Dataset shared publicly" "$ds" "Remove public principals (CIS 7.1)."; log_crit "    dataset ${ds} PUBLIC"; }
        cmek=$(jq -r '(.defaultEncryptionConfiguration.kmsKeyName // "None")' <<< "$info" 2>/dev/null)
        [[ -z "$cmek" || "$cmek" == "None" || "$cmek" == "null" ]] && add_finding "INFO" "BIGQUERY" "Dataset without default CMEK" "$ds" "Uses Google-managed encryption (CIS 7.2)."
    done < <(jq -r '.[] | .datasetReference.datasetId // .id | sub("^.*:";"")' <<< "$datasets" 2>/dev/null)

    log_ok "BigQuery done."
}

# --- Cloud DNS -----------------------------------------------------------------
scan_dns() {
    log_step "Scanning Cloud DNS (managed zones)..."
    mark_category_scanned "DNS"

    local zones
    zones=$(gcloud dns managed-zones list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -z "$zones" || "$zones" == "[]" ]]; then
        log_info "  → No managed zones detected."
        log_ok "Cloud DNS done."
        return 0
    fi

    while IFS=$'\t' read -r zname visibility dnssec; do
        [[ -z "$zname" ]] && continue
        if [[ "$visibility" == "public" && "$dnssec" != "on" ]]; then
            add_finding "WARNING" "DNS" "DNSSEC not enabled on public zone" \
                "$zname" "DNSSEC state '${dnssec}'. Enable to prevent DNS spoofing (CIS 3.3)."
            log_warn "    zone ${zname}: DNSSEC ${dnssec}"
        fi
    done < <(jq -r '.[] | [ .name, (.visibility // "public"), (.dnssecConfig.state // "off") ] | @tsv' <<< "$zones")

    log_ok "Cloud DNS done."
}

# --- API Keys ------------------------------------------------------------------
scan_apikeys() {
    log_step "Scanning API Keys..."
    mark_category_scanned "APIKEYS"

    local keys
    keys=$(gcloud services api-keys list --project="$PROJECT_ID" --format=json 2>/dev/null)
    if [[ -z "$keys" || "$keys" == "[]" ]]; then
        log_info "  → No API keys detected."
        log_ok "API Keys done."
        return 0
    fi

    while IFS=$'\t' read -r display has_app_restr has_api_restr; do
        [[ -z "$display" ]] && continue
        if [[ "$has_app_restr" != "true" && "$has_api_restr" != "true" ]]; then
            add_finding "CRITICAL" "APIKEYS" "Unrestricted API key" "$display" "No app or API restrictions (CIS 1.12/1.13)."
            log_crit "    API key ${display} unrestricted"
        elif [[ "$has_api_restr" != "true" ]]; then
            add_finding "WARNING" "APIKEYS" "API key without API target restriction" "$display" "Restricts callers but can invoke any API (CIS 1.13)."
            log_warn "    API key ${display}: no API restriction"
        fi
    done < <(jq -r '.[]
                | [ (.displayName // (.name | split("/") | last)),
                    (((.restrictions.browserKeyRestrictions // .restrictions.serverKeyRestrictions
                        // .restrictions.androidKeyRestrictions // .restrictions.iosKeyRestrictions) != null) | tostring),
                    (((.restrictions.apiTargets // []) | length > 0) | tostring) ]
                | @tsv' <<< "$keys")

    log_ok "API Keys done."
}

# --- Dispatcher ----------------------------------------------------------------
run_scan_by_api() {
    local api="$1"
    local fn="${API_TO_SCANNER[$api]:-}"
    if [[ -z "$fn" ]]; then
        log_warn "No scanner defined for ${api}."
        return 1
    fi
    if ! is_service_enabled "$api"; then
        log_warn "${api} is not active; skipping."
        return 0
    fi
    "$fn"
}

# ------------------------------------------------------------------------------
#  MENU ACTIONS
# ------------------------------------------------------------------------------
scan_all() {
    reset_state
    log_step "Starting FULL scan of active services..."
    hr
    local api
    for api in "${DETECTED_SCANNABLE[@]}"; do
        run_scan_by_api "$api"; hr
    done
    finish_scan
}

scan_on_demand() {
    if (( ${#DETECTED_SCANNABLE[@]} == 0 )); then
        log_warn "No active services to choose from."
        return 0
    fi

    printf '\n%sSelect the services to scan:%s\n' "$C_BOLD" "$C_RESET"
    local i api
    for i in "${!DETECTED_SCANNABLE[@]}"; do
        api="${DETECTED_SCANNABLE[$i]}"
        printf '   %s%2d)%s %s\n' "$C_CYN" "$((i + 1))" "$C_RESET" "${API_TO_LABEL[$api]}"
    done
    printf '   %s a)%s All\n' "$C_CYN" "$C_RESET"
    printf '   %s q)%s Cancel\n\n' "$C_CYN" "$C_RESET"

    local input
    read -rp "$(printf 'Numbers separated by spaces (e.g. 1 3): ')" input
    [[ -z "$input" || "$input" == "q" ]] && { log_info "Cancelled."; return 0; }

    reset_state; hr

    if [[ "$input" == "a" || "$input" == "all" ]]; then
        for api in "${DETECTED_SCANNABLE[@]}"; do run_scan_by_api "$api"; hr; done
    else
        local sel
        local -A seen=()
        for sel in $input; do
            if ! [[ "$sel" =~ ^[0-9]+$ ]]; then log_warn "Ignored: '${sel}'"; continue; fi
            local idx=$((sel - 1))
            if (( idx < 0 || idx >= ${#DETECTED_SCANNABLE[@]} )); then log_warn "Out of range: ${sel}"; continue; fi
            [[ -n "${seen[$idx]:-}" ]] && continue
            seen[$idx]=1
            run_scan_by_api "${DETECTED_SCANNABLE[$idx]}"; hr
        done
    fi

    (( ${#SCANNED_CATEGORIES[@]} == 0 )) && { log_warn "No valid scan executed."; return 0; }
    finish_scan
}

finish_scan() {
    hr
    printf '%sScan summary:%s  ' "$C_BOLD" "$C_RESET"
    printf '%s%d CRITICAL%s · %s%d WARNING%s · %s%d INFO%s\n' \
        "$C_RED" "$CRITICAL_COUNT" "$C_RESET" \
        "$C_YEL" "$WARNING_COUNT" "$C_RESET" \
        "$C_BLU" "$INFO_COUNT" "$C_RESET"
    generate_html_report; hr
}

# ------------------------------------------------------------------------------
#  PHASE 4: HTML REPORT
# ------------------------------------------------------------------------------
count_findings() {
    local cat="$1" sev="$2" f n=0 fsev fcat
    for f in "${FINDINGS[@]:-}"; do
        [[ -z "$f" ]] && continue
        IFS="$DELIM" read -r fsev fcat _ _ _ <<< "$f"
        [[ "$fcat" == "$cat" ]] || continue
        [[ -z "$sev" || "$fsev" == "$sev" ]] && n=$((n + 1))
    done
    printf '%d' "$n"
}

emit_category_rows() {
    local cat="$1" sev f fsev fcat ftitle fres fdetail
    for sev in CRITICAL WARNING INFO; do
        for f in "${FINDINGS[@]:-}"; do
            [[ -z "$f" ]] && continue
            IFS="$DELIM" read -r fsev fcat ftitle fres fdetail <<< "$f"
            [[ "$fcat" == "$cat" && "$fsev" == "$sev" ]] || continue
            printf '        <tr>\n'
            printf '          <td><span class="badge %s">%s</span></td>\n' \
                "$(tr '[:upper:]' '[:lower:]' <<< "$sev")" "$sev"
            printf '          <td class="ttl">%s</td>\n' "$(html_escape "$ftitle")"
            printf '          <td class="res"><code>%s</code></td>\n' "$(html_escape "$fres")"
            printf '          <td class="det">%s</td>\n' "$(html_escape "$fdetail")"
            printf '        </tr>\n'
        done
    done
}

generate_html_report() {
    log_step "Phase 4 · Generating HTML report..."
    stage_icons

    local ts total posture posture_class
    ts=$(date '+%Y-%m-%d %H:%M:%S %Z')
    total=$(( CRITICAL_COUNT + WARNING_COUNT + INFO_COUNT ))
    if (( CRITICAL_COUNT > 0 )); then posture="HIGH RISK";   posture_class="crit"
    elif (( WARNING_COUNT > 0 )); then posture="MEDIUM RISK"; posture_class="warn"
    else posture="LOW RISK"; posture_class="ok"; fi

    cat > "$REPORT_FILE" <<'HTML_HEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GCP Security Assessment</title>
<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --panel-2:#1c2230; --border:#2a3140;
    --txt:#e6edf3; --muted:#8b949e; --accent:#3b82f6;
    --crit:#ef4444; --warn:#f59e0b; --info:#3b82f6; --ok:#22c55e;
    --shadow:0 8px 24px rgba(0,0,0,.35);
  }
  body.light{
    --bg:#f3f5f8; --panel:#ffffff; --panel-2:#f0f3f7; --border:#dfe4ea;
    --txt:#1b232e; --muted:#5c6773; --shadow:0 8px 24px rgba(20,30,50,.08);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
       font-family:"Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;
       transition:background .2s,color .2s}
  .wrap{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
  header.top{display:flex;align-items:center;justify-content:space-between;
             gap:16px;flex-wrap:wrap;margin-bottom:22px}
  .brand{display:flex;align-items:center;gap:14px}
  .logo{width:44px;height:44px;border-radius:11px;
        background:linear-gradient(135deg,#3b82f6,#8b5cf6);
        display:flex;align-items:center;justify-content:center;font-size:22px}
  .brand h1{font-size:20px;margin:0;letter-spacing:.3px}
  .brand p{margin:2px 0 0;color:var(--muted);font-size:13px}
  .toggle{cursor:pointer;border:1px solid var(--border);background:var(--panel);
          color:var(--txt);border-radius:9px;padding:9px 14px;font-size:13px}
  .toggle:hover{border-color:var(--accent)}
  .meta{display:flex;gap:20px;flex-wrap:wrap;color:var(--muted);font-size:13px;
        margin-bottom:20px}
  .meta b{color:var(--txt)}
  .posture{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;
           border-radius:999px;font-weight:600;font-size:13px}
  .posture.crit{background:rgba(239,68,68,.15);color:var(--crit)}
  .posture.warn{background:rgba(245,158,11,.15);color:var(--warn)}
  .posture.ok{background:rgba(34,197,94,.15);color:var(--ok)}
  .tabs{display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--border);
        margin-bottom:22px}
  .tab{cursor:pointer;padding:11px 16px;border:none;background:none;color:var(--muted);
       font-size:14px;border-bottom:2px solid transparent;transition:.15s;font-weight:500}
  .tab:hover{color:var(--txt)}
  .tab.active{color:var(--accent);border-bottom-color:var(--accent)}
  .tab .count{display:inline-block;min-width:18px;padding:0 6px;margin-left:6px;
              border-radius:999px;font-size:11px;background:var(--panel-2);color:var(--muted)}
  .panel{display:none;animation:fade .25s ease}
  .panel.active{display:block}
  @keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
         gap:16px;margin-bottom:26px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:14px;
        padding:18px 20px;box-shadow:var(--shadow)}
  .card .k{color:var(--muted);font-size:13px;margin-bottom:8px}
  .card .v{font-size:32px;font-weight:700;line-height:1}
  .card.c-crit .v{color:var(--crit)} .card.c-warn .v{color:var(--warn)}
  .card.c-info .v{color:var(--info)} .card.c-total .v{color:var(--txt)}
  .chart{background:var(--panel);border:1px solid var(--border);border-radius:14px;
         padding:20px 22px;box-shadow:var(--shadow);margin-bottom:26px}
  .chart h3{margin:0 0 16px;font-size:15px}
  .bar-row{display:flex;align-items:center;gap:12px;margin:10px 0}
  .bar-row .lbl{width:90px;font-size:13px;color:var(--muted)}
  .bar-track{flex:1;background:var(--panel-2);border-radius:8px;height:22px;overflow:hidden}
  .bar-fill{height:100%;border-radius:8px;transition:width .6s ease;min-width:2px}
  .bar-fill.crit{background:var(--crit)} .bar-fill.warn{background:var(--warn)}
  .bar-fill.info{background:var(--info)}
  .bar-row .num{width:40px;text-align:right;font-weight:600;font-size:14px}
  .svc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
  .svc{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px}
  .svc .h{display:flex;align-items:center;gap:9px;font-weight:600;margin-bottom:12px}
  .svc .h .ico{font-size:18px}
  .ico-svg{display:inline-block;width:1.15em;height:1.15em;
           vertical-align:-.18em;object-fit:contain;flex:none}
  .logo .ico-svg{width:24px;height:24px;filter:brightness(0) invert(1)}
  h2 .ico-svg{width:1.1em;height:1.1em}
  .svc .pips{display:flex;gap:14px;font-size:13px}
  .svc .pip{display:flex;align-items:center;gap:5px;color:var(--muted)}
  .dot{width:9px;height:9px;border-radius:50%}
  .dot.crit{background:var(--crit)} .dot.warn{background:var(--warn)} .dot.info{background:var(--info)}
  table{width:100%;border-collapse:collapse;background:var(--panel);
        border:1px solid var(--border);border-radius:12px;overflow:hidden}
  thead th{text-align:left;padding:12px 14px;font-size:12px;letter-spacing:.5px;
           text-transform:uppercase;color:var(--muted);background:var(--panel-2);
           border-bottom:1px solid var(--border)}
  tbody td{padding:13px 14px;border-bottom:1px solid var(--border);
           font-size:14px;vertical-align:top}
  tbody tr:last-child td{border-bottom:none}
  tbody tr:hover{background:var(--panel-2)}
  td.ttl{font-weight:600;white-space:nowrap}
  td.res code{background:var(--panel-2);padding:2px 7px;border-radius:6px;
              font-size:12.5px;word-break:break-all}
  td.det{color:var(--muted);line-height:1.5}
  .badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;
         font-weight:700;letter-spacing:.4px}
  .badge.critical{background:rgba(239,68,68,.16);color:var(--crit)}
  .badge.warning{background:rgba(245,158,11,.16);color:var(--warn)}
  .badge.info{background:rgba(59,130,246,.16);color:var(--info)}
  .empty{background:var(--panel);border:1px dashed var(--border);border-radius:12px;
         padding:40px;text-align:center;color:var(--muted)}
  .empty .big{font-size:40px;margin-bottom:8px}
  .empty .ico-svg{width:44px;height:44px}
  footer{margin-top:36px;text-align:center;color:var(--muted);font-size:12px}
</style>
</head>
<body>
<div class="wrap">
HTML_HEAD

    {
        printf '<header class="top">\n'
        printf '  <div class="brand"><div class="logo">%s</div>\n' "$(html_icon shield)"
        printf '    <div><h1>GCP Security Assessment</h1>\n'
        printf '      <p>Posture evaluation · project <b>%s</b></p></div>\n' "$(html_escape "$PROJECT_ID")"
        printf '  </div>\n'
        printf '  <button class="toggle" onclick="toggleTheme()">%s Light/dark theme</button>\n' "$(html_icon theme "🌗")"
        printf '</header>\n'
        printf '<div class="meta">\n'
        printf '  <span>Generated: <b>%s</b></span>\n' "$ts"
        printf '  <span>Total findings: <b>%d</b></span>\n' "$total"
        printf '  <span class="posture %s">Posture: %s</span>\n' "$posture_class" "$posture"
        printf '</div>\n'

        printf '<div class="tabs">\n'
        printf '  <button class="tab active" onclick="showTab(event,'"'"'summary'"'"')">%s Executive Summary</button>\n' "$(html_icon summary)"
        printf '  <button class="tab" onclick="showTab(event,'"'"'inventory'"'"')">%s Service Inventory<span class="count">%d</span></button>\n' "$(html_icon inventory)" "${#ENABLED_SERVICES[@]}"
        local cat
        for cat in "${CAT_ORDER[@]}"; do
            local scanned=0 c
            for c in "${SCANNED_CATEGORIES[@]:-}"; do [[ "$c" == "$cat" ]] && scanned=1; done
            (( scanned )) || continue
            local n; n=$(count_findings "$cat" "")
            printf '  <button class="tab" onclick="showTab(event,'"'"'%s'"'"')">%s %s<span class="count">%d</span></button>\n' \
                "$cat" "$(html_icon "${cat,,}")" "${CAT_TITLE[$cat]}" "$n"
        done
        printf '</div>\n'
    } >> "$REPORT_FILE"

    local max=$CRITICAL_COUNT
    (( WARNING_COUNT > max )) && max=$WARNING_COUNT
    (( INFO_COUNT > max )) && max=$INFO_COUNT
    (( max == 0 )) && max=1
    local pct_c=$(( CRITICAL_COUNT * 100 / max ))
    local pct_w=$(( WARNING_COUNT * 100 / max ))
    local pct_i=$(( INFO_COUNT * 100 / max ))

    {
        printf '<div id="summary" class="panel active">\n'
        printf '  <div class="cards">\n'
        printf '    <div class="card c-crit"><div class="k">Critical</div><div class="v">%d</div></div>\n' "$CRITICAL_COUNT"
        printf '    <div class="card c-warn"><div class="k">Warnings</div><div class="v">%d</div></div>\n' "$WARNING_COUNT"
        printf '    <div class="card c-info"><div class="k">Informational</div><div class="v">%d</div></div>\n' "$INFO_COUNT"
        printf '    <div class="card c-total"><div class="k">Total</div><div class="v">%d</div></div>\n' "$total"
        printf '  </div>\n'
        printf '  <div class="chart"><h3>Distribution by severity</h3>\n'
        printf '    <div class="bar-row"><span class="lbl">Critical</span><div class="bar-track"><div class="bar-fill crit" style="width:%d%%"></div></div><span class="num">%d</span></div>\n' "$pct_c" "$CRITICAL_COUNT"
        printf '    <div class="bar-row"><span class="lbl">Warning</span><div class="bar-track"><div class="bar-fill warn" style="width:%d%%"></div></div><span class="num">%d</span></div>\n' "$pct_w" "$WARNING_COUNT"
        printf '    <div class="bar-row"><span class="lbl">Info</span><div class="bar-track"><div class="bar-fill info" style="width:%d%%"></div></div><span class="num">%d</span></div>\n' "$pct_i" "$INFO_COUNT"
        printf '  </div>\n'
        printf '  <h3 style="margin:0 0 14px;font-size:15px">Breakdown by service</h3>\n'
        printf '  <div class="svc-grid">\n'
        local cat scanned c cc cw ci
        for cat in "${CAT_ORDER[@]}"; do
            scanned=0
            for c in "${SCANNED_CATEGORIES[@]:-}"; do [[ "$c" == "$cat" ]] && scanned=1; done
            (( scanned )) || continue
            cc=$(count_findings "$cat" "CRITICAL")
            cw=$(count_findings "$cat" "WARNING")
            ci=$(count_findings "$cat" "INFO")
            printf '    <div class="svc"><div class="h">%s%s</div>\n' "$(html_icon "${cat,,}")" "${CAT_TITLE[$cat]}"
            printf '      <div class="pips">\n'
            printf '        <span class="pip"><span class="dot crit"></span>%d</span>\n' "$cc"
            printf '        <span class="pip"><span class="dot warn"></span>%d</span>\n' "$cw"
            printf '        <span class="pip"><span class="dot info"></span>%d</span>\n' "$ci"
            printf '      </div></div>\n'
        done
        printf '  </div>\n</div>\n'
    } >> "$REPORT_FILE"

    {
        local cat scanned c n
        for cat in "${CAT_ORDER[@]}"; do
            scanned=0
            for c in "${SCANNED_CATEGORIES[@]:-}"; do [[ "$c" == "$cat" ]] && scanned=1; done
            (( scanned )) || continue
            n=$(count_findings "$cat" "")
            printf '<div id="%s" class="panel">\n' "$cat"
            printf '  <h2 style="font-size:18px;margin:0 0 16px">%s %s</h2>\n' "$(html_icon "${cat,,}")" "${CAT_TITLE[$cat]}"
            if (( n == 0 )); then
                printf '  <div class="empty"><div class="big">%s</div>No security findings for this service.</div>\n' "$(html_icon ok)"
            else
                printf '  <table><thead><tr>\n'
                printf '    <th>Severity</th><th>Finding</th><th>Resource</th><th>Detail</th>\n'
                printf '  </tr></thead><tbody>\n'
                emit_category_rows "$cat"
                printf '  </tbody></table>\n'
            fi
            printf '</div>\n'
        done
    } >> "$REPORT_FILE"

    {
        printf '<div id="inventory" class="panel">\n'
        printf '  <h2 style="font-size:18px;margin:0 0 6px">%s Service Inventory</h2>\n' "$(html_icon inventory)"
        printf '  <p style="color:var(--muted);margin:0 0 16px;font-size:14px">All enabled APIs detected as active in the project.</p>\n'
        printf '  <table><thead><tr><th>Service (API)</th><th>Coverage</th></tr></thead><tbody>\n'
        local api scanner
        for api in "${ENABLED_SERVICES[@]:-}"; do
            [[ -z "$api" ]] && continue
            scanner="${API_TO_SCANNER[$api]:-}"
            [[ -z "$scanner" ]] && continue
            printf '    <tr><td class="res"><code>%s</code></td><td><span class="badge info">DEEP SCAN</span></td></tr>\n' "$(html_escape "$api")"
        done
        for api in "${UNSCANNED_SERVICES[@]:-}"; do
            [[ -z "$api" ]] && continue
            printf '    <tr><td class="res"><code>%s</code></td><td><span class="badge warning">INVENTORY ONLY</span></td></tr>\n' "$(html_escape "$api")"
        done
        printf '  </tbody></table>\n</div>\n'
    } >> "$REPORT_FILE"

    cat >> "$REPORT_FILE" <<'HTML_TAIL'
<footer>
  Report generated by GCP Security Assessment v2.1.0 · Project-level scan (no Cloud Asset Inventory, no organization-level permissions).
</footer>
</div>
<script>
  function showTab(ev, id){
    document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
    document.querySelectorAll('.tab').forEach(function(t){ t.classList.remove('active'); });
    document.getElementById(id).classList.add('active');
    ev.currentTarget.classList.add('active');
  }
  function toggleTheme(){ document.body.classList.toggle('light'); }
</script>
</body>
</html>
HTML_TAIL

    log_ok "Report generated: ${C_BOLD}${REPORT_FILE}${C_RESET}"
    log_info "The report loads its icons from the icons/ folder - keep it next to the HTML when moving or sharing it."
    printf '    %sOpen the file in your browser:%s file://%s/%s\n' \
        "$C_DIM" "$C_RESET" "$(pwd)" "$REPORT_FILE"
    zip_report
}

# ------------------------------------------------------------------------------
#  MAIN MENU (PHASE 2)
# ------------------------------------------------------------------------------
main_menu() {
    local opt
    while true; do
        printf '\n%s%s══ MAIN MENU ══%s\n' "$C_BOLD" "$C_CYN" "$C_RESET"
        PS3="$(printf '%sChoose an option: %s' "$C_YEL" "$C_RESET")"
        select opt in \
            "Scan ALL active services" \
            "Scan services ON-DEMAND" \
            "Exit"; do
            case "$REPLY" in
                1) scan_all;       break ;;
                2) scan_on_demand; break ;;
                3) log_info "Exiting. See you soon!"; exit 0 ;;
                *) log_warn "Invalid option. Try again."; break ;;
            esac
        done
    done
}

# ------------------------------------------------------------------------------
#  ENTRY POINT
# ------------------------------------------------------------------------------
main() {
    local project="" a
    for a in "$@"; do
        case "$a" in
            --zip) ZIP_REPORT=true ;;
            --*)   printf 'Unknown option: %s\nUsage: %s [--zip] [PROJECT_ID]\n' "$a" "$0" >&2; exit 1 ;;
            *)     project="$a" ;;
        esac
    done

    print_banner
    check_dependencies
    resolve_project "$project"
    discover_services

    if (( ${#DETECTED_SCANNABLE[@]} == 0 )); then
        log_warn "No supported services are active. Nothing to scan."
        exit 0
    fi

    main_menu
}

main "$@"
