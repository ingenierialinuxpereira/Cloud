#!/usr/bin/env bash
#
# ==============================================================================
#  AWS Security Assessment  ·  Security posture evaluation for AWS
# ------------------------------------------------------------------------------
#  Author  : Francisco Gutierrez
#  Requires: AWS CLI v2 + jq   (read-only; no changes are ever made)
#  Scope   : ACCOUNT-level scan using the current credentials. Global services
#            (IAM, S3, Route 53, CloudTrail) are scanned once; regional services
#            are scanned in the selected region (or all regions if requested).
#
#  Deep scanners (v1.0):
#    IAM · S3 · EC2 · VPC/Security Groups · RDS · EKS · Lambda · ECR
#    Secrets Manager · SNS · SQS · KMS · CloudTrail · GuardDuty · Config · Route 53
#  Checks are aligned where possible with the CIS AWS Foundations Benchmark.
#
#  Usage:
#     ./aws_security_assessment_en.sh [--zip] [REGION]
#     ./aws_security_assessment_en.sh --zip                     # zip report + icons/
#     AWS_PROFILE=prod ./aws_security_assessment_en.sh us-east-1
#     AWS_SCAN_ALL_REGIONS=1 ./aws_security_assessment_en.sh   # regional scans in every region
#
#  Flags:
#     --zip   After generating the HTML report, package it together with a
#             copy of the icons/ folder into <report>.zip so the report
#             carries its images anywhere it is downloaded or shared.
#
#  Phases:
#     1) Context discovery (account, region(s), reachable services)
#     2) Interactive menu (all / on-demand / exit)
#     3) Per-service scanning logic
#     4) Self-contained HTML report with tabs
# ==============================================================================

set -uo pipefail   # -e intentionally omitted: aws may fail and we handle it

# ------------------------------------------------------------------------------
#  CONSTANTS AND GLOBAL STATE
# ------------------------------------------------------------------------------
readonly SCRIPT_NAME="AWS Security Assessment"
readonly SCRIPT_VERSION="1.0.0"
readonly DELIM=$'\037'            # Unit Separator: safe delimiter for findings
readonly KEY_WARN_DAYS=90         # access keys > 90 days  -> WARNING
readonly KEY_CRIT_DAYS=365        # access keys > 365 days -> CRITICAL
readonly INACTIVE_DAYS=90         # credentials unused > 90 days -> WARNING

ACCOUNT_ID=""
PRIMARY_REGION=""
SCAN_CONTEXT=""                   # human-readable context shown in the report
REPORT_FILE=""
ZIP_REPORT=false                  # --zip: package report + icons/ into a portable zip
declare -a SCAN_REGIONS=()        # regions used by regional scanners

# Icons/emojis folder (next to the script; overridable via the ICONS_DIR env
# var). The HTML report does NOT embed the icons: it references them with
# <img src="icons/<name>.<ext>"> tags. Supported formats: svg png jpg jpeg
# gif webp. A copy of the folder is placed next to the report automatically,
# and it must stay next to the HTML file when the report is moved or shared.
ICONS_DIR="${ICONS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/icons}"

# Findings: each element = "SEV<US>CAT<US>TITLE<US>RESOURCE<US>DETAIL"
declare -a FINDINGS=()
declare -a ENABLED_SERVICES=()      # all services we know how to scan (for inventory)
declare -a DETECTED_SCANNABLE=()    # reachable services this run will scan
declare -a SCANNED_CATEGORIES=()    # categories actually executed (for the tabs)
declare -a UNSCANNED_SERVICES=()    # reachable but not deep-scanned (denied/opt-out)

CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0

# Fixed order of services with a deep scanner.
readonly KNOWN_SCANNABLE_ORDER=(
    "iam" "s3" "ec2" "vpc" "rds" "eks" "lambda" "ecr"
    "secrets" "sns" "sqs" "kms" "cloudtrail" "guardduty" "config" "route53"
)

# service -> internal category
declare -A API_TO_CATEGORY=(
    ["iam"]="IAM"          ["s3"]="S3"            ["ec2"]="EC2"        ["vpc"]="VPC"
    ["rds"]="RDS"          ["eks"]="EKS"          ["lambda"]="LAMBDA"  ["ecr"]="ECR"
    ["secrets"]="SECRETS"  ["sns"]="SNS"          ["sqs"]="SQS"        ["kms"]="KMS"
    ["cloudtrail"]="CLOUDTRAIL" ["guardduty"]="GUARDDUTY" ["config"]="CONFIG" ["route53"]="ROUTE53"
)

# service -> scan function
declare -A API_TO_SCANNER=(
    ["iam"]="scan_iam"          ["s3"]="scan_s3"            ["ec2"]="scan_ec2"      ["vpc"]="scan_vpc"
    ["rds"]="scan_rds"          ["eks"]="scan_eks"          ["lambda"]="scan_lambda" ["ecr"]="scan_ecr"
    ["secrets"]="scan_secrets"  ["sns"]="scan_sns"          ["sqs"]="scan_sqs"      ["kms"]="scan_kms"
    ["cloudtrail"]="scan_cloudtrail" ["guardduty"]="scan_guardduty" ["config"]="scan_config" ["route53"]="scan_route53"
)

# service -> human-readable label (menus/console)
declare -A API_TO_LABEL=(
    ["iam"]="IAM · users, keys, policies"     ["s3"]="S3 · buckets"
    ["ec2"]="EC2 · instances, EBS"            ["vpc"]="VPC · security groups, flow logs"
    ["rds"]="RDS · databases"                 ["eks"]="EKS · Kubernetes clusters"
    ["lambda"]="Lambda · functions"           ["ecr"]="ECR · container registries"
    ["secrets"]="Secrets Manager"             ["sns"]="SNS · topics"
    ["sqs"]="SQS · queues"                    ["kms"]="KMS · keys"
    ["cloudtrail"]="CloudTrail · audit logging" ["guardduty"]="GuardDuty · threat detection"
    ["config"]="AWS Config · recording"       ["route53"]="Route 53 · DNS"
)

# Category metadata for the report (order + title). Icons: icons/<lowercase>.svg
readonly CAT_ORDER=(IAM S3 EC2 VPC RDS EKS LAMBDA ECR SECRETS SNS SQS KMS CLOUDTRAIL GUARDDUTY CONFIG ROUTE53)
declare -A CAT_TITLE=(
    [IAM]="IAM"                [S3]="S3"                  [EC2]="EC2 / EBS"        [VPC]="VPC / Sec. Groups"
    [RDS]="RDS"                [EKS]="EKS"                [LAMBDA]="Lambda"        [ECR]="ECR"
    [SECRETS]="Secrets Mgr"    [SNS]="SNS"                [SQS]="SQS"              [KMS]="KMS"
    [CLOUDTRAIL]="CloudTrail"  [GUARDDUTY]="GuardDuty"    [CONFIG]="AWS Config"    [ROUTE53]="Route 53"
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
    printf '%s' "$C_YEL$C_BOLD"
    cat <<'BANNER'
    _        _____   ____                       _ _
   / \      / / / \ / ___|  ___  ___ _   _ _ __(_) |_ _   _
  / _ \    / /|  \/ \___ \ / _ \/ __| | | | '__| | __| | | |
 / ___ \  / / | |\ | ___) |  __/ (__| |_| | |  | | |_| |_| |
/_/   \_\/_/  |_| \_|____/ \___|\___|\__,_|_|  |_|\__|\__, |
                                                      |___/
BANNER
    printf '%s' "$C_RESET"
    printf '   %s%s v%s%s\n' "$C_DIM" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$C_RESET"
    printf '   %sAccount-level scan · AWS CLI (read-only) · CIS-aligned%s\n\n' "$C_DIM" "$C_RESET"
}

# ------------------------------------------------------------------------------
#  UTILITIES
# ------------------------------------------------------------------------------
html_escape() {
    local s="${1-}"
    s="${s//&/\&amp;}"; s="${s//</\&lt;}"; s="${s//>/\&gt;}"; s="${s//\"/\&quot;}"
    printf '%s' "$s"
}

# html_icon <name> [fallback]
# Emits an <img> tag that REFERENCES the icon from the icons/ folder sitting
# next to the HTML report (nothing is embedded in the HTML). Icons and emoji
# images may be provided in any of these formats (first match wins):
#   icons/<name>.svg | .png | .jpg | .jpeg | .gif | .webp
# If no file is found, the plain-text fallback (e.g. an emoji) is printed.
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

# stage_icons
# The HTML references icons with relative paths ("icons/..."), so a copy of
# the icons folder must live NEXT TO the report file. If ICONS_DIR is located
# somewhere else (e.g. next to the script while the report is written to the
# current directory), copy it into place. Missing folder -> warn and continue
# (the report falls back to plain-text/emoji fallbacks where provided).
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

# zip_report
# When --zip was passed, package the HTML report together with a copy of the
# icons/ folder into <report>.zip so the report carries its images anywhere
# it is downloaded, emailed or moved. Paths inside the zip are relative
# (report.html + icons/), so it can be extracted and opened as-is.
zip_report() {
    [[ "$ZIP_REPORT" == true ]] || return 0
    if ! command -v zip >/dev/null 2>&1; then
        log_warn "'zip' is not installed - skipping packaging (e.g. 'apt-get install zip' / 'yum install zip')."
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
            log_warn "icons/ folder not found next to the report - zipping the HTML only."
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
    for c in "${SCANNED_CATEGORIES[@]:-}"; do [[ "$c" == "$cat" ]] && return 0; done
    SCANNED_CATEGORIES+=("$cat")
}

reset_state() {
    FINDINGS=(); SCANNED_CATEGORIES=()
    CRITICAL_COUNT=0; WARNING_COUNT=0; INFO_COUNT=0
}

is_service_enabled() {
    local api="$1" s
    for s in "${ENABLED_SERVICES[@]:-}"; do [[ "$s" == "$api" ]] && return 0; done
    return 1
}

# Thin AWS wrapper: JSON output, no pager, swallow stderr (callers check output).
awsq() { aws "$@" --output json --no-cli-pager 2>/dev/null; }

# Age in whole days for an ISO-8601 timestamp; prints -1 if unpar. / N/A.
age_days() {
    local d="${1:-}"
    case "$d" in ""|"N/A"|"no_information"|"not_supported"|"null") echo -1; return;; esac
    local e; e=$(date -d "$d" +%s 2>/dev/null) || { echo -1; return; }
    echo $(( ( $(date +%s) - e ) / 86400 ))
}

# Reads an IAM/resource policy document from stdin and returns 0 if it grants
# access to everyone (Principal "*") in an Allow statement without a Condition.
policy_is_public() {
    jq -e '
        (.Statement // [])
        | (if type=="object" then [.] else . end)
        | any(.[];
            (.Effect=="Allow")
            and ( (.Principal=="*")
                  or (.Principal.AWS=="*")
                  or (((.Principal.AWS // empty)
                        | (if type=="array" then any(.[]; .=="*") else .=="*" end)) // false) )
            and ((has("Condition")|not)) )
    ' >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
#  PHASE 0: DEPENDENCIES AND CONTEXT
# ------------------------------------------------------------------------------
check_dependencies() {
    log_step "Checking dependencies and context..."
    if (( BASH_VERSINFO[0] < 4 )); then
        log_error "Bash 4 or higher is required (detected ${BASH_VERSION})."; exit 1
    fi
    local missing=0
    command -v aws >/dev/null 2>&1 || { log_error "'aws' CLI is not installed or not on PATH."; missing=1; }
    command -v jq  >/dev/null 2>&1 || { log_error "'jq' is not installed (e.g. 'apt-get install jq')."; missing=1; }
    (( missing )) && exit 1

    local ident
    ident=$(awsq sts get-caller-identity)
    if [[ -z "$ident" ]]; then
        log_error "Unable to call sts:GetCallerIdentity. Configure credentials (aws configure / SSO / role)."
        exit 1
    fi
    ACCOUNT_ID=$(jq -r '.Account' <<< "$ident")
    local arn; arn=$(jq -r '.Arn' <<< "$ident")
    log_ok "Authenticated as: ${C_BOLD}${arn}${C_RESET}"
    log_ok "Account: ${C_BOLD}${ACCOUNT_ID}${C_RESET}"
}

resolve_context() {
    # Region priority: CLI arg > AWS_REGION > configured region > us-east-1.
    PRIMARY_REGION="${1:-}"
    [[ -z "$PRIMARY_REGION" ]] && PRIMARY_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
    [[ -z "$PRIMARY_REGION" ]] && PRIMARY_REGION="$(aws configure get region 2>/dev/null)"
    [[ -z "$PRIMARY_REGION" ]] && PRIMARY_REGION="us-east-1"

    if [[ "${AWS_SCAN_ALL_REGIONS:-0}" == "1" ]]; then
        local regions
        regions=$(awsq ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null)
        if [[ -n "$regions" ]]; then
            read -r -a SCAN_REGIONS <<< "$regions"
        else
            SCAN_REGIONS=("$PRIMARY_REGION")
        fi
    else
        SCAN_REGIONS=("$PRIMARY_REGION")
    fi

    SCAN_CONTEXT="${ACCOUNT_ID} · region(s): ${SCAN_REGIONS[*]}"
    log_ok "Primary region: ${C_BOLD}${PRIMARY_REGION}${C_RESET}"
    log_ok "Regional scans cover: ${C_BOLD}${SCAN_REGIONS[*]}${C_RESET}"
    REPORT_FILE="aws_assessment_${ACCOUNT_ID}_$(date +%Y%m%d_%H%M%S).html"
}

# ------------------------------------------------------------------------------
#  PHASE 1: DISCOVERY
# ------------------------------------------------------------------------------
discover_services() {
    log_step "Phase 1 · Preparing scanners..."
    # All known services have a built-in deep scanner. We keep the full list as
    # "enabled" for the inventory tab; scanners themselves handle empty results
    # and permission errors gracefully.
    ENABLED_SERVICES=("${KNOWN_SCANNABLE_ORDER[@]}")
    DETECTED_SCANNABLE=("${KNOWN_SCANNABLE_ORDER[@]}")
    UNSCANNED_SERVICES=()

    hr
    log_info "Coverage:"
    printf '      %s• Services with a deep scan : %s%d%s\n' "$C_DIM" "$C_GRN" "${#DETECTED_SCANNABLE[@]}" "$C_RESET"
    printf '      %s• Regions (regional scans)  : %s%d%s\n' "$C_DIM" "$C_BOLD" "${#SCAN_REGIONS[@]}" "$C_RESET"
    hr
    local api n=1
    for api in "${DETECTED_SCANNABLE[@]}"; do
        printf '      %s%2d.%s %-38s %s(%s)%s\n' \
            "$C_GRN" "$n" "$C_RESET" "${API_TO_LABEL[$api]}" "$C_DIM" "$api" "$C_RESET"
        n=$((n + 1))
    done
    hr
}

# ==============================================================================
#  PHASE 3: SECURITY SCANNERS
# ==============================================================================

# --- IAM (global) --------------------------------------------------------------
scan_iam() {
    log_step "Scanning IAM (account, users, keys, policies)..."
    mark_category_scanned "IAM"

    # 1) Account password policy
    log_info "  → Password policy..."
    local pp
    pp=$(awsq iam get-account-password-policy)
    if [[ -z "$pp" ]]; then
        add_finding "WARNING" "IAM" "No account password policy" "account/${ACCOUNT_ID}" \
            "No IAM password policy is set. Define one requiring length >= 14, complexity, and expiry (CIS 1.8-1.11)."
        log_warn "    no password policy"
    else
        local minlen reuse
        minlen=$(jq -r '.PasswordPolicy.MinimumPasswordLength // 0' <<< "$pp")
        reuse=$(jq -r '.PasswordPolicy.PasswordReusePrevention // 0' <<< "$pp")
        (( minlen < 14 )) && add_finding "WARNING" "IAM" "Password minimum length < 14" "account/${ACCOUNT_ID}" \
            "MinimumPasswordLength=${minlen}. CIS recommends >= 14 (CIS 1.8)."
        (( reuse < 24 )) && add_finding "INFO" "IAM" "Password reuse prevention < 24" "account/${ACCOUNT_ID}" \
            "PasswordReusePrevention=${reuse}. CIS recommends remembering >= 24 passwords (CIS 1.9)."
    fi

    # 2) Root account posture
    log_info "  → Root account..."
    local summ mfa root_keys
    summ=$(awsq iam get-account-summary)
    mfa=$(jq -r '.SummaryMap.AccountMFAEnabled // 0' <<< "$summ")
    root_keys=$(jq -r '.SummaryMap.AccountAccessKeysPresent // 0' <<< "$summ")
    if [[ "$mfa" != "1" ]]; then
        add_finding "CRITICAL" "IAM" "Root account has no MFA" "root/${ACCOUNT_ID}" \
            "MFA is not enabled on the root user. Enable hardware or virtual MFA immediately (CIS 1.5)."
        log_crit "    root MFA disabled"
    fi
    if [[ "$root_keys" != "0" ]]; then
        add_finding "CRITICAL" "IAM" "Root account has access keys" "root/${ACCOUNT_ID}" \
            "Root access keys exist and should never be used. Delete them (CIS 1.4)."
        log_crit "    root access keys present"
    fi

    # 3) Credential report (MFA, key age, inactivity)
    log_info "  → Credential report..."
    aws iam generate-credential-report >/dev/null 2>&1
    local report
    report=$(aws iam get-credential-report --query Content --output text 2>/dev/null | base64 -d 2>/dev/null)
    if [[ -n "$report" ]]; then
        local line
        while IFS=, read -r user arn ctime pwd_enabled pwd_last_used pwd_last_chg pwd_next mfa_active \
                            ak1_active ak1_rot ak1_used _ _ ak2_active ak2_rot ak2_used _; do
            [[ "$user" == "user" || -z "$user" ]] && continue
            [[ "$user" == "<root_account>" ]] && continue

            if [[ "$pwd_enabled" == "true" && "$mfa_active" == "false" ]]; then
                add_finding "WARNING" "IAM" "Console user without MFA" "user/${user}" \
                    "Has console access but no MFA device. Enforce MFA for all console users (CIS 1.10)."
                log_warn "    ${user}: console, no MFA"
            fi

            local d
            if [[ "$ak1_active" == "true" ]]; then
                d=$(age_days "$ak1_rot")
                if (( d > KEY_CRIT_DAYS )); then
                    add_finding "CRITICAL" "IAM" "Access key very old" "user/${user}" \
                        "Access key 1 is ${d} days old (> ${KEY_CRIT_DAYS}). Rotate/retire it (CIS 1.14)."
                elif (( d > KEY_WARN_DAYS )); then
                    add_finding "WARNING" "IAM" "Access key not rotated" "user/${user}" \
                        "Access key 1 is ${d} days old (> ${KEY_WARN_DAYS}). Rotate it (CIS 1.14)."
                fi
            fi
            if [[ "$ak2_active" == "true" ]]; then
                d=$(age_days "$ak2_rot")
                if (( d > KEY_CRIT_DAYS )); then
                    add_finding "CRITICAL" "IAM" "Access key very old" "user/${user}" \
                        "Access key 2 is ${d} days old (> ${KEY_CRIT_DAYS}). Rotate/retire it (CIS 1.14)."
                elif (( d > KEY_WARN_DAYS )); then
                    add_finding "WARNING" "IAM" "Access key not rotated" "user/${user}" \
                        "Access key 2 is ${d} days old (> ${KEY_WARN_DAYS}). Rotate it (CIS 1.14)."
                fi
            fi

            # Inactivity (console + keys)
            if [[ "$pwd_enabled" == "true" ]]; then
                d=$(age_days "$pwd_last_used")
                (( d > INACTIVE_DAYS )) && add_finding "INFO" "IAM" "Inactive console user" "user/${user}" \
                    "Console password unused for ${d} days. Disable or remove stale access (CIS 1.12)."
            fi
        done <<< "$report"
    fi

    # 4) Policies attached directly to users + AdministratorAccess
    log_info "  → User policy attachments..."
    local users u
    users=$(awsq iam list-users | jq -r '.Users[]?.UserName')
    if [[ -n "$users" ]]; then
        while IFS= read -r u; do
            [[ -z "$u" ]] && continue
            local attached
            attached=$(awsq iam list-attached-user-policies --user-name "$u" \
                        | jq -r '.AttachedPolicies[]?.PolicyName')
            if [[ -n "$attached" ]]; then
                add_finding "WARNING" "IAM" "Managed policy attached directly to user" "user/${u}" \
                    "Policies should be attached to groups/roles, not users (CIS 1.15). Attached: $(paste -sd', ' <<< "$attached")."
                if grep -q '^AdministratorAccess$' <<< "$attached"; then
                    add_finding "WARNING" "IAM" "User has AdministratorAccess" "user/${u}" \
                        "The user has full administrative access directly attached. Apply least privilege."
                    log_warn "    ${u}: AdministratorAccess"
                fi
            fi
        done <<< "$users"
    fi

    log_ok "IAM done."
}

# --- S3 (global) ---------------------------------------------------------------
scan_s3() {
    log_step "Scanning S3 (buckets)..."
    mark_category_scanned "S3"

    # Account-level Public Access Block (CIS 2.1.5)
    local acc_pab
    acc_pab=$(awsq s3control get-public-access-block --account-id "$ACCOUNT_ID")
    if [[ -z "$acc_pab" ]] || [[ "$(jq -r '[.PublicAccessBlockConfiguration|to_entries[].value]|all' <<< "$acc_pab")" != "true" ]]; then
        add_finding "WARNING" "S3" "Account-level S3 Public Access Block not fully on" "account/${ACCOUNT_ID}" \
            "Enable all four account-level Block Public Access settings to prevent any bucket from being made public (CIS 2.1.5)."
        log_warn "    account PAB not fully enabled"
    fi

    local buckets b
    buckets=$(awsq s3api list-buckets | jq -r '.Buckets[]?.Name')
    if [[ -z "$buckets" ]]; then
        log_info "  → No buckets detected."; log_ok "S3 done."; return 0
    fi

    while IFS= read -r b; do
        [[ -z "$b" ]] && continue
        log_info "  → s3://${b}"

        # Public via policy status (authoritative)
        local ps
        ps=$(awsq s3api get-bucket-policy-status --bucket "$b")
        if [[ "$(jq -r '.PolicyStatus.IsPublic // false' <<< "$ps")" == "true" ]]; then
            add_finding "CRITICAL" "S3" "Bucket is public (policy)" "s3://${b}" \
                "The bucket policy grants public access. Restrict it and enable Block Public Access (CIS 2.1.x)."
            log_crit "    ${b} is PUBLIC (policy)"
        fi

        # Public ACL grants
        local acl
        acl=$(awsq s3api get-bucket-acl --bucket "$b")
        if [[ "$(jq -r '[.Grants[]?.Grantee.URI // ""] | any(test("AllUsers|AuthenticatedUsers"))' <<< "$acl")" == "true" ]]; then
            add_finding "CRITICAL" "S3" "Bucket ACL grants public access" "s3://${b}" \
                "An ACL grants AllUsers/AuthenticatedUsers. Remove public ACLs and enable Block Public Access."
            log_crit "    ${b} public ACL"
        fi

        # Per-bucket Public Access Block
        local pab
        pab=$(awsq s3api get-public-access-block --bucket "$b")
        if [[ -z "$pab" ]] || [[ "$(jq -r '[.PublicAccessBlockConfiguration|to_entries[].value]|all' <<< "$pab")" != "true" ]]; then
            add_finding "WARNING" "S3" "Block Public Access not fully enabled" "s3://${b}" \
                "Not all four Block Public Access settings are on for this bucket (CIS 2.1.5)."
        fi

        # Default encryption
        local enc
        enc=$(awsq s3api get-bucket-encryption --bucket "$b")
        [[ -z "$enc" ]] && add_finding "WARNING" "S3" "No default encryption" "s3://${b}" \
            "Server-side encryption is not configured by default. Enable SSE-S3 or SSE-KMS (CIS 2.1.1)."

        # Versioning
        local ver
        ver=$(awsq s3api get-bucket-versioning --bucket "$b" | jq -r '.Status // "Disabled"')
        [[ "$ver" != "Enabled" ]] && add_finding "INFO" "S3" "Versioning disabled" "s3://${b}" \
            "Object versioning is off; overwritten/deleted objects cannot be recovered (CIS 2.1.3)."

        # Access logging
        local logn
        logn=$(awsq s3api get-bucket-logging --bucket "$b" | jq -r '.LoggingEnabled.TargetBucket // "None"')
        [[ "$logn" == "None" || -z "$logn" ]] && add_finding "INFO" "S3" "Server access logging disabled" "s3://${b}" \
            "No access logging target set; requests to the bucket are not logged (CIS 2.1.2)."
    done <<< "$buckets"

    log_ok "S3 done."
}

# --- EC2 / EBS (regional) ------------------------------------------------------
scan_ec2() {
    log_step "Scanning EC2 (instances, EBS)..."
    mark_category_scanned "EC2"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        log_info "  → region ${region}"

        # EBS encryption by default (CIS 2.2.1)
        local ebd
        ebd=$(awsq ec2 get-ebs-encryption-by-default --region "$region" | jq -r '.EbsEncryptionByDefault // false')
        [[ "$ebd" != "true" ]] && add_finding "WARNING" "EC2" "EBS encryption by default disabled" "${region}" \
            "New EBS volumes are not encrypted by default. Enable account/region default encryption (CIS 2.2.1)."

        # Instances: public IP + IMDSv2
        local inst
        inst=$(awsq ec2 describe-instances --region "$region")
        if [[ -n "$inst" ]]; then
            while IFS=$'\t' read -r id pub tokens; do
                [[ -z "$id" ]] && continue
                [[ -n "$pub" && "$pub" != "null" ]] && add_finding "WARNING" "EC2" "Instance has a public IP" "${id} (${region})" \
                    "Public IP ${pub} is attached. Prefer private subnets + NAT/SSM/bastion."
                [[ "$tokens" != "required" ]] && add_finding "WARNING" "EC2" "IMDSv2 not enforced" "${id} (${region})" \
                    "HttpTokens=${tokens}; the instance still allows IMDSv1, which is exploitable via SSRF. Require IMDSv2 (CIS 5.6)."
            done < <(jq -r '.Reservations[]?.Instances[]?
                        | select((.State.Name // "")!="terminated")
                        | [ .InstanceId, (.PublicIpAddress // "null"), (.MetadataOptions.HttpTokens // "optional") ] | @tsv' <<< "$inst")
        fi

        # Unencrypted EBS volumes
        local vols
        vols=$(awsq ec2 describe-volumes --region "$region")
        if [[ -n "$vols" ]]; then
            while IFS= read -r vid; do
                [[ -z "$vid" ]] && continue
                add_finding "WARNING" "EC2" "Unencrypted EBS volume" "${vid} (${region})" \
                    "Volume is not encrypted at rest. Recreate from an encrypted snapshot (CIS 2.2.1)."
            done < <(jq -r '.Volumes[]? | select((.Encrypted // false)==false) | .VolumeId' <<< "$vols")
        fi

        # Public AMIs / snapshots owned by this account
        local pub_amis
        pub_amis=$(awsq ec2 describe-images --owners self --region "$region" | jq -r '.Images[]? | select(.Public==true) | .ImageId')
        if [[ -n "$pub_amis" ]]; then
            local a
            while IFS= read -r a; do [[ -z "$a" ]] && continue
                add_finding "CRITICAL" "EC2" "Public AMI" "${a} (${region})" \
                    "This AMI is shared publicly and may leak baked-in secrets/data. Make it private."
                log_crit "    public AMI ${a}"
            done <<< "$pub_amis"
        fi
    done
    log_ok "EC2 done."
}

# --- VPC / Security Groups (regional) ------------------------------------------
scan_vpc() {
    log_step "Scanning VPC (security groups, flow logs)..."
    mark_category_scanned "VPC"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        log_info "  → region ${region}"

        # Security groups open to the world
        local sgs
        sgs=$(awsq ec2 describe-security-groups --region "$region")
        if [[ -n "$sgs" ]]; then
            while IFS=$'\t' read -r sgid ports; do
                [[ -z "$sgid" ]] && continue
                local sev="WARNING"
                if [[ "$ports" == *":22"* || "$ports" == *":3389"* || "$ports" == *"ALL"* ]]; then sev="CRITICAL"; fi
                add_finding "$sev" "VPC" "Security group open to 0.0.0.0/0" "${sgid} (${region})" \
                    "Ingress from the Internet on: ${ports}. Restrict source ranges; never expose 22/3389 publicly (CIS 5.2/5.3)."
                [[ "$sev" == "CRITICAL" ]] && log_crit "    ${sgid} exposes ${ports}" || log_warn "    ${sgid} open (${ports})"
            done < <(jq -r '.SecurityGroups[]?
                        | .GroupId as $g
                        | [ $g,
                            ([ .IpPermissions[]?
                               | select((.IpRanges[]?.CidrIp=="0.0.0.0/0") or (.Ipv6Ranges[]?.CidrIpv6=="::/0"))
                               | (if .IpProtocol=="-1" then "ALL" else (.IpProtocol + ":" + ((.FromPort // 0)|tostring)) end) ]
                             | unique | join(" ")) ]
                        | select(.[1] != "")
                        | @tsv' <<< "$sgs")

            # Default SG should carry no rules
            while IFS= read -r dsg; do
                [[ -z "$dsg" ]] && continue
                add_finding "WARNING" "VPC" "Default security group has rules" "${dsg} (${region})" \
                    "The default SG should deny all traffic (no rules) and not be attached to resources (CIS 5.4)."
            done < <(jq -r '.SecurityGroups[]?
                        | select(.GroupName=="default")
                        | select(((.IpPermissions|length)>0) or ((.IpPermissionsEgress|length)>1))
                        | .GroupId' <<< "$sgs")
        fi

        # VPCs without flow logs
        local vpcs fls
        vpcs=$(awsq ec2 describe-vpcs --region "$region" | jq -r '.Vpcs[]?.VpcId')
        fls=$(awsq ec2 describe-flow-logs --region "$region" | jq -r '.FlowLogs[]?.ResourceId')
        if [[ -n "$vpcs" ]]; then
            local v
            while IFS= read -r v; do
                [[ -z "$v" ]] && continue
                if ! grep -qx "$v" <<< "$fls"; then
                    add_finding "WARNING" "VPC" "VPC flow logs disabled" "${v} (${region})" \
                        "No flow logs on this VPC; network forensics/anomaly detection is impaired (CIS 3.9)."
                    log_warn "    ${v}: no flow logs"
                fi
            done <<< "$vpcs"
        fi
    done
    log_ok "VPC done."
}

# --- RDS (regional) ------------------------------------------------------------
scan_rds() {
    log_step "Scanning RDS (databases)..."
    mark_category_scanned "RDS"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local dbs
        dbs=$(awsq rds describe-db-instances --region "$region")
        [[ -z "$dbs" ]] && continue
        log_info "  → region ${region}"
        while IFS=$'\t' read -r id public enc backup delprot tls; do
            [[ -z "$id" ]] && continue
            [[ "$public" == "true" ]] && { add_finding "CRITICAL" "RDS" "Publicly accessible database" "${id} (${region})" \
                "PubliclyAccessible=true exposes the DB endpoint to the Internet. Disable public access (CIS 2.3.3)."; log_crit "    ${id} public"; }
            [[ "$enc" != "true" ]] && add_finding "WARNING" "RDS" "Storage not encrypted" "${id} (${region})" \
                "StorageEncrypted=false. Enable encryption at rest with KMS (CIS 2.3.1)."
            [[ "$backup" == "0" ]] && add_finding "WARNING" "RDS" "Automated backups disabled" "${id} (${region})" \
                "BackupRetentionPeriod=0. Enable automated backups for recovery (CIS 2.3.2)."
            [[ "$delprot" != "true" ]] && add_finding "INFO" "RDS" "Deletion protection disabled" "${id} (${region})" \
                "Enable deletion protection for production databases."
        done < <(jq -r '.DBInstances[]?
                    | [ .DBInstanceIdentifier,
                        ((.PubliclyAccessible // false)|tostring),
                        ((.StorageEncrypted // false)|tostring),
                        ((.BackupRetentionPeriod // 0)|tostring),
                        ((.DeletionProtection // false)|tostring),
                        "na" ] | @tsv' <<< "$dbs")
    done
    log_ok "RDS done."
}

# --- EKS (regional) ------------------------------------------------------------
scan_eks() {
    log_step "Scanning EKS (clusters)..."
    mark_category_scanned "EKS"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local names c
        names=$(awsq eks list-clusters --region "$region" | jq -r '.clusters[]?')
        [[ -z "$names" ]] && continue
        log_info "  → region ${region}"
        while IFS= read -r c; do
            [[ -z "$c" ]] && continue
            local desc pub cidrs logging secrets ver
            desc=$(awsq eks describe-cluster --name "$c" --region "$region")
            pub=$(jq -r '.cluster.resourcesVpcConfig.endpointPublicAccess // false' <<< "$desc")
            cidrs=$(jq -r '(.cluster.resourcesVpcConfig.publicAccessCidrs // []) | join(",")' <<< "$desc")
            logging=$(jq -r '[.cluster.logging.clusterLogging[]? | select(.enabled==true) | .types[]] | length' <<< "$desc")
            secrets=$(jq -r '(.cluster.encryptionConfig // []) | length' <<< "$desc")
            ver=$(jq -r '.cluster.version // "?"' <<< "$desc")
            if [[ "$pub" == "true" && "$cidrs" == *"0.0.0.0/0"* ]]; then
                add_finding "CRITICAL" "EKS" "Public API endpoint open to the world" "${c} (${region})" \
                    "The Kubernetes API endpoint is public with 0.0.0.0/0. Restrict public access CIDRs or make it private."
                log_crit "    ${c}: API open to world"
            elif [[ "$pub" == "true" ]]; then
                add_finding "WARNING" "EKS" "Public API endpoint" "${c} (${region})" \
                    "The API endpoint is public (restricted CIDRs). Consider a private endpoint."
            fi
            [[ "$logging" == "0" ]] && add_finding "WARNING" "EKS" "Control-plane logging disabled" "${c} (${region})" \
                "No control-plane log types are enabled; audit/authenticator logs are lost. Enable control-plane logging."
            [[ "$secrets" == "0" ]] && add_finding "WARNING" "EKS" "Secrets encryption (KMS) not configured" "${c} (${region})" \
                "Kubernetes secrets are not envelope-encrypted with a KMS key. Enable secrets encryption."
        done <<< "$names"
    done
    log_ok "EKS done."
}

# --- Lambda (regional) ---------------------------------------------------------
scan_lambda() {
    log_step "Scanning Lambda (functions)..."
    mark_category_scanned "LAMBDA"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local fns
        fns=$(awsq lambda list-functions --region "$region")
        [[ -z "$fns" ]] && continue
        log_info "  → region ${region}"
        while IFS=$'\t' read -r name runtime vpc envsecret; do
            [[ -z "$name" ]] && continue
            # Public resource policy
            local pol
            pol=$(aws lambda get-policy --function-name "$name" --region "$region" --output json --no-cli-pager 2>/dev/null | jq -r '.Policy // empty')
            if [[ -n "$pol" ]] && policy_is_public <<< "$pol"; then
                add_finding "CRITICAL" "LAMBDA" "Function policy allows public invoke" "${name} (${region})" \
                    "The resource policy grants access to a wildcard principal without conditions. Restrict it."
                log_crit "    ${name} public policy"
            fi
            case "$runtime" in
                nodejs|nodejs4.3*|nodejs6*|nodejs8*|nodejs10*|nodejs12*|nodejs14*|python2.7|python3.6|python3.7|dotnetcore*|ruby2.5|ruby2.7|go1.x|java8)
                    add_finding "WARNING" "LAMBDA" "Deprecated runtime" "${name} (${region})" \
                        "Runtime '${runtime}' is deprecated/EOL and no longer patched. Upgrade to a supported runtime." ;;
            esac
            [[ "$envsecret" == "true" ]] && add_finding "WARNING" "LAMBDA" "Possible secret in environment variable" "${name} (${region})" \
                "An env var name suggests a credential. Use Secrets Manager / SSM Parameter Store instead of plaintext env."
            [[ "$vpc" == "none" ]] && add_finding "INFO" "LAMBDA" "Not attached to a VPC" "${name} (${region})" \
                "The function runs outside any VPC; egress is not governed by VPC controls (may be intentional)."
        done < <(jq -r '.Functions[]?
                    | [ .FunctionName,
                        (.Runtime // "unknown"),
                        (if (.VpcConfig.VpcId // "")=="" then "none" else "vpc" end),
                        (((.Environment.Variables // {}) | keys | any(test("(?i)(pass|secret|token|api[_-]?key|credential|private[_-]?key)"))) | tostring) ]
                    | @tsv' <<< "$fns")
    done
    log_ok "Lambda done."
}

# --- ECR (regional) ------------------------------------------------------------
scan_ecr() {
    log_step "Scanning ECR (repositories)..."
    mark_category_scanned "ECR"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local repos
        repos=$(awsq ecr describe-repositories --region "$region")
        [[ -z "$repos" ]] && continue
        log_info "  → region ${region}"
        while IFS=$'\t' read -r name scan mutab; do
            [[ -z "$name" ]] && continue
            local pol
            pol=$(aws ecr get-repository-policy --repository-name "$name" --region "$region" --output json --no-cli-pager 2>/dev/null | jq -r '.policyText // empty')
            if [[ -n "$pol" ]] && policy_is_public <<< "$pol"; then
                add_finding "CRITICAL" "ECR" "Repository policy is public" "${name} (${region})" \
                    "The repo policy grants a wildcard principal without conditions; images may be pulled/pushed publicly."
                log_crit "    ${name} public policy"
            fi
            [[ "$scan" != "true" ]] && add_finding "WARNING" "ECR" "Scan on push disabled" "${name} (${region})" \
                "Image scanning on push is off; vulnerable images can be published undetected."
            [[ "$mutab" == "MUTABLE" ]] && add_finding "INFO" "ECR" "Mutable image tags" "${name} (${region})" \
                "Tags are mutable, allowing an image to be silently replaced. Consider IMMUTABLE tags."
        done < <(jq -r '.repositories[]?
                    | [ .repositoryName,
                        ((.imageScanningConfiguration.scanOnPush // false)|tostring),
                        (.imageTagMutability // "MUTABLE") ] | @tsv' <<< "$repos")
    done
    log_ok "ECR done."
}

# --- Secrets Manager (regional) ------------------------------------------------
scan_secrets() {
    log_step "Scanning Secrets Manager..."
    mark_category_scanned "SECRETS"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local secs
        secs=$(awsq secretsmanager list-secrets --region "$region")
        [[ -z "$secs" ]] && continue
        log_info "  → region ${region}"
        while IFS=$'\t' read -r name rot kms; do
            [[ -z "$name" ]] && continue
            local pol
            pol=$(aws secretsmanager get-resource-policy --secret-id "$name" --region "$region" --output json --no-cli-pager 2>/dev/null | jq -r '.ResourcePolicy // empty')
            if [[ -n "$pol" ]] && policy_is_public <<< "$pol"; then
                add_finding "CRITICAL" "SECRETS" "Secret resource policy is public" "${name} (${region})" \
                    "The resource policy grants a wildcard principal without conditions. Revoke immediately."
                log_crit "    ${name} public policy"
            fi
            [[ "$rot" != "true" ]] && add_finding "INFO" "SECRETS" "Rotation not enabled" "${name} (${region})" \
                "Automatic rotation is off; long-lived secrets increase blast radius if leaked."
            [[ "$kms" == "none" ]] && add_finding "INFO" "SECRETS" "Uses default AWS-managed key" "${name} (${region})" \
                "For sensitive data, encrypt with a customer-managed KMS key (CMK) for tighter access control."
        done < <(jq -r '.SecretList[]?
                    | [ .Name,
                        ((.RotationEnabled // false)|tostring),
                        (if (.KmsKeyId // "")=="" then "none" else "cmk" end) ] | @tsv' <<< "$secs")
    done
    log_ok "Secrets Manager done."
}

# --- SNS (regional) ------------------------------------------------------------
scan_sns() {
    log_step "Scanning SNS (topics)..."
    mark_category_scanned "SNS"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local topics t
        topics=$(awsq sns list-topics --region "$region" | jq -r '.Topics[]?.TopicArn')
        [[ -z "$topics" ]] && continue
        log_info "  → region ${region}"
        while IFS= read -r t; do
            [[ -z "$t" ]] && continue
            local attr pol kms
            attr=$(awsq sns get-topic-attributes --topic-arn "$t" --region "$region")
            pol=$(jq -r '.Attributes.Policy // empty' <<< "$attr")
            kms=$(jq -r '.Attributes.KmsMasterKeyId // "none"' <<< "$attr")
            if [[ -n "$pol" ]] && policy_is_public <<< "$pol"; then
                add_finding "CRITICAL" "SNS" "Topic policy is public" "${t##*:} (${region})" \
                    "The topic policy grants a wildcard principal without conditions. Restrict publish/subscribe."
                log_crit "    ${t##*:} public policy"
            fi
            [[ "$kms" == "none" ]] && add_finding "INFO" "SNS" "No encryption at rest" "${t##*:} (${region})" \
                "No KmsMasterKeyId set; messages are not encrypted at rest with a CMK."
        done <<< "$topics"
    done
    log_ok "SNS done."
}

# --- SQS (regional) ------------------------------------------------------------
scan_sqs() {
    log_step "Scanning SQS (queues)..."
    mark_category_scanned "SQS"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local queues q
        queues=$(awsq sqs list-queues --region "$region" | jq -r '.QueueUrls[]?')
        [[ -z "$queues" ]] && continue
        log_info "  → region ${region}"
        while IFS= read -r q; do
            [[ -z "$q" ]] && continue
            local attr pol kms sse
            attr=$(awsq sqs get-queue-attributes --queue-url "$q" --attribute-names Policy KmsMasterKeyId SqsManagedSseEnabled --region "$region")
            pol=$(jq -r '.Attributes.Policy // empty' <<< "$attr")
            kms=$(jq -r '.Attributes.KmsMasterKeyId // "none"' <<< "$attr")
            sse=$(jq -r '.Attributes.SqsManagedSseEnabled // "false"' <<< "$attr")
            if [[ -n "$pol" ]] && policy_is_public <<< "$pol"; then
                add_finding "CRITICAL" "SQS" "Queue policy is public" "${q##*/} (${region})" \
                    "The queue policy grants a wildcard principal without conditions. Restrict access."
                log_crit "    ${q##*/} public policy"
            fi
            if [[ "$kms" == "none" && "$sse" != "true" ]]; then
                add_finding "INFO" "SQS" "No encryption at rest" "${q##*/} (${region})" \
                    "Neither KMS SSE nor SQS-managed SSE is enabled; messages are not encrypted at rest."
            fi
        done <<< "$queues"
    done
    log_ok "SQS done."
}

# --- KMS (regional) ------------------------------------------------------------
scan_kms() {
    log_step "Scanning KMS (customer keys)..."
    mark_category_scanned "KMS"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local keys k
        keys=$(awsq kms list-keys --region "$region" | jq -r '.Keys[]?.KeyId')
        [[ -z "$keys" ]] && continue
        log_info "  → region ${region}"
        while IFS= read -r k; do
            [[ -z "$k" ]] && continue
            local meta mgr state
            meta=$(awsq kms describe-key --key-id "$k" --region "$region")
            mgr=$(jq -r '.KeyMetadata.KeyManager // "AWS"' <<< "$meta")
            state=$(jq -r '.KeyMetadata.KeyState // ""' <<< "$meta")
            [[ "$mgr" != "CUSTOMER" || "$state" != "Enabled" ]] && continue

            local rot
            rot=$(awsq kms get-key-rotation-status --key-id "$k" --region "$region" | jq -r '.KeyRotationEnabled // false')
            [[ "$rot" != "true" ]] && add_finding "WARNING" "KMS" "Key rotation disabled" "${k} (${region})" \
                "Automatic annual rotation is off for this customer-managed key. Enable rotation (CIS 3.8)."

            local pol
            pol=$(aws kms get-key-policy --key-id "$k" --policy-name default --region "$region" --output json --no-cli-pager 2>/dev/null | jq -r '.Policy // empty')
            if [[ -n "$pol" ]] && policy_is_public <<< "$pol"; then
                add_finding "CRITICAL" "KMS" "Key policy is public" "${k} (${region})" \
                    "The key policy grants a wildcard principal without conditions; anyone could use the key."
                log_crit "    ${k} public policy"
            fi
        done <<< "$keys"
    done
    log_ok "KMS done."
}

# --- CloudTrail (account/global) -----------------------------------------------
scan_cloudtrail() {
    log_step "Scanning CloudTrail (audit logging)..."
    mark_category_scanned "CLOUDTRAIL"
    local trails
    trails=$(awsq cloudtrail describe-trails --region "$PRIMARY_REGION")
    local count
    count=$(jq -r '.trailList | length' <<< "$trails" 2>/dev/null || echo 0)
    if [[ -z "$trails" || "$count" == "0" ]]; then
        add_finding "CRITICAL" "CLOUDTRAIL" "No CloudTrail configured" "account/${ACCOUNT_ID}" \
            "No trail exists; API activity is not being recorded. Create a multi-region trail (CIS 3.1)."
        log_crit "    no trail"
        log_ok "CloudTrail done."; return 0
    fi

    # Is there at least one logging, multi-region, validated trail?
    local multi=0 t name mr val kms status
    while IFS=$'\t' read -r name mr val kms; do
        [[ -z "$name" ]] && continue
        status=$(awsq cloudtrail get-trail-status --name "$name" --region "$PRIMARY_REGION" | jq -r '.IsLogging // false')
        [[ "$mr" == "true" && "$status" == "true" ]] && multi=1
        [[ "$val" != "true" ]] && add_finding "WARNING" "CLOUDTRAIL" "Log file validation disabled" "$name" \
            "Enable log file integrity validation to detect tampering (CIS 3.2)."
        [[ -z "$kms" || "$kms" == "null" ]] && add_finding "INFO" "CLOUDTRAIL" "Trail logs not KMS-encrypted" "$name" \
            "Configure SSE-KMS encryption for trail log files (CIS 3.7)."
        [[ "$status" != "true" ]] && add_finding "WARNING" "CLOUDTRAIL" "Trail is not logging" "$name" \
            "The trail exists but IsLogging=false. Start logging."
    done < <(jq -r '.trailList[]? | [ .Name, ((.IsMultiRegionTrail // false)|tostring), ((.LogFileValidationEnabled // false)|tostring), (.KmsKeyId // "null") ] | @tsv' <<< "$trails")

    (( multi == 0 )) && add_finding "CRITICAL" "CLOUDTRAIL" "No active multi-region trail" "account/${ACCOUNT_ID}" \
        "No enabled multi-region trail is logging. Enable one to capture all regions (CIS 3.1)."
    log_ok "CloudTrail done."
}

# --- GuardDuty (regional) ------------------------------------------------------
scan_guardduty() {
    log_step "Scanning GuardDuty (threat detection)..."
    mark_category_scanned "GUARDDUTY"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local dets
        dets=$(awsq guardduty list-detectors --region "$region" | jq -r '.DetectorIds[]?')
        if [[ -z "$dets" ]]; then
            add_finding "WARNING" "GUARDDUTY" "GuardDuty not enabled" "${region}" \
                "No detector in this region; threat detection is off. Enable GuardDuty."
            log_warn "    ${region}: GuardDuty off"
        fi
    done
    log_ok "GuardDuty done."
}

# --- AWS Config (regional) -----------------------------------------------------
scan_config() {
    log_step "Scanning AWS Config (recording)..."
    mark_category_scanned "CONFIG"
    local region
    for region in "${SCAN_REGIONS[@]}"; do
        local rec recording
        rec=$(awsq configservice describe-configuration-recorders --region "$region")
        if [[ -z "$rec" ]] || [[ "$(jq -r '.ConfigurationRecorders | length' <<< "$rec" 2>/dev/null || echo 0)" == "0" ]]; then
            add_finding "WARNING" "CONFIG" "AWS Config not enabled" "${region}" \
                "No configuration recorder; resource configuration history is not tracked (CIS 3.5)."
            log_warn "    ${region}: Config off"
            continue
        fi
        recording=$(awsq configservice describe-configuration-recorder-status --region "$region" | jq -r '[.ConfigurationRecordersStatus[]?.recording] | any')
        [[ "$recording" != "true" ]] && add_finding "WARNING" "CONFIG" "Config recorder stopped" "${region}" \
            "A recorder exists but is not recording. Start it (CIS 3.5)."
    done
    log_ok "AWS Config done."
}

# --- Route 53 (global) ---------------------------------------------------------
scan_route53() {
    log_step "Scanning Route 53 (public hosted zones)..."
    mark_category_scanned "ROUTE53"
    local zones
    zones=$(awsq route53 list-hosted-zones)
    [[ -z "$zones" ]] && { log_info "  → No hosted zones."; log_ok "Route 53 done."; return 0; }
    local zid zname priv
    while IFS=$'\t' read -r zid zname priv; do
        [[ -z "$zid" ]] && continue
        [[ "$priv" == "true" ]] && continue   # DNSSEC not applicable to private zones
        local st
        st=$(awsq route53 get-dnssec --hosted-zone-id "$zid" | jq -r '.Status.ServeSignature // "NOT_SIGNING"')
        if [[ "$st" != "SIGNING" ]]; then
            add_finding "WARNING" "ROUTE53" "DNSSEC not enabled on public zone" "${zname}" \
                "Public hosted zone is not DNSSEC-signed (status: ${st}); records can be spoofed. Enable DNSSEC signing."
            log_warn "    ${zname}: DNSSEC ${st}"
        fi
    done < <(jq -r '.HostedZones[]? | [ (.Id|sub("/hostedzone/";"")), .Name, ((.Config.PrivateZone // false)|tostring) ] | @tsv' <<< "$zones")
    log_ok "Route 53 done."
}

# --- Dispatcher ----------------------------------------------------------------
run_scan_by_api() {
    local api="$1" fn="${API_TO_SCANNER[$api]:-}"
    [[ -z "$fn" ]] && { log_warn "No scanner defined for ${api}."; return 1; }
    "$fn"
}

# ------------------------------------------------------------------------------
#  MENU ACTIONS
# ------------------------------------------------------------------------------
scan_all() {
    reset_state
    log_step "Starting FULL scan..."
    hr
    local api
    for api in "${DETECTED_SCANNABLE[@]}"; do
        run_scan_by_api "$api"; hr
    done
    finish_scan
}

scan_on_demand() {
    if (( ${#DETECTED_SCANNABLE[@]} == 0 )); then
        log_warn "No services available to scan."; return 0
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
        local sel; local -A seen=()
        for sel in $input; do
            [[ "$sel" =~ ^[0-9]+$ ]] || { log_warn "Ignored: '${sel}'"; continue; }
            local idx=$((sel - 1))
            (( idx < 0 || idx >= ${#DETECTED_SCANNABLE[@]} )) && { log_warn "Out of range: ${sel}"; continue; }
            [[ -n "${seen[$idx]:-}" ]] && continue; seen[$idx]=1
            run_scan_by_api "${DETECTED_SCANNABLE[$idx]}"; hr
        done
    fi
    (( ${#SCANNED_CATEGORIES[@]} == 0 )) && { log_warn "No valid scan executed."; return 0; }
    finish_scan
}

# Console summary + report generation after any scan.
finish_scan() {
    hr
    printf '%sScan summary:%s  ' "$C_BOLD" "$C_RESET"
    printf '%s%d CRITICAL%s · %s%d WARNING%s · %s%d INFO%s\n' \
        "$C_RED" "$CRITICAL_COUNT" "$C_RESET" \
        "$C_YEL" "$WARNING_COUNT" "$C_RESET" \
        "$C_BLU" "$INFO_COUNT" "$C_RESET"
    generate_html_report
    hr
}
# ------------------------------------------------------------------------------
#  PHASE 4: SELF-CONTAINED HTML REPORT WITH TABS
# ------------------------------------------------------------------------------

# Counts findings for a category/severity.
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

# Emits the <tr> rows for a category, ordered by severity.
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
    if (( CRITICAL_COUNT > 0 )); then posture="HIGH RISK"; posture_class="crit"
    elif (( WARNING_COUNT > 0 )); then posture="MEDIUM RISK"; posture_class="warn"
    else posture="LOW RISK"; posture_class="ok"; fi

    # --- Head + CSS (static, quoted heredoc) ---
    cat > "$REPORT_FILE" <<'HTML_HEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Security Assessment</title>
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

  /* Tabs */
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

  /* Cards */
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
         gap:16px;margin-bottom:26px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:14px;
        padding:18px 20px;box-shadow:var(--shadow)}
  .card .k{color:var(--muted);font-size:13px;margin-bottom:8px}
  .card .v{font-size:32px;font-weight:700;line-height:1}
  .card.c-crit .v{color:var(--crit)} .card.c-warn .v{color:var(--warn)}
  .card.c-info .v{color:var(--info)} .card.c-total .v{color:var(--txt)}

  /* Bar chart */
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

  /* Service breakdown */
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

  /* Tables */
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

    # --- Dynamic header ---
    {
        printf '<header class="top">\n'
        printf '  <div class="brand"><div class="logo">%s</div>\n' "$(html_icon shield)"
        printf '    <div><h1>AWS Security Assessment</h1>\n'
        printf '      <p>Posture evaluation · account <b>%s</b></p></div>\n' "$(html_escape "$SCAN_CONTEXT")"
        printf '  </div>\n'
        printf '  <button class="toggle" onclick="toggleTheme()">%s Light/dark theme</button>\n' "$(html_icon theme "🌗")"
        printf '</header>\n'

        printf '<div class="meta">\n'
        printf '  <span>Generated: <b>%s</b></span>\n' "$ts"
        printf '  <span>Total findings: <b>%d</b></span>\n' "$total"
        printf '  <span class="posture %s">Posture: %s</span>\n' "$posture_class" "$posture"
        printf '</div>\n'

        # --- Tab buttons ---
        printf '<div class="tabs">\n'
        printf '  <button class="tab active" onclick="showTab(event,'"'"'summary'"'"')">%s Executive Summary</button>\n' "$(html_icon summary)"
        printf '  <button class="tab" onclick="showTab(event,'"'"'inventory'"'"')">%s Service Inventory<span class="count">%d</span></button>\n' "$(html_icon inventory)" "${#ENABLED_SERVICES[@]}"
        local cat
        for cat in "${CAT_ORDER[@]}"; do
            # only tabs for scanned categories
            local scanned=0 c
            for c in "${SCANNED_CATEGORIES[@]:-}"; do [[ "$c" == "$cat" ]] && scanned=1; done
            (( scanned )) || continue
            local n; n=$(count_findings "$cat" "")
            printf '  <button class="tab" onclick="showTab(event,'"'"'%s'"'"')">%s %s<span class="count">%d</span></button>\n' \
                "$cat" "$(html_icon "${cat,,}")" "${CAT_TITLE[$cat]}" "$n"
        done
        printf '</div>\n'
    } >> "$REPORT_FILE"

    # --- Panel: Executive Summary ---
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
            printf '    <div class="svc"><div class="h">%s%s</div>\n' \
                "$(html_icon "${cat,,}")" "${CAT_TITLE[$cat]}"
            printf '      <div class="pips">\n'
            printf '        <span class="pip"><span class="dot crit"></span>%d</span>\n' "$cc"
            printf '        <span class="pip"><span class="dot warn"></span>%d</span>\n' "$cw"
            printf '        <span class="pip"><span class="dot info"></span>%d</span>\n' "$ci"
            printf '      </div></div>\n'
        done
        printf '  </div>\n'
        printf '</div>\n'
    } >> "$REPORT_FILE"

    # --- Per-category panels ---
    {
        local cat scanned c n
        for cat in "${CAT_ORDER[@]}"; do
            scanned=0
            for c in "${SCANNED_CATEGORIES[@]:-}"; do [[ "$c" == "$cat" ]] && scanned=1; done
            (( scanned )) || continue
            n=$(count_findings "$cat" "")
            printf '<div id="%s" class="panel">\n' "$cat"
            printf '  <h2 style="font-size:18px;margin:0 0 16px">%s %s</h2>\n' \
                "$(html_icon "${cat,,}")" "${CAT_TITLE[$cat]}"
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

    # --- Panel: Service Inventory (all detected active services) ---
    {
        printf '<div id="inventory" class="panel">\n'
        printf '  <h2 style="font-size:18px;margin:0 0 6px">%s Service Inventory</h2>\n' "$(html_icon inventory)"
        printf '  <p style="color:var(--muted);margin:0 0 16px;font-size:14px">All enabled APIs detected as active in the project. Deep scanning applies to supported services; the rest are listed for full visibility.</p>\n'
        printf '  <table><thead><tr><th>Service (API)</th><th>Coverage</th></tr></thead><tbody>\n'
        local api scanner
        # First the ones with a deep scanner (active), then the rest.
        for api in "${ENABLED_SERVICES[@]:-}"; do
            [[ -z "$api" ]] && continue
            scanner="${API_TO_SCANNER[$api]:-}"
            [[ -z "$scanner" ]] && continue
            printf '    <tr><td class="res"><code>%s</code></td><td><span class="badge info">DEEP SCAN</span></td></tr>\n' \
                "$(html_escape "$api")"
        done
        for api in "${UNSCANNED_SERVICES[@]:-}"; do
            [[ -z "$api" ]] && continue
            printf '    <tr><td class="res"><code>%s</code></td><td><span class="badge warning">INVENTORY ONLY</span></td></tr>\n' \
                "$(html_escape "$api")"
        done
        printf '  </tbody></table>\n'
        printf '</div>\n'
    } >> "$REPORT_FILE"
    cat >> "$REPORT_FILE" <<'HTML_TAIL'
<footer>
  Report generated by AWS Security Assessment · Account-level scan using the AWS CLI (read-only). Regional scanners cover the selected region(s).
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
            "Scan ALL services" \
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
    # --- Argument parsing: flags + optional region (order-independent) ---
    local region="" a
    for a in "$@"; do
        case "$a" in
            --zip) ZIP_REPORT=true ;;
            --*)   printf 'Unknown option: %s\nUsage: %s [--zip] [REGION]\n' "$a" "$0" >&2; exit 1 ;;
            *)     region="$a" ;;
        esac
    done

    print_banner
    check_dependencies
    resolve_context "$region"
    discover_services
    main_menu
}

main "$@"
