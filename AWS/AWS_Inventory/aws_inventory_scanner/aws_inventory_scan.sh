#!/usr/bin/env bash
#===============================================================================
#
#  aws_inventory_scan.sh
#
#  Author  : DevOps Engineering Team   (edit the AUTHOR variable below)
#  Version : 1.2.0
#  Date    : 2026-07-09
#
#  Deep inventory scan of an AWS account WITHOUT AWS Config, CloudTrail or
#  Resource Explorer - only plain read/list API calls through the AWS CLI.
#
#  Strategy (mirror of the GCP scanner):
#    1. Identify the caller (account + ARN) via STS.
#    2. Scan region by region (AWS has no per-project API enablement like
#       GCP, so REGIONS play the role that PROJECTS play in the GCP tool).
#    3. Run fast, targeted "sub-checks" with native aws CLI commands to
#       confirm whether high-value services actually have resources
#       deployed (EKS, SageMaker, Amplify, SNS/SQS, Lambda, EC2, RDS,
#       DynamoDB, ECS) plus GLOBAL services (S3, CloudFront).
#    4. Classify every service as:
#         - ACTIVE -> "Active with Resources / Usage Detected"
#         - EMPTY  -> "No Active Resources Found"
#    5. Emit a fully self-contained HTML dashboard with automatic dark
#       mode, tabbed navigation (one tab per region + Global), badges
#       and a key-metrics grid. Icons are written to an icons/ folder.
#
#  Usage:
#    chmod +x aws_inventory_scan.sh
#    ./aws_inventory_scan.sh                 # current region + Global (default)
#    ./aws_inventory_scan.sh --zip           # also package report+icons into a zip
#    ./aws_inventory_scan.sh --all           # every enabled region + Global
#    ./aws_inventory_scan.sh us-east-1 eu-west-1   # explicit regions + Global
#
#  Output:
#    ./aws_services_inventory.html  (+ icons/ folder)
#
#  Requirements:
#    - aws CLI v2 installed and credentials configured (aws configure / SSO)
#    - Read-only IAM permissions (see README notes at bottom of file)
#
#===============================================================================

set -u                    # Fail on unset variables (we handle errors manually)
set -o pipefail           # Propagate failures through pipes

#===============================================================================
# >>> EDITABLE CONFIGURATION SECTION <<<
#===============================================================================

# ------------------------------------------------------------------
# SCAN SCOPE
#   current - scan ONLY the region active in the AWS CLI config
#             (aws configure get region / $AWS_REGION). Default.
#   all     - scan every region enabled for the account
# Command line always wins:
#   ./aws_inventory_scan.sh                  -> uses SCAN_SCOPE below
#   ./aws_inventory_scan.sh --all            -> scan all enabled regions
#   ./aws_inventory_scan.sh us-east-1 ...    -> scan exactly these regions
# Global services (S3, CloudFront) are always scanned once, in their
# own "Global" tab, regardless of scope.
# ------------------------------------------------------------------
SCAN_SCOPE="current"

# Execution display mode:
#   auto  - TUI (pinned banner + in-place progress bar/spinner) when running
#           in an interactive terminal; plain scrolling logs otherwise
#   tui   - force the pinned-banner progress display
#   plain - force classic scrolling [INFO]/[ OK ] logs (best for CI pipelines)
PROGRESS_MODE="auto"

# Author name shown in the banner, the HTML report footer, and logs.
AUTHOR="DevOps Engineering Team"

# Script version (displayed in banner and report footer)
VERSION="1.2.0"

# Show every service by default. Set to "true" to hide services with
# no resources found (only Active rows will be rendered).
HIDE_EMPTY=false

# Automatically package the report + icons folder into a portable zip
# after every scan (same as passing --zip on the command line).
ZIP_REPORT=false

# HTML report output path
REPORT_FILE="aws_services_inventory.html"

# Folder (created next to the report) holding all icons/images referenced
# by the HTML. Keep this folder together with the HTML file when moving it.
ASSETS_DIR="icons"

# Per-command timeout in seconds (requires GNU coreutils `timeout`;
# gracefully skipped if unavailable, e.g. stock macOS).
CMD_TIMEOUT=45

#===============================================================================
# END OF EDITABLE CONFIGURATION
#===============================================================================

#-------------------------------------------------------------------------------
# Globals / counters
#-------------------------------------------------------------------------------
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S %Z')"
ACCOUNT_ID=""
CALLER_ARN=""
TMP_DIR="$(mktemp -d)"
TABS_BUTTONS_FILE="${TMP_DIR}/tabs_buttons.html"
TABS_PANELS_FILE="${TMP_DIR}/tabs_panels.html"
SUMMARY_ROWS_FILE="${TMP_DIR}/summary_rows.html"

TOTAL_REGIONS=0
TOTAL_CHECKS=0
TOTAL_ACTIVE=0
TOTAL_EMPTY=0

: > "${TABS_BUTTONS_FILE}"
: > "${TABS_PANELS_FILE}"
: > "${SUMMARY_ROWS_FILE}"

# --- TUI state ----------------------------------------------------------------
UI_TUI=false            # true when the pinned-banner progress display is active
UI_SCANNING=false       # true while the region loop owns the status area
SPIN_CHARS='-\|/'       # spinner frames (plain ASCII)
SPIN_IDX=0
CUR_IDX=0               # current region number
CUR_PCT=0               # overall progress percent
CUR_REGION=""           # current region name
WARN_COUNT=0
WARN_FILE="${TMP_DIR}/warnings.log"
: > "${WARN_FILE}"

# Clean up temp files and restore the terminal cursor on any exit
cleanup() {
  rm -rf "${TMP_DIR}"
  if [ "${UI_TUI}" = true ]; then
    printf '\033[?25h' >&2   # make sure the cursor is visible again
  fi
}
trap cleanup EXIT

#-------------------------------------------------------------------------------
# Logging helpers (stderr, so stdout stays clean)
#-------------------------------------------------------------------------------
log()  { printf '\033[0;36m[INFO]\033[0m  %s\n'  "$*" >&2; }
ok()   { printf '\033[0;32m[ OK ]\033[0m  %s\n'  "$*" >&2; }
warn() {
  # While the TUI status area is live, buffer warnings (count shown in the
  # status block) and print them after the scan so the banner never scrolls.
  if [ "${UI_TUI}" = true ] && [ "${UI_SCANNING}" = true ]; then
    WARN_COUNT=$((WARN_COUNT + 1))
    printf '%s\n' "$*" >> "${WARN_FILE}"
  else
    printf '\033[0;33m[WARN]\033[0m  %s\n' "$*" >&2
  fi
}
err()  { printf '\033[0;31m[FAIL]\033[0m  %s\n'  "$*" >&2; }

#-------------------------------------------------------------------------------
# print_banner
# Startup banner (plain ASCII characters only, ANSI colors for styling).
#-------------------------------------------------------------------------------
print_banner() {
  local C='\033[1;33m' B='\033[1;34m' D='\033[0;37m' R='\033[0m'
  printf '%b' "${C}" >&2
  cat >&2 <<'BANNER'
  ============================================================================
     ___ _       _______    ____                      _
    /   | |     / / ___/   /  _/___ _   _____  ____  / /_____  _______  __
   / /| | | /| / /\__ \    / // __ \ | / / _ \/ __ \/ __/ __ \/ ___/ / / /
  / ___ | |/ |/ /___/ /  _/ // / / / |/ /  __/ / / / /_/ /_/ / /  / /_/ /
 /_/  |_|__/|__//____/  /___/_/ /_/|___/\___/_/ /_/\__/\____/_/   \__, |
                                                                 /____/
BANNER
  printf '%b' "${R}" >&2
  printf '  %bDeep Services Inventory Scanner v%s%b  |  read-only  |  no AWS Config/CloudTrail\n' "${B}" "${VERSION}" "${R}" >&2
  printf '  %bAuthor: %s%b\n' "${D}" "${AUTHOR}" "${R}" >&2
  printf '  %bReport: %s  |  Icons: %s/  |  %s%b\n' \
    "${D}" "${REPORT_FILE}" "${ASSETS_DIR}" "${SCAN_DATE}" "${R}" >&2
  printf '%b  ============================================================================%b\n\n' "${C}" "${R}" >&2
}

#-------------------------------------------------------------------------------
# ui_init / ui_scan_start / ui_rewind / ui_draw / ui_finish
# Identical TUI engine to the GCP scanner: fixed 4-line status block redrawn
# in place with cursor-up repositioning, so the banner never scrolls away.
#-------------------------------------------------------------------------------
ui_init() {
  case "${PROGRESS_MODE}" in
    tui)   UI_TUI=true  ;;
    plain) UI_TUI=false ;;
    *)     if [ -t 2 ]; then UI_TUI=true; else UI_TUI=false; fi ;;
  esac
  if [ "${UI_TUI}" = true ]; then
    printf '\033[2J\033[H\033[?25l' >&2   # clear screen, home cursor, hide cursor
  fi
  print_banner
}

UI_BLOCK_LINES=4      # exact height of the status block drawn by ui_draw
UI_DRAWN=false        # whether a block is currently on screen

ui_scan_start() {
  UI_SCANNING=true
  UI_DRAWN=false
}

# ui_rewind: move the cursor back over the previous status block and erase it
ui_rewind() {
  if [ "${UI_DRAWN}" = true ]; then
    printf '\033[%dA\r\033[J' "${UI_BLOCK_LINES}" >&2
  fi
}

ui_draw() {
  local step="$1"
  if [ "${UI_TUI}" != true ]; then
    log "${step}"
    return
  fi
  # Truncate so a line can never wrap (would desync cursor repositioning)
  step="${step:0:58}"
  SPIN_IDX=$(( (SPIN_IDX + 1) % 4 ))
  local spin_char="${SPIN_CHARS:${SPIN_IDX}:1}"
  local width=32
  local filled=$(( CUR_PCT * width / 100 ))
  local bar_fill bar_rest
  bar_fill="$(printf '%*s' "${filled}" '' | tr ' ' '#')"
  bar_rest="$(printf '%*s' "$((width - filled))" '' | tr ' ' '.')"
  {
    ui_rewind
    printf '  \033[1;33m[%s%s]\033[0m \033[1m%3d%%\033[0m  %s\n' \
      "${bar_fill}" "${bar_rest}" "${CUR_PCT}" "${spin_char}"
    printf '  Region   : \033[1;34m%.40s\033[0m  (%d of %d)\n' \
      "${CUR_REGION}" "${CUR_IDX}" "${TOTAL_REGIONS}"
    printf '  Step     : %s\n' "${step}"
    printf '  Totals   : %d active | %d empty | %d warning(s)\n' \
      "${TOTAL_ACTIVE}" "${TOTAL_EMPTY}" "${WARN_COUNT}"
  } >&2
  UI_DRAWN=true
}

ui_finish() {
  if [ "${UI_TUI}" = true ]; then
    CUR_PCT=100
    local width=32 bar
    bar="$(printf '%*s' "${width}" '' | tr ' ' '#')"
    {
      ui_rewind
      printf '  \033[1;32m[%s]\033[0m \033[1m100%%\033[0m  done\n' "${bar}"
      printf '  Scan complete: %d region(s) | %d checks | %d active | %d empty\n\n' \
        "${TOTAL_REGIONS}" "${TOTAL_CHECKS}" "${TOTAL_ACTIVE}" "${TOTAL_EMPTY}"
      printf '\033[?25h'                  # show cursor again
    } >&2
    UI_DRAWN=false
  else
    ok "Scan complete: ${TOTAL_REGIONS} region(s) | ${TOTAL_CHECKS} checks | ${TOTAL_ACTIVE} active | ${TOTAL_EMPTY} empty"
  fi
  UI_SCANNING=false
  # Flush warnings collected while the status area was live
  if [ -s "${WARN_FILE}" ]; then
    local w
    while IFS= read -r w; do
      warn "${w}"
    done < "${WARN_FILE}"
  fi
}

#-------------------------------------------------------------------------------
# run_aws <args...>
# Wrapper that (a) applies a timeout when available, (b) disables the pager
# and (c) silences stderr so missing permissions or unsupported regions
# never break the loop. Empty string on any failure.
#-------------------------------------------------------------------------------
run_aws() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${CMD_TIMEOUT}s" aws --no-cli-pager "$@" 2>/dev/null || true
  else
    aws --no-cli-pager "$@" 2>/dev/null || true
  fi
}

#-------------------------------------------------------------------------------
# count_items <aws-text-output>
# The aws CLI with --output text separates list items with tabs/newlines
# and prints the literal word "None" for empty results. This normalizes
# that into a clean item count.
#-------------------------------------------------------------------------------
count_items() {
  printf '%s' "$1" | tr '\t' '\n' | grep -v '^None$' | grep -c . || true
}

#-------------------------------------------------------------------------------
# html_escape <string>  -> HTML-safe string on stdout
#-------------------------------------------------------------------------------
html_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
                         -e 's/"/\&quot;/g'
}

#-------------------------------------------------------------------------------
# Category registry: dynamic list of service-type tabs.
# CAT_ORDER preserves tab order; the associative arrays hold per-category
# row files and counters, keyed by category display name.
#-------------------------------------------------------------------------------
CAT_ORDER=()
declare -A CAT_INDEX=() CAT_TOTAL=() CAT_ACTIVE=() CAT_EMPTY=()

# cat_rows_file <category-name> -> echoes the rows file path (registers new
# categories on first use)
cat_rows_file() {
  local name="$1"
  if [ -z "${CAT_INDEX[${name}]+x}" ]; then
    CAT_ORDER+=("${name}")
    CAT_INDEX[${name}]=$(( ${#CAT_ORDER[@]} - 1 ))
    CAT_TOTAL[${name}]=0; CAT_ACTIVE[${name}]=0; CAT_EMPTY[${name}]=0
    : > "${TMP_DIR}/cat_${CAT_INDEX[${name}]}.html"
  fi
  printf '%s' "${TMP_DIR}/cat_${CAT_INDEX[${name}]}.html"
}

# register_categories_in_order: pre-registers categories so tab order is
# deterministic (registry order: regional first, then global)
register_categories_in_order() {
  local entry name
  for entry in "${REGIONAL_CHECKS[@]}" "${GLOBAL_CHECKS[@]}"; do
    name="${entry##*|}"
    cat_rows_file "${name}" >/dev/null
  done
}

#===============================================================================
# TARGETED RESOURCE SUB-CHECKS
# Each regional function takes <region>, prints "<count>|<human summary>"
# and always exits 0. Global functions take no region argument.
#===============================================================================

check_eks() {
  local region="$1" out count
  out="$(run_aws eks list-clusters --region "${region}" --query 'clusters' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} cluster(s)"
}

check_sagemaker() {
  local region="$1" ep models e m
  ep="$(run_aws sagemaker list-endpoints --region "${region}" --query 'Endpoints[].EndpointName' --output text)"
  models="$(run_aws sagemaker list-models --region "${region}" --query 'Models[].ModelName' --output text)"
  e="$(count_items "${ep}")"
  m="$(count_items "${models}")"
  printf '%s|%s' "$((e + m))" "${e} endpoint(s), ${m} model(s)"
}

check_amplify() {
  local region="$1" out count
  out="$(run_aws amplify list-apps --region "${region}" --query 'apps[].appId' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} Amplify app(s)"
}

check_sns_sqs() {
  local region="$1" topics queues t q
  topics="$(run_aws sns list-topics --region "${region}" --query 'Topics[].TopicArn' --output text)"
  queues="$(run_aws sqs list-queues --region "${region}" --query 'QueueUrls[]' --output text)"
  t="$(count_items "${topics}")"
  q="$(count_items "${queues}")"
  printf '%s|%s' "$((t + q))" "${t} SNS topic(s), ${q} SQS queue(s)"
}

check_lambda() {
  local region="$1" out count
  out="$(run_aws lambda list-functions --region "${region}" --query 'Functions[].FunctionName' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} function(s)"
}

check_ec2() {
  local region="$1" out count
  # Count every non-terminated instance (running, stopped, pending, stopping)
  out="$(run_aws ec2 describe-instances --region "${region}" \
        --filters 'Name=instance-state-name,Values=pending,running,stopping,stopped' \
        --query 'Reservations[].Instances[].InstanceId' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} EC2 instance(s) (non-terminated)"
}

check_rds() {
  local region="$1" out count
  out="$(run_aws rds describe-db-instances --region "${region}" \
        --query 'DBInstances[].DBInstanceIdentifier' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} DB instance(s)"
}

check_dynamodb() {
  local region="$1" out count
  out="$(run_aws dynamodb list-tables --region "${region}" --query 'TableNames[]' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} table(s)"
}

check_ecs() {
  local region="$1" out count
  out="$(run_aws ecs list-clusters --region "${region}" --query 'clusterArns[]' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} ECS cluster(s)"
}

# ---- Global (region-less) checks ----------------------------------------------

check_s3() {
  local out count
  out="$(run_aws s3api list-buckets --query 'Buckets[].Name' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} bucket(s)"
}

check_cloudfront() {
  local out count
  out="$(run_aws cloudfront list-distributions --query 'DistributionList.Items[].Id' --output text)"
  count="$(count_items "${out}")"
  printf '%s|%s' "${count}" "${count} distribution(s)"
}

#-------------------------------------------------------------------------------
# Sub-check registries: "cli-namespace|check function|pretty label"
# To add a new deep check: write a check_x function above and add a row here.
#-------------------------------------------------------------------------------
# shellcheck disable=SC2034  # consumed via nameref in run_checks
# Format: "cli-namespace|check function|pretty label|Service Category"
# The report tabs are grouped by the Service Category column.
REGIONAL_CHECKS=(
  "eks|check_eks|Amazon EKS (Kubernetes)|Compute & Containers"
  "ec2|check_ec2|Amazon EC2 (Compute)|Compute & Containers"
  "ecs|check_ecs|Amazon ECS (Containers)|Compute & Containers"
  "sagemaker|check_sagemaker|Amazon SageMaker (AI/ML)|AI & Machine Learning"
  "lambda|check_lambda|AWS Lambda|Serverless"
  "sns+sqs|check_sns_sqs|SNS / SQS (Messaging)|Messaging & Integration"
  "rds|check_rds|Amazon RDS (Databases)|Databases"
  "dynamodb|check_dynamodb|Amazon DynamoDB|Databases"
  "amplify|check_amplify|AWS Amplify|Web & Mobile"
)

# shellcheck disable=SC2034  # consumed via nameref in run_checks
GLOBAL_CHECKS=(
  "s3|check_s3|Amazon S3 (Storage)|Storage & CDN"
  "cloudfront|check_cloudfront|Amazon CloudFront (CDN)|Storage & CDN"
)

#===============================================================================
# HTML GENERATION
#===============================================================================

#-------------------------------------------------------------------------------
# write_assets
# Generates every icon/image used by the report into ${ASSETS_DIR}/ as small
# standalone SVG files. The HTML references them with <img src="..."> tags,
# so no icon fonts, emojis, or inline glyphs are used anywhere.
#-------------------------------------------------------------------------------
write_assets() {
  mkdir -p "${ASSETS_DIR}"

  # Report logo: generic cloud mark (AWS orange gradient)
  cat > "${ASSETS_DIR}/logo-cloud.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="48" height="48">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#f59e0b"/><stop offset="1" stop-color="#d97706"/>
  </linearGradient></defs>
  <path fill="url(#g)" d="M37 21.2A11.5 11.5 0 0 0 15.4 18 9.5 9.5 0 0 0 16 37h20a8 8 0 0 0 1-15.8z"/>
  <circle cx="20" cy="28" r="2.4" fill="#ffffff" opacity=".9"/>
  <circle cx="28" cy="28" r="2.4" fill="#ffffff" opacity=".9"/>
  <path d="M20 28h8" stroke="#ffffff" stroke-width="1.6" opacity=".9"/>
</svg>
SVG

  # Status: active with resources (green check in filled circle)
  cat > "${ASSETS_DIR}/status-active.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
  <circle cx="8" cy="8" r="7" fill="#10b981"/>
  <path d="M4.8 8.2l2.2 2.2 4.2-4.6" fill="none" stroke="#ffffff" stroke-width="1.8"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>
SVG

  # Status: no resources found (amber half-filled circle)
  cat > "${ASSETS_DIR}/status-empty.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
  <circle cx="8" cy="8" r="6.2" fill="none" stroke="#f59e0b" stroke-width="1.6"/>
  <path d="M8 1.8a6.2 6.2 0 0 1 0 12.4z" fill="#f59e0b"/>
</svg>
SVG

  # Metric: regions scanned (globe)
  cat > "${ASSETS_DIR}/metric-regions.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <g fill="none" stroke="#3b82f6" stroke-width="1.8">
    <circle cx="12" cy="12" r="8.5"/>
    <ellipse cx="12" cy="12" rx="3.8" ry="8.5"/>
    <path d="M3.8 12h16.4M4.9 7.5h14.2M4.9 16.5h14.2"/>
  </g>
</svg>
SVG

  # Metric: services checked (grid)
  cat > "${ASSETS_DIR}/metric-checks.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <g fill="none" stroke="#8b5cf6" stroke-width="1.8" stroke-linejoin="round">
    <rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/>
    <rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/>
    <rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/>
    <rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>
  </g>
</svg>
SVG

  # Metric: active resource services (bolt)
  cat > "${ASSETS_DIR}/metric-active.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <path fill="#10b981" d="M13 2L4.5 13.5H11L9.8 22l8.7-11.5H12z"/>
</svg>
SVG

  # Metric: empty services (outline circle)
  cat > "${ASSETS_DIR}/metric-empty.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <circle cx="12" cy="12" r="8.5" fill="none" stroke="#94a3b8" stroke-width="1.8"/>
  <path d="M8 12h8" stroke="#94a3b8" stroke-width="1.8" stroke-linecap="round"/>
</svg>
SVG

  ok "Icon assets written to ${ASSETS_DIR}/ (7 SVG files)"
}

write_html_header() {
  # Heredoc with quoted delimiter: nothing inside is expanded by Bash.
  cat > "${REPORT_FILE}" <<'HTML_HEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Services Inventory</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#f8fafc; --surface:#ffffff; --surface-2:#f1f5f9;
    --text:#0f172a; --text-muted:#64748b; --border:#e2e8f0;
    --accent:#d97706; --accent-soft:#fef3c7;
    --green:#059669; --green-bg:#d1fae5;
    --amber:#b45309; --amber-bg:#fef3c7;
    --gray:#475569;  --gray-bg:#e2e8f0;
    --shadow:0 1px 3px rgba(15,23,42,.08),0 4px 14px rgba(15,23,42,.05);
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0f172a; --surface:#1e293b; --surface-2:#293548;
      --text:#f1f5f9; --text-muted:#94a3b8; --border:#334155;
      --accent:#fbbf24; --accent-soft:#453411;
      --green:#34d399; --green-bg:#064e3b;
      --amber:#fbbf24; --amber-bg:#453411;
      --gray:#cbd5e1;  --gray-bg:#334155;
      --shadow:0 1px 3px rgba(0,0,0,.4),0 4px 14px rgba(0,0,0,.3);
    }
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);
       font-family:'Inter',system-ui,-apple-system,sans-serif;
       font-size:15px;line-height:1.55;padding:32px 20px 80px}
  .wrap{max-width:1180px;margin:0 auto}
  header.hero{margin-bottom:28px}
  .hero h1{font-size:26px;font-weight:800;letter-spacing:-.02em}
  .hero p{color:var(--text-muted);margin-top:4px;font-size:14px}
  .hero code{font-family:'JetBrains Mono',monospace;font-size:13px;
             background:var(--surface-2);padding:2px 7px;border-radius:6px}
  .hero-row{display:flex;align-items:center;gap:14px}
  .hero-row img{width:44px;height:44px}

  /* --- key metrics grid --- */
  .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));
           gap:14px;margin:22px 0 30px}
  .metric{background:var(--surface);border:1px solid var(--border);
          border-radius:14px;padding:18px 20px;box-shadow:var(--shadow)}
  .metric img{width:24px;height:24px;margin-bottom:8px;display:block}
  .metric .num{font-size:30px;font-weight:800;letter-spacing:-.03em}
  .metric .lbl{color:var(--text-muted);font-size:12.5px;font-weight:600;
               text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
  .metric.m-active .num{color:var(--green)}
  .metric.m-empty .num{color:var(--text-muted)}

  /* --- tabs --- */
  .tabbar{display:flex;flex-wrap:wrap;gap:8px;border-bottom:1px solid var(--border);
          padding-bottom:10px;margin-bottom:22px}
  .tabbar button{font:inherit;font-weight:600;font-size:13.5px;cursor:pointer;
          color:var(--text-muted);background:transparent;border:1px solid transparent;
          padding:7px 14px;border-radius:9px;transition:all .15s ease}
  .tabbar button:hover{background:var(--surface-2);color:var(--text)}
  .tabbar button.active{background:var(--accent-soft);color:var(--accent);
          border-color:var(--accent)}
  .panel{display:none;animation:fade .18s ease}
  .panel.active{display:block}
  @keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

  /* --- tables --- */
  .card{background:var(--surface);border:1px solid var(--border);
        border-radius:14px;box-shadow:var(--shadow);overflow:hidden;margin-bottom:22px}
  .card h2{font-size:16px;font-weight:700;padding:16px 20px;
           border-bottom:1px solid var(--border)}
  .card h2 small{color:var(--text-muted);font-weight:500;font-size:13px;margin-left:8px}
  table{width:100%;border-collapse:collapse;font-size:14px}
  th{background:var(--surface-2);color:var(--text-muted);text-align:left;
     font-size:11.5px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
     padding:10px 20px}
  td{padding:11px 20px;border-top:1px solid var(--border);vertical-align:middle}
  td.api{font-family:'JetBrains Mono',monospace;font-size:13px}
  tr:hover td{background:var(--surface-2)}

  /* --- badges --- */
  .badge{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;
         font-weight:700;padding:4px 10px;border-radius:999px;white-space:nowrap}
  .badge img{width:12px;height:12px;display:block}
  .b-active{color:var(--green);background:var(--green-bg)}
  .b-empty{color:var(--amber);background:var(--amber-bg)}
  .detail{color:var(--text-muted);font-size:13px}
  .projlink{color:var(--accent);cursor:pointer;font-weight:600;
            background:none;border:none;font:inherit;padding:0}
  .projlink:hover{text-decoration:underline}
  footer{margin-top:34px;color:var(--text-muted);font-size:12.5px;text-align:center}
</style>
</head>
<body>
<div class="wrap">
HTML_HEAD
}

write_html_footer() {
  cat >> "${REPORT_FILE}" <<'HTML_FOOT'
</div><!-- /wrap -->
<script>
  // Lightweight pure-JS tab switcher
  function showTab(id, btn){
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tabbar button').forEach(b => b.classList.remove('active'));
    var panel = document.getElementById(id);
    if (panel) panel.classList.add('active');
    if (btn) {
      btn.classList.add('active');
    } else {
      var match = document.querySelector('.tabbar button[data-target="'+id+'"]');
      if (match) match.classList.add('active');
    }
    window.scrollTo({top:0, behavior:'smooth'});
  }
  document.querySelectorAll('.tabbar button').forEach(function(b){
    b.addEventListener('click', function(){ showTab(b.dataset.target, b); });
  });
</script>
</body>
</html>
HTML_FOOT
}

#===============================================================================
# SCAN LOGIC
#===============================================================================

#-------------------------------------------------------------------------------
# run_checks <tab_label> <checks_array_name> [region]
# Executes every check in the given registry, appends its row (with the
# region column) to the matching CATEGORY rows file, appends the per-region
# summary row, and rolls up the global and per-category counters.
#-------------------------------------------------------------------------------
run_checks() {
  local tab_label="$1" checks_name="$2" region="${3:-}"
  local esc_label; esc_label="$(html_escape "${tab_label}")"
  local r_total=0 r_active=0 r_empty=0

  # Indirect expansion of the registry array by name
  local -n checks_ref="${checks_name}"

  local entry ns fn label category crows_file res count summary
  for entry in "${checks_ref[@]}"; do
    ns="${entry%%|*}"
    fn="$(printf '%s' "${entry}" | cut -d'|' -f2)"
    label="$(printf '%s' "${entry}" | cut -d'|' -f3)"
    category="${entry##*|}"
    crows_file="$(cat_rows_file "${category}")"
    ui_draw "Sub-check: ${label}"

    if [ -n "${region}" ]; then
      res="$("${fn}" "${region}")"
    else
      res="$("${fn}")"
    fi
    count="${res%%|*}"
    summary="${res#*|}"
    r_total=$((r_total + 1))
    CAT_TOTAL[${category}]=$(( CAT_TOTAL[${category}] + 1 ))

    local esc_ns esc_lbl esc_sum
    esc_ns="$(html_escape "${ns}")"
    esc_lbl="$(html_escape "${label}")"
    esc_sum="$(html_escape "${summary}")"

    if [ "${count}" -gt 0 ] 2>/dev/null; then
      r_active=$((r_active + 1))
      CAT_ACTIVE[${category}]=$(( CAT_ACTIVE[${category}] + 1 ))
      printf '<tr><td>%s</td><td class="api">%s</td><td>%s</td><td><span class="badge b-active"><img src="'"${ASSETS_DIR}"'/status-active.svg" alt="">Active with Resources</span></td><td class="detail">%s</td></tr>\n' \
        "${esc_label}" "${esc_ns}" "${esc_lbl}" "${esc_sum}" >> "${crows_file}"
    else
      r_empty=$((r_empty + 1))
      CAT_EMPTY[${category}]=$(( CAT_EMPTY[${category}] + 1 ))
      if [ "${HIDE_EMPTY}" != "true" ]; then
        printf '<tr><td>%s</td><td class="api">%s</td><td>%s</td><td><span class="badge b-empty"><img src="'"${ASSETS_DIR}"'/status-empty.svg" alt="">No Active Resources Found</span></td><td class="detail">%s</td></tr>\n' \
          "${esc_label}" "${esc_ns}" "${esc_lbl}" "${esc_sum}" >> "${crows_file}"
      fi
    fi
  done

  # Executive summary row (per-region rollup)
  printf '<tr><td>%s</td><td>%d</td><td><span class="badge b-active">%d</span></td><td><span class="badge b-empty">%d</span></td></tr>\n' \
    "${esc_label}" "${r_total}" "${r_active}" "${r_empty}" \
    >> "${SUMMARY_ROWS_FILE}"

  # Global counters
  TOTAL_CHECKS=$((TOTAL_CHECKS + r_total))
  TOTAL_ACTIVE=$((TOTAL_ACTIVE + r_active))
  TOTAL_EMPTY=$((TOTAL_EMPTY + r_empty))

  ui_draw "Done: ${r_total} checks, ${r_active} active, ${r_empty} empty"
}

#-------------------------------------------------------------------------------
# make_report_zip
# Packages the HTML report together with the icons folder into a single
# portable zip that can be downloaded, emailed and opened anywhere.
#-------------------------------------------------------------------------------
make_report_zip() {
  local zip_file="${REPORT_FILE%.*}.zip"
  if ! command -v zip >/dev/null 2>&1; then
    warn "zip command not found - skipping report packaging (install: apt/yum/brew install zip)"
    return 0
  fi
  rm -f "${zip_file}"
  if zip -r "${zip_file}" "${REPORT_FILE}" "${ASSETS_DIR}" >/dev/null 2>&1; then
    ok "Portable report package: ${zip_file}  (HTML + ${ASSETS_DIR}/ folder)"
  else
    warn "Could not create ${zip_file}"
  fi
}

#===============================================================================
# MAIN
#===============================================================================
main() {
  # ---- Argument pre-parse: extract flags, keep the rest for scope logic --------
  local MAKE_ZIP="${ZIP_REPORT}"
  local ARGS=() a
  for a in "$@"; do
    case "${a}" in
      --zip) MAKE_ZIP=true ;;
      *)     ARGS+=("${a}") ;;
    esac
  done
  set -- ${ARGS[@]+"${ARGS[@]}"}

  ui_init
  log "AWS Deep Inventory Scan - starting"

  # ---- Preflight checks --------------------------------------------------------
  if ! command -v aws >/dev/null 2>&1; then
    err "aws CLI not found in PATH. Install the AWS CLI v2 first."
    exit 1
  fi

  ACCOUNT_ID="$(run_aws sts get-caller-identity --query 'Account' --output text)"
  CALLER_ARN="$(run_aws sts get-caller-identity --query 'Arn' --output text)"
  if [ -z "${ACCOUNT_ID}" ] || [ "${ACCOUNT_ID}" = "None" ]; then
    err "No valid AWS credentials found. Run: aws configure  (or aws sso login)"
    exit 1
  fi
  ok "Authenticated: account ${ACCOUNT_ID} (${CALLER_ARN})"

  # ---- Region discovery (scope-aware) -----------------------------------------
  local regions=""
  if [ "$#" -gt 0 ] && [ "$1" != "--all" ]; then
    regions="$(printf '%s\n' "$@")"
    log "Scope: explicit region list from command line"
  elif [ "${1:-}" = "--all" ] || [ "${SCAN_SCOPE}" = "all" ]; then
    log "Scope: ALL regions enabled for this account"
    log "Discovering enabled regions..."
    regions="$(run_aws ec2 describe-regions --query 'Regions[].RegionName' --output text | tr '\t' '\n')"
    if [ -z "${regions}" ]; then
      err "Could not list regions (ec2:DescribeRegions denied?)."
      exit 1
    fi
  else
    # Default: only the region currently active in the AWS CLI config/env
    regions="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
    if [ -z "${regions}" ]; then
      regions="$(run_aws configure get region)"
    fi
    if [ -z "${regions}" ] || [ "${regions}" = "None" ]; then
      err "No current region set in the AWS CLI config."
      err "Fix with: aws configure set region REGION   (e.g. us-east-1)"
      err "Or scan everything with: $0 --all"
      exit 1
    fi
    log "Scope: current region only (${regions})"
  fi

  TOTAL_REGIONS="$(printf '%s' "${regions}" | grep -c . || true)"
  ok "Found ${TOTAL_REGIONS} region(s) to scan (+ Global services)"

  # ---- Scan loop -----------------------------------------------------------------
  register_categories_in_order
  ui_scan_start
  local idx=0 region
  while IFS= read -r region; do
    [ -z "${region}" ] && continue
    idx=$((idx + 1))
    CUR_IDX="${idx}"
    CUR_REGION="${region}"
    CUR_PCT=$(( (idx - 1) * 100 / (TOTAL_REGIONS + 1) ))
    run_checks "${region}" REGIONAL_CHECKS "${region}"
  done <<< "${regions}"

  # ---- Global services tab ---------------------------------------------------------
  CUR_IDX=$((TOTAL_REGIONS + 1))
  CUR_REGION="global"
  CUR_PCT=$(( TOTAL_REGIONS * 100 / (TOTAL_REGIONS + 1) ))
  run_checks "Global" GLOBAL_CHECKS ""
  ui_finish

  # ---- Assemble the final HTML ------------------------------------------------------
  log "Writing icon assets and building HTML dashboard: ${REPORT_FILE}"
  write_assets
  write_html_header

  {
    # Hero
    printf '<header class="hero"><div class="hero-row"><img src="%s/logo-cloud.svg" alt="AWS Inventory logo"><h1>AWS Services Inventory</h1></div>' "${ASSETS_DIR}"
    printf '<p>Deep resource scan | %s | account <code>%s</code> | AWS Config / CloudTrail <strong>not</strong> used</p></header>\n' \
      "$(html_escape "${SCAN_DATE}")" "$(html_escape "${ACCOUNT_ID}")"

    # Metrics grid
    printf '<div class="metrics">\n'
    printf '<div class="metric"><img src="%s/metric-regions.svg" alt=""><div class="num">%d</div><div class="lbl">Regions Scanned</div></div>\n' "${ASSETS_DIR}" "${TOTAL_REGIONS}"
    printf '<div class="metric"><img src="%s/metric-checks.svg" alt=""><div class="num">%d</div><div class="lbl">Services Checked</div></div>\n' "${ASSETS_DIR}" "${TOTAL_CHECKS}"
    printf '<div class="metric m-active"><img src="%s/metric-active.svg" alt=""><div class="num">%d</div><div class="lbl">Active Resource Services</div></div>\n' "${ASSETS_DIR}" "${TOTAL_ACTIVE}"
    printf '<div class="metric m-empty"><img src="%s/metric-empty.svg" alt=""><div class="num">%d</div><div class="lbl">No Resources Found</div></div>\n' "${ASSETS_DIR}" "${TOTAL_EMPTY}"
    printf '</div>\n'

    # Build category tab buttons + panels (skip categories with no rows)
    local ci cname cid crf
    for ci in "${!CAT_ORDER[@]}"; do
      cname="${CAT_ORDER[${ci}]}"
      [ "${CAT_TOTAL[${cname}]:-0}" -eq 0 ] && continue
      cid="cat-${ci}"
      crf="${TMP_DIR}/cat_${ci}.html"
      printf '<button data-target="%s">%s</button>\n' "${cid}" "$(html_escape "${cname}")" \
        >> "${TABS_BUTTONS_FILE}"
      {
        printf '<section class="panel" id="%s">\n' "${cid}"
        printf '<div class="card"><h2>%s <small>%d checks | %d active | %d empty</small></h2>\n' \
          "$(html_escape "${cname}")" "${CAT_TOTAL[${cname}]}" \
          "${CAT_ACTIVE[${cname}]}" "${CAT_EMPTY[${cname}]}"
        printf '<table><thead><tr><th>Region</th><th>Service</th><th>Deep Check</th><th>Status</th><th>Details</th></tr></thead><tbody>\n'
        cat "${crf}"
        printf '</tbody></table></div></section>\n'
      } >> "${TABS_PANELS_FILE}"
    done

    # Tab bar (Executive Summary + one button per SERVICE CATEGORY)
    printf '<nav class="tabbar"><button class="active" data-target="summary">Executive Summary</button>\n'
    cat "${TABS_BUTTONS_FILE}"
    printf '</nav>\n'

    # Executive summary panel: category rollup + region rollup
    printf '<section class="panel active" id="summary">\n'

    printf '<div class="card"><h2>Services by Category <small>click a category to open its tab</small></h2>\n'
    printf '<table><thead><tr><th>Category</th><th>Checks</th><th>Active w/ Resources</th><th>No Resources</th></tr></thead><tbody>\n'
    for ci in "${!CAT_ORDER[@]}"; do
      cname="${CAT_ORDER[${ci}]}"
      [ "${CAT_TOTAL[${cname}]:-0}" -eq 0 ] && continue
      printf '<tr><td><button class="projlink" onclick="showTab(%s)">%s</button></td><td>%d</td><td><span class="badge b-active">%d</span></td><td><span class="badge b-empty">%d</span></td></tr>\n' \
        "'cat-${ci}'" "$(html_escape "${cname}")" "${CAT_TOTAL[${cname}]}" \
        "${CAT_ACTIVE[${cname}]}" "${CAT_EMPTY[${cname}]}"
    done
    printf '</tbody></table></div>\n'

    printf '<div class="card"><h2>Regions <small>per-region rollup</small></h2>\n'
    printf '<table><thead><tr><th>Region</th><th>Services Checked</th><th>Active w/ Resources</th><th>No Resources</th></tr></thead><tbody>\n'
    cat "${SUMMARY_ROWS_FILE}"
    printf '</tbody></table></div>\n'

    printf '</section>\n'

    # Category detail panels
    cat "${TABS_PANELS_FILE}"

    printf '<footer>Generated by aws_inventory_scan.sh v%s | Author: %s | read-only scan | no AWS Config or CloudTrail used</footer>\n' \
      "$(html_escape "${VERSION}")" "$(html_escape "${AUTHOR}")"
  } >> "${REPORT_FILE}"

  write_html_footer

  ok "Report ready: ${REPORT_FILE}"
  ok "Open it in any browser - dark mode follows your OS preference automatically."
  ok "NOTE: keep the ${ASSETS_DIR}/ folder next to the HTML file (it holds the icons)."

  if [ "${MAKE_ZIP}" = true ]; then
    make_report_zip
  fi
}

main "$@"

#===============================================================================
# MINIMUM IAM PERMISSIONS (reference)
#===============================================================================
# Simplest options: attach the AWS-managed policy `ReadOnlyAccess` (broad)
# or `SecurityAudit` / `ViewOnlyAccess` (narrower) to the user/role.
#
# Least-privilege alternative (custom policy, Allow on "*"):
#   sts:GetCallerIdentity          -> account identification
#   ec2:DescribeRegions            -> region discovery (--all mode only)
#   eks:ListClusters               -> EKS sub-check
#   sagemaker:ListEndpoints
#   sagemaker:ListModels           -> SageMaker sub-check
#   amplify:ListApps               -> Amplify sub-check
#   sns:ListTopics
#   sqs:ListQueues                 -> Messaging sub-check
#   lambda:ListFunctions           -> Lambda sub-check
#   ec2:DescribeInstances          -> EC2 sub-check
#   rds:DescribeDBInstances        -> RDS sub-check
#   dynamodb:ListTables            -> DynamoDB sub-check
#   ecs:ListClusters               -> ECS sub-check
#   s3:ListAllMyBuckets            -> S3 sub-check (global)
#   cloudfront:ListDistributions   -> CloudFront sub-check (global)
#
# Explicitly NOT required: AWS Config, CloudTrail, Resource Explorer,
# or any write permission. The scan is 100% read-only.
#===============================================================================
