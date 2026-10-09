#!/usr/bin/env bash
#===============================================================================
#
#  gcp_inventory_scan.sh
#
#  Author  : DevOps Engineering Team   (edit the AUTHOR variable below)
#  Version : 1.7.0   (current-project scope + multi-region identification)
#  Date    : 2026-07-09
#
#  Deep inventory scan of the CURRENT gcloud project WITHOUT using
#  Cloud Asset Inventory (no cloudasset.assets.* permissions required).
#
#  Strategy:
#    1. Resolve the single project active in the gcloud config
#       (gcloud config get-value project).
#    2. List enabled APIs per project (serviceusage.services.list).
#    3. Run fast, targeted "sub-checks" with native gcloud commands to
#       confirm whether high-value services actually have resources
#       deployed (GKE, Vertex AI, Firebase, Pub/Sub, Cloud Functions,
#       Compute Engine, Cloud Storage, Cloud Run, Cloud SQL).
#    4. MULTI-REGION IDENTIFICATION: every sub-check records the region,
#       zone or location of each resource it finds (Vertex AI is probed
#       across all major regions). The report shows exactly which
#       regions of the project are in use and by which services.
#    5. Classify every service as:
#         - ACTIVE   -> "Active with Resources / Usage Detected"
#         - PASSIVE  -> "Enabled (No Active Resources Found)"
#         - ENABLED  -> Enabled, but no deep sub-check exists for it
#    6. Emit a fully self-contained HTML dashboard with automatic dark
#       mode, tabbed navigation, badges and a key-metrics grid.
#
#  Usage:
#    chmod +x gcp_inventory_scan.sh
#    ./gcp_inventory_scan.sh           # scans ONLY the current gcloud project
#    ./gcp_inventory_scan.sh --zip     # also package report+icons into a zip
#
#  Output:
#    ./gcp_services_inventory.html
#
#  Requirements:
#    - gcloud CLI installed and authenticated (gcloud auth login)
#    - Read-only IAM permissions (see README notes at bottom of file)
#
#===============================================================================

set -u                    # Fail on unset variables (we handle errors manually)
set -o pipefail           # Propagate failures through pipes

#===============================================================================
# >>> EDITABLE CONFIGURATION SECTION <<<
#===============================================================================

# ------------------------------------------------------------------
# API BASELINE LIST (regex fragments, matched with grep -E against the
# API name, e.g. "compute.googleapis.com").
# These are internal / baseline Google APIs that are enabled on almost
# every project by default and do not represent direct, user-initiated
# business consumption.
#
# BEHAVIOR: matching APIs are NOT hidden — every enabled service gets
# a row in the report. Matches are simply tagged with a muted
# "System / Baseline" badge and counted in the "System Services"
# metric, so nothing is ever missing from the inventory.
# Set HIDE_BASELINE=true below to suppress them again if needed.
# ------------------------------------------------------------------
API_BLACKLIST=(
  "serviceusage\.googleapis\.com"
  "servicemanagement\.googleapis\.com"
  "servicenetworking\.googleapis\.com"
  "cloudresourcemanager\.googleapis\.com"
  "cloudapis\.googleapis\.com"
  "iam\.googleapis\.com"
  "iamcredentials\.googleapis\.com"
  "sts\.googleapis\.com"
  "storage-api\.googleapis\.com"        # Legacy JSON API alias
  "storage-component\.googleapis\.com"  # Legacy component alias
  "bigquerymigration\.googleapis\.com"
  "bigquerystorage\.googleapis\.com"
  "datastore\.googleapis\.com"          # Auto-enabled alongside Firestore
  "analyticshub\.googleapis\.com"
  "dataform\.googleapis\.com"
  "dataplex\.googleapis\.com"
)

# ------------------------------------------------------------------
# VERTEX AI REGIONS
# `gcloud ai ...` commands are regional. For multi-region identification
# we probe the major Vertex AI regions below. Each region adds ~2-4
# seconds to the scan; trim the list if you only use specific regions.
# ------------------------------------------------------------------
VERTEX_REGIONS=(
  "us-central1" "us-east1" "us-east4" "us-west1" "us-west4"
  "northamerica-northeast1" "southamerica-east1"
  "europe-west1" "europe-west2" "europe-west3" "europe-west4"
  "asia-east1" "asia-northeast1" "asia-southeast1" "australia-southeast1"
)

# Author name shown in the banner, the HTML report footer, and logs.
AUTHOR="DevOps Engineering Team"

# Script version (displayed in banner and report footer)
VERSION="1.7.0"

# ------------------------------------------------------------------
# SCAN SCOPE
# This script scans ONLY the project currently active in the gcloud
# config (gcloud config get-value project). To scan a different
# project, switch first:  gcloud config set project PROJECT_ID
# ------------------------------------------------------------------

# Execution display mode:
#   auto  - TUI (pinned banner + in-place progress bar/spinner) when running
#           in an interactive terminal; plain scrolling logs otherwise
#   tui   - force the pinned-banner progress display
#   plain - force classic scrolling [INFO]/[ OK ] logs (best for CI pipelines)
PROGRESS_MODE="auto"

# ------------------------------------------------------------------
# SERVICE CATEGORY RULES (regex fragment | Category name)
# The report groups its tabs by TYPE OF SERVICE: every API is assigned
# to the first category whose regex matches its name. APIs matching the
# baseline list above always go to "System / Baseline". Anything that
# matches no rule lands in "Other Services". Edit and reorder freely -
# first match wins, and tab order follows the order of first appearance
# of each category name in this list.
# ------------------------------------------------------------------
CATEGORY_RULES=(
  "container\.|gkehub|gkebackup|anthos|run\.googleapis|appengine|compute\.googleapis|osconfig|oslogin|batch\.|autoscaling|vm|artifactregistry|containerregistry|containeranalysis|binaryauthorization|Compute & Containers"
  "aiplatform|generativelanguage|gemini|notebooks|ml\.googleapis|speech|vision|translate|language\.googleapis|documentai|videointelligence|dialogflow|recommendations|AI & Machine Learning"
  "storage\.googleapis|storagetransfer|filestore|backupdr|Storage"
  "sqladmin|sql-component|spanner|firestore|bigtable|redis|memcache|alloydb|Databases"
  "pubsub|eventarc|cloudtasks|cloudscheduler|workflows|integrations|Messaging & Integration"
  "cloudfunctions|Serverless"
  "bigquery|dataflow|dataproc|composer|datacatalog|datafusion|datastream|looker|analytics|Data & Analytics"
  "firebase|fcm|identitytoolkit|firestore|appdistribution|testlab|Firebase & Mobile"
  "dns\.|networkservices|networkconnectivity|networksecurity|vpcaccess|servicedirectory|loadbalanc|cdn|interconnect|edgecache|Networking"
  "kms|secretmanager|securitycenter|websecurityscanner|accesscontextmanager|certificatemanager|privateca|recaptcha|Identity & Security"
  "logging|monitoring|cloudtrace|cloudprofiler|clouderrorreporting|opsconfig|Operations & Monitoring"
)
# NOTE on the format: everything up to the LAST pipe is the regex
# (alternatives separated by |); the text after the last pipe is the
# category display name.

# Show every service by default. Set to "true" to hide baseline APIs.
HIDE_BASELINE=false

# Automatically package the report + icons folder into a portable zip
# after every scan (same as passing --zip on the command line).
ZIP_REPORT=false

# HTML report output path
REPORT_FILE="gcp_services_inventory.html"

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
ACTIVE_ACCOUNT=""
TMP_DIR="$(mktemp -d)"
TABS_BUTTONS_FILE="${TMP_DIR}/tabs_buttons.html"
TABS_PANELS_FILE="${TMP_DIR}/tabs_panels.html"
SUMMARY_ROWS_FILE="${TMP_DIR}/summary_rows.html"

TOTAL_PROJECTS=0
TOTAL_APIS=0
TOTAL_ACTIVE=0
TOTAL_PASSIVE=0
TOTAL_FILTERED=0
TOTAL_REGIONS=0

# --- Multi-region tracking ------------------------------------------------------
# Every sub-check records "region|service-label" lines here (a file is used
# because sub-checks run inside $(...) subshells where variables don't persist).
REGIONS_FILE="${TMP_DIR}/regions.log"
REGION_ROWS_FILE="${TMP_DIR}/region_rows.html"
: > "${REGIONS_FILE}"
: > "${REGION_ROWS_FILE}"

# note_region <region-or-location> <service-label>
# Records that <service-label> has at least one resource in <region>.
note_region() {
  local r="$1" lbl="$2"
  [ -z "${r}" ] && return 0
  r="$(printf '%s' "${r}" | tr 'A-Z' 'a-z')"
  printf '%s|%s\n' "${r}" "${lbl}" >> "${REGIONS_FILE}"
}

# zone_to_region <zone-or-region> -> region on stdout
# Zones end in "-<single letter>" (us-central1-a); regions do not.
zone_to_region() {
  case "$1" in
    *-[a-z]) printf '%s' "${1%-*}" ;;
    *)       printf '%s' "$1" ;;
  esac
}

# join_unique: stdin lines -> deduped, comma-separated list on stdout
join_unique() {
  sort -u | grep -v '^$' | paste -sd',' - 2>/dev/null | sed 's/,/, /g'
}

: > "${TABS_BUTTONS_FILE}"
: > "${TABS_PANELS_FILE}"
: > "${SUMMARY_ROWS_FILE}"

# --- TUI state ----------------------------------------------------------------
UI_TUI=false            # true when the pinned-banner progress display is active
UI_SCANNING=false       # true while the project loop owns the status area
SPIN_CHARS='-\|/'       # spinner frames (plain ASCII)
SPIN_IDX=0
CUR_IDX=0               # current project number
CUR_PCT=0               # overall progress percent
CUR_PROJ=""             # current project id
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
# Written to stderr like all other execution output.
#-------------------------------------------------------------------------------
print_banner() {
  local C='\033[1;36m' B='\033[1;34m' D='\033[0;37m' R='\033[0m'
  printf '%b' "${C}" >&2
  cat >&2 <<'BANNER'
  ============================================================================
    ____  ____ ____    ___                      _
   / ___|/ ___|  _ \  |_ _|_ ____   _____ _ __ | |_ ___  _ __ _   _
  | |  _| |   | |_) |  | || '_ \ \ / / _ \ '_ \| __/ _ \| '__| | | |
  | |_| | |___|  __/   | || | | \ V /  __/ | | | || (_) | |  | |_| |
   \____|\____|_|     |___|_| |_|\_/ \___|_| |_|\__\___/|_|   \__, |
                                                              |___/
BANNER
  printf '%b' "${R}" >&2
  printf '  %bDeep Services Inventory Scanner v%s%b  |  read-only  |  no Cloud Asset Inventory\n' "${B}" "${VERSION}" "${R}" >&2
  printf '  %bAuthor: %s%b\n' "${D}" "${AUTHOR}" "${R}" >&2
  printf '  %bReport: %s  |  Icons: %s/  |  %s%b\n' \
    "${D}" "${REPORT_FILE}" "${ASSETS_DIR}" "${SCAN_DATE}" "${R}" >&2
  printf '%b  ============================================================================%b\n\n' "${C}" "${R}" >&2
}

#-------------------------------------------------------------------------------
# ui_init
# Decides the display mode. In TUI mode: clears the screen, hides the cursor
# and prints the banner pinned at the top. In plain mode: just the banner.
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

#-------------------------------------------------------------------------------
# ui_scan_start
# Opens the fixed 4-line status area. From here on, every update moves the
# cursor UP over the previous block and redraws it in place - the classic
# multi-line progress technique, supported by every ANSI terminal - so the
# banner never scrolls away.
#-------------------------------------------------------------------------------
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

#-------------------------------------------------------------------------------
# ui_draw <step description>
# TUI mode : jumps back to the anchor, clears below, redraws the status block
#            (progress bar + percent + spinner + project + step + totals).
# Plain    : falls back to a normal scrolling [INFO] log line.
#-------------------------------------------------------------------------------
ui_draw() {
  local step="$1"
  if [ "${UI_TUI}" != true ]; then
    log "${step}"
    return
  fi
  # Truncate the step text so a line can never wrap (which would desync
  # the cursor-up repositioning on narrow terminals)
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
    printf '  \033[1;36m[%s%s]\033[0m \033[1m%3d%%\033[0m  %s\n' \
      "${bar_fill}" "${bar_rest}" "${CUR_PCT}" "${spin_char}"
    printf '  Project  : \033[1;34m%.40s\033[0m  (%d of %d)\n' \
      "${CUR_PROJ}" "${CUR_IDX}" "${TOTAL_PROJECTS}"
    printf '  Step     : %s\n' "${step}"
    printf '  Totals   : %d active | %d passive | %d system | %d warning(s)\n' \
      "${TOTAL_ACTIVE}" "${TOTAL_PASSIVE}" "${TOTAL_FILTERED}" "${WARN_COUNT}"
  } >&2
  UI_DRAWN=true
}

#-------------------------------------------------------------------------------
# ui_finish
# Draws the final 100% state, restores the cursor and releases the status
# area; buffered warnings (if any) are flushed below it afterwards.
#-------------------------------------------------------------------------------
ui_finish() {
  if [ "${UI_TUI}" = true ]; then
    CUR_PCT=100
    local width=32 bar
    bar="$(printf '%*s' "${width}" '' | tr ' ' '#')"
    {
      ui_rewind
      printf '  \033[1;32m[%s]\033[0m \033[1m100%%\033[0m  done\n' "${bar}"
      printf '  Scan complete: %d project(s) | %d APIs | %d active | %d passive | %d system\n\n' \
        "${TOTAL_PROJECTS}" "${TOTAL_APIS}" "${TOTAL_ACTIVE}" "${TOTAL_PASSIVE}" "${TOTAL_FILTERED}"
      printf '\033[?25h'                  # show cursor again
    } >&2
    UI_DRAWN=false
  else
    ok "Scan complete: ${TOTAL_PROJECTS} project(s) | ${TOTAL_APIS} APIs | ${TOTAL_ACTIVE} active | ${TOTAL_PASSIVE} passive | ${TOTAL_FILTERED} system"
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
# run_gcloud <args...>
# Wrapper that (a) applies a timeout when available and (b) silences
# stderr so disabled APIs / missing permissions never break the loop.
# Returns the command's stdout; empty string on any failure.
#-------------------------------------------------------------------------------
run_gcloud() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${CMD_TIMEOUT}s" gcloud "$@" 2>/dev/null || true
  else
    gcloud "$@" 2>/dev/null || true
  fi
}

#-------------------------------------------------------------------------------
# is_blacklisted <api-name>  -> exit 0 if the API matches the blacklist
#-------------------------------------------------------------------------------
is_blacklisted() {
  local api="$1" pattern
  for pattern in "${API_BLACKLIST[@]}"; do
    if printf '%s' "${api}" | grep -qE "${pattern}"; then
      return 0
    fi
  done
  return 1
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
declare -A CAT_INDEX=() CAT_TOTAL=() CAT_ACTIVE=() CAT_PASSIVE=() CAT_SYSTEM=()

# cat_rows_file <category-name> -> echoes the rows file path (registers new
# categories on first use)
cat_rows_file() {
  local name="$1"
  if [ -z "${CAT_INDEX[${name}]+x}" ]; then
    CAT_ORDER+=("${name}")
    CAT_INDEX[${name}]=$(( ${#CAT_ORDER[@]} - 1 ))
    CAT_TOTAL[${name}]=0; CAT_ACTIVE[${name}]=0
    CAT_PASSIVE[${name}]=0; CAT_SYSTEM[${name}]=0
    : > "${TMP_DIR}/cat_${CAT_INDEX[${name}]}.html"
  fi
  printf '%s' "${TMP_DIR}/cat_${CAT_INDEX[${name}]}.html"
}

# get_category <api-name> -> echoes the category display name
get_category() {
  local api="$1" rule pattern name
  if is_blacklisted "${api}"; then
    printf 'System / Baseline'
    return
  fi
  for rule in "${CATEGORY_RULES[@]}"; do
    pattern="${rule%|*}"      # everything up to the LAST pipe = regex
    name="${rule##*|}"        # after the last pipe = category name
    if printf '%s' "${api}" | grep -qE "${pattern}"; then
      printf '%s' "${name}"
      return
    fi
  done
  printf 'Other Services'
}

# register_categories_in_order: pre-registers categories so tab order is
# deterministic (rule order, then Other, then System / Baseline last)
register_categories_in_order() {
  local rule name
  for rule in "${CATEGORY_RULES[@]}"; do
    name="${rule##*|}"
    cat_rows_file "${name}" >/dev/null
  done
  cat_rows_file 'Other Services'    >/dev/null
  cat_rows_file 'System / Baseline' >/dev/null
}

#===============================================================================
# TARGETED RESOURCE SUB-CHECKS
# Each function prints "<count>|<human summary>" and always exits 0.
# A count of 0 means the API is enabled but no live resources were found.
#===============================================================================

check_gke() {
  local project="$1" out count name loc region regions=""
  out="$(run_gcloud container clusters list --project="${project}" --format='value(name,location)')"
  count="$(printf '%s' "${out}" | grep -c . || true)"
  while IFS="$(printf '\t')" read -r name loc; do
    [ -z "${name}" ] && continue
    region="$(zone_to_region "${loc}")"
    if [ -n "${region}" ]; then
      note_region "${region}" "GKE"
      regions="${regions}${region}
"
    fi
  done <<< "${out}"
  local rlist; rlist="$(printf '%s' "${regions}" | join_unique)"
  printf '%s|%s' "${count}" "${count} cluster(s)${rlist:+ (regions: ${rlist})}"
}

check_vertex() {
  local project="$1" region out ep_count=0 model_count=0 regions_hit=""
  for region in "${VERTEX_REGIONS[@]}"; do
    out="$(run_gcloud ai endpoints list --project="${project}" --region="${region}" --format='value(name)')"
    local n; n="$(printf '%s' "${out}" | grep -c . || true)"
    if [ "${n}" -gt 0 ]; then
      ep_count=$((ep_count + n))
      note_region "${region}" "Vertex AI"
      regions_hit="${regions_hit}${region}
"
    fi
    out="$(run_gcloud ai models list --project="${project}" --region="${region}" --format='value(name)')"
    n="$(printf '%s' "${out}" | grep -c . || true)"
    if [ "${n}" -gt 0 ]; then
      model_count=$((model_count + n))
      note_region "${region}" "Vertex AI"
      regions_hit="${regions_hit}${region}
"
    fi
  done
  local total=$((ep_count + model_count))
  local rlist; rlist="$(printf '%s' "${regions_hit}" | join_unique)"
  printf '%s|%s' "${total}" \
    "${ep_count} endpoint(s), ${model_count} model(s) (${#VERTEX_REGIONS[@]} regions probed${rlist:+; active in: ${rlist}})"
}

# NOTE: There is no native `gcloud firebase projects list` command; Firebase
# project listing lives in the separate `firebase` CLI. To keep this script
# dependency-free we query the Firebase Management REST API directly with the
# session's access token. HTTP 200 => the project IS a Firebase project.
check_firebase() {
  local project="$1" token http_code
  token="$(run_gcloud auth print-access-token)"
  if [ -z "${token}" ] || ! command -v curl >/dev/null 2>&1; then
    printf '0|Could not verify (no curl/token)'
    return 0
  fi
  http_code="$(curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer ${token}" \
      "https://firebase.googleapis.com/v1beta1/projects/${project}" 2>/dev/null || echo 000)"
  if [ "${http_code}" = "200" ]; then
    printf '1|Project is Firebase-enabled'
  else
    printf '0|Not associated with Firebase'
  fi
}

check_pubsub() {
  local project="$1" topics subs t s
  topics="$(run_gcloud pubsub topics list --project="${project}" --format='value(name)')"
  subs="$(run_gcloud pubsub subscriptions list --project="${project}" --format='value(name)')"
  t="$(printf '%s' "${topics}" | grep -c . || true)"
  s="$(printf '%s' "${subs}"   | grep -c . || true)"
  if [ $((t + s)) -gt 0 ]; then
    note_region "global" "Pub/Sub"
  fi
  printf '%s|%s' "$((t + s))" "${t} topic(s), ${s} subscription(s) (global service)"
}

check_functions() {
  local project="$1" out count line region regions=""
  out="$(run_gcloud functions list --project="${project}" --format='value(name)')"
  count="$(printf '%s' "${out}" | grep -c . || true)"
  while IFS= read -r line; do
    [ -z "${line}" ] && continue
    # Gen2 names are full paths: projects/P/locations/REGION/functions/NAME
    region="$(printf '%s' "${line}" | sed -n 's|.*/locations/\([^/]*\)/.*|\1|p')"
    if [ -n "${region}" ]; then
      note_region "${region}" "Cloud Functions"
      regions="${regions}${region}
"
    fi
  done <<< "${out}"
  local rlist; rlist="$(printf '%s' "${regions}" | join_unique)"
  printf '%s|%s' "${count}" "${count} function(s) (Gen1+Gen2)${rlist:+ (regions: ${rlist})}"
}

check_compute() {
  local project="$1" out count name zone region regions=""
  out="$(run_gcloud compute instances list --project="${project}" --format='value(name,zone)')"
  count="$(printf '%s' "${out}" | grep -c . || true)"
  while IFS="$(printf '\t')" read -r name zone; do
    [ -z "${name}" ] && continue
    region="$(zone_to_region "${zone}")"
    if [ -n "${region}" ]; then
      note_region "${region}" "Compute Engine"
      regions="${regions}${region}
"
    fi
  done <<< "${out}"
  local rlist; rlist="$(printf '%s' "${regions}" | join_unique)"
  printf '%s|%s' "${count}" "${count} VM instance(s)${rlist:+ (regions: ${rlist})}"
}

check_storage() {
  local project="$1" out count name loc regions=""
  out="$(run_gcloud storage buckets list --project="${project}" --format='value(name,location)')"
  count="$(printf '%s' "${out}" | grep -c . || true)"
  while IFS="$(printf '\t')" read -r name loc; do
    [ -z "${name}" ] && continue
    # Bucket locations can be regions (US-CENTRAL1), multi-regions (US, EU)
    # or dual-regions (NAM4); record them all, lowercased.
    if [ -n "${loc}" ]; then
      loc="$(printf '%s' "${loc}" | tr 'A-Z' 'a-z')"
      note_region "${loc}" "Cloud Storage"
      regions="${regions}${loc}
"
    fi
  done <<< "${out}"
  local rlist; rlist="$(printf '%s' "${regions}" | join_unique)"
  printf '%s|%s' "${count}" "${count} bucket(s)${rlist:+ (locations: ${rlist})}"
}

check_run() {
  local project="$1" out count regs r
  out="$(run_gcloud run services list --project="${project}" --platform=managed --format='value(metadata.name)')"
  count="$(printf '%s' "${out}" | grep -c . || true)"
  regs="$(run_gcloud run services list --project="${project}" --platform=managed \
          --format='value(metadata.labels."cloud.googleapis.com/location")')"
  while IFS= read -r r; do
    [ -z "${r}" ] && continue
    note_region "${r}" "Cloud Run"
  done <<< "${regs}"
  local rlist; rlist="$(printf '%s\n' "${regs}" | join_unique)"
  printf '%s|%s' "${count}" "${count} service(s)${rlist:+ (regions: ${rlist})}"
}

check_sql() {
  local project="$1" out count name region regions=""
  out="$(run_gcloud sql instances list --project="${project}" --format='value(name,region)')"
  count="$(printf '%s' "${out}" | grep -c . || true)"
  while IFS="$(printf '\t')" read -r name region; do
    [ -z "${name}" ] && continue
    if [ -n "${region}" ]; then
      note_region "${region}" "Cloud SQL"
      regions="${regions}${region}
"
    fi
  done <<< "${out}"
  local rlist; rlist="$(printf '%s' "${regions}" | join_unique)"
  printf '%s|%s' "${count}" "${count} instance(s)${rlist:+ (regions: ${rlist})}"
}

#-------------------------------------------------------------------------------
# Sub-check registry: maps an API name to its check function + pretty label.
# To add a new deep check: write a check_x function above and add a row here.
#-------------------------------------------------------------------------------
SUBCHECK_APIS=(
  "container.googleapis.com|check_gke|Kubernetes Engine (GKE)"
  "aiplatform.googleapis.com|check_vertex|Vertex AI / Gemini Enterprise"
  "firebase.googleapis.com|check_firebase|Firebase"
  "pubsub.googleapis.com|check_pubsub|Pub/Sub"
  "cloudfunctions.googleapis.com|check_functions|Cloud Functions"
  "compute.googleapis.com|check_compute|Compute Engine"
  "storage.googleapis.com|check_storage|Cloud Storage"
  "run.googleapis.com|check_run|Cloud Run"
  "sqladmin.googleapis.com|check_sql|Cloud SQL"
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

  # Report logo: generic cloud mark
  cat > "${ASSETS_DIR}/logo-cloud.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="48" height="48">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#2563eb"/>
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

  # Status: passive / enabled only (amber half-filled circle)
  cat > "${ASSETS_DIR}/status-passive.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
  <circle cx="8" cy="8" r="6.2" fill="none" stroke="#f59e0b" stroke-width="1.6"/>
  <path d="M8 1.8a6.2 6.2 0 0 1 0 12.4z" fill="#f59e0b"/>
</svg>
SVG

  # Status: enabled, not deep-checked (neutral outline circle)
  cat > "${ASSETS_DIR}/status-enabled.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
  <circle cx="8" cy="8" r="6.2" fill="none" stroke="#94a3b8" stroke-width="1.6"/>
  <circle cx="8" cy="8" r="2" fill="#94a3b8"/>
</svg>
SVG

  # Status: system / baseline default API (muted gear)
  cat > "${ASSETS_DIR}/status-system.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
  <path fill="#94a3b8" d="M8 1.5l1 .2.4 1.5c.4.1.8.3 1.1.5l1.4-.7.8.8-.7 1.4c.2.3.4.7.5 1.1l1.5.4.2 1-.2 1-1.5.4c-.1.4-.3.8-.5 1.1l.7 1.4-.8.8-1.4-.7c-.3.2-.7.4-1.1.5l-.4 1.5-1 .2-1-.2-.4-1.5a4.6 4.6 0 0 1-1.1-.5l-1.4.7-.8-.8.7-1.4a4.6 4.6 0 0 1-.5-1.1l-1.5-.4-.2-1 .2-1 1.5-.4c.1-.4.3-.8.5-1.1l-.7-1.4.8-.8 1.4.7c.3-.2.7-.4 1.1-.5l.4-1.5 1-.2z"/>
  <circle cx="8" cy="8" r="2.2" fill="#ffffff"/>
</svg>
SVG

  # Metric: projects scanned (folder)
  cat > "${ASSETS_DIR}/metric-projects.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <path fill="none" stroke="#3b82f6" stroke-width="1.8" stroke-linejoin="round"
        d="M3 6.5A1.5 1.5 0 0 1 4.5 5h4l2 2.5h9A1.5 1.5 0 0 1 21 9v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z"/>
</svg>
SVG

  # Metric: APIs discovered (grid)
  cat > "${ASSETS_DIR}/metric-apis.svg" <<'SVG'
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

  # Metric: system / baseline services (gear, larger)
  cat > "${ASSETS_DIR}/metric-system.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <path fill="none" stroke="#94a3b8" stroke-width="1.8" d="M12 8.2a3.8 3.8 0 1 1 0 7.6 3.8 3.8 0 0 1 0-7.6z"/>
  <path fill="none" stroke="#94a3b8" stroke-width="1.8" stroke-linecap="round"
        d="M12 2.8v2.4M12 18.8v2.4M21.2 12h-2.4M5.2 12H2.8M18.5 5.5l-1.7 1.7M7.2 16.8l-1.7 1.7M18.5 18.5l-1.7-1.7M7.2 7.2L5.5 5.5"/>
</svg>
SVG

  # Metric: regions in use (globe)
  cat > "${ASSETS_DIR}/metric-regions.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <g fill="none" stroke="#06b6d4" stroke-width="1.8">
    <circle cx="12" cy="12" r="9"/>
    <ellipse cx="12" cy="12" rx="4" ry="9"/>
    <path d="M3.6 9h16.8M3.6 15h16.8"/>
  </g>
</svg>
SVG

  ok "Icon assets written to ${ASSETS_DIR}/ (10 SVG files)"
}

write_html_header() {
  # Heredoc with quoted delimiter: nothing inside is expanded by Bash,
  # so CSS/JS braces and dollar signs are safe.
  cat > "${REPORT_FILE}" <<'HTML_HEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GCP Services Inventory</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#f8fafc; --surface:#ffffff; --surface-2:#f1f5f9;
    --text:#0f172a; --text-muted:#64748b; --border:#e2e8f0;
    --accent:#2563eb; --accent-soft:#dbeafe;
    --green:#059669; --green-bg:#d1fae5;
    --amber:#b45309; --amber-bg:#fef3c7;
    --gray:#475569;  --gray-bg:#e2e8f0;
    --shadow:0 1px 3px rgba(15,23,42,.08),0 4px 14px rgba(15,23,42,.05);
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0f172a; --surface:#1e293b; --surface-2:#293548;
      --text:#f1f5f9; --text-muted:#94a3b8; --border:#334155;
      --accent:#60a5fa; --accent-soft:#1e3a5f;
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

  /* --- key metrics grid --- */
  .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));
           gap:14px;margin:22px 0 30px}
  .metric{background:var(--surface);border:1px solid var(--border);
          border-radius:14px;padding:18px 20px;box-shadow:var(--shadow)}
  .metric .num{font-size:30px;font-weight:800;letter-spacing:-.03em}
  .metric .lbl{color:var(--text-muted);font-size:12.5px;font-weight:600;
               text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
  .metric.m-active .num{color:var(--green)}
  .metric.m-regions .num{color:#06b6d4}
  .metric.m-filtered .num{color:var(--text-muted)}

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
  .card h2 img{width:18px;height:18px;vertical-align:-3px;margin-right:8px}
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
  .metric img{width:24px;height:24px;margin-bottom:8px;display:block}
  .hero-row{display:flex;align-items:center;gap:14px}
  .hero-row img{width:44px;height:44px}
  .b-active{color:var(--green);background:var(--green-bg)}
  .b-passive{color:var(--amber);background:var(--amber-bg)}
  .b-enabled{color:var(--gray);background:var(--gray-bg)}
  .b-system{color:var(--text-muted);background:transparent;
            border:1px dashed var(--border)}
  tr.baseline td{opacity:.72}
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
# PER-PROJECT SCAN
#===============================================================================
scan_project() {
  local project="$1" idx="$2"
  local esc_project; esc_project="$(html_escape "${project}")"

  ui_draw "Listing enabled APIs"

  # ---- 1) Enabled APIs -------------------------------------------------------
  local enabled_apis
  enabled_apis="$(run_gcloud services list --enabled --project="${project}" \
                  --format='value(config.name)')"

  if [ -z "${enabled_apis}" ]; then
    warn "  No enabled APIs visible (permissions?) - skipping detail scan."
  fi

  # ---- 2) Deep sub-checks for enabled high-value APIs ------------------------
  # Results stored as "api|count|summary|label" lines
  local subcheck_results=""
  local entry api fn label
  for entry in "${SUBCHECK_APIS[@]}"; do
    api="${entry%%|*}"
    fn="$(printf '%s' "${entry}" | cut -d'|' -f2)"
    label="$(printf '%s' "${entry}" | cut -d'|' -f3)"
    if printf '%s\n' "${enabled_apis}" | grep -qx "${api}"; then
      ui_draw "Sub-check: ${label}"
      local res count summary
      res="$("${fn}" "${project}")"
      count="${res%%|*}"
      summary="${res#*|}"
      subcheck_results="${subcheck_results}${api}|${count}|${summary}|${label}
"
    fi
  done

  # ---- 3) Build table rows, grouped by SERVICE CATEGORY -----------------------
  # Each row carries the project name and is appended to its category's
  # rows file; the tabs of the report are the categories, not the projects.
  local p_total=0 p_active=0 p_passive=0 p_filtered=0

  local api category crows_file
  while IFS= read -r api; do
    [ -z "${api}" ] && continue
    p_total=$((p_total + 1))

    category="$(get_category "${api}")"
    crows_file="$(cat_rows_file "${category}")"
    CAT_TOTAL[${category}]=$(( CAT_TOTAL[${category}] + 1 ))

    if [ "${category}" = "System / Baseline" ]; then
      p_filtered=$((p_filtered + 1))
      CAT_SYSTEM[${category}]=$(( CAT_SYSTEM[${category}] + 1 ))
      # Only skip the row if the user explicitly opted to hide baselines
      if [ "${HIDE_BASELINE}" = "true" ]; then
        continue
      fi
      printf '<tr class="baseline"><td>%s</td><td class="api">%s</td><td>-</td><td><span class="badge b-system"><img src="'"${ASSETS_DIR}"'/status-system.svg" alt="">System / Baseline (Default)</span></td><td class="detail">Auto-enabled Google infrastructure API required for the project to operate</td></tr>\n' \
        "${esc_project}" "$(html_escape "${api}")" >> "${crows_file}"
      continue
    fi

    local esc_api; esc_api="$(html_escape "${api}")"
    local match
    match="$(printf '%s' "${subcheck_results}" | grep "^${api}|" || true)"

    if [ -n "${match}" ]; then
      local count summary label
      count="$(printf '%s'  "${match}" | cut -d'|' -f2)"
      summary="$(printf '%s' "${match}" | cut -d'|' -f3)"
      label="$(printf '%s'  "${match}" | cut -d'|' -f4)"
      local esc_sum;   esc_sum="$(html_escape "${summary}")"
      local esc_label; esc_label="$(html_escape "${label}")"
      if [ "${count}" -gt 0 ] 2>/dev/null; then
        p_active=$((p_active + 1))
        CAT_ACTIVE[${category}]=$(( CAT_ACTIVE[${category}] + 1 ))
        printf '<tr><td>%s</td><td class="api">%s</td><td>%s</td><td><span class="badge b-active"><img src="'"${ASSETS_DIR}"'/status-active.svg" alt="">Active with Resources</span></td><td class="detail">%s</td></tr>\n' \
          "${esc_project}" "${esc_api}" "${esc_label}" "${esc_sum}" >> "${crows_file}"
      else
        p_passive=$((p_passive + 1))
        CAT_PASSIVE[${category}]=$(( CAT_PASSIVE[${category}] + 1 ))
        printf '<tr><td>%s</td><td class="api">%s</td><td>%s</td><td><span class="badge b-passive"><img src="'"${ASSETS_DIR}"'/status-passive.svg" alt="">Enabled (No Active Resources Found)</span></td><td class="detail">%s</td></tr>\n' \
          "${esc_project}" "${esc_api}" "${esc_label}" "${esc_sum}" >> "${crows_file}"
      fi
    else
      # Enabled API without a targeted deep-check
      printf '<tr><td>%s</td><td class="api">%s</td><td>-</td><td><span class="badge b-enabled"><img src="'"${ASSETS_DIR}"'/status-enabled.svg" alt="">Enabled (Not Deep-Checked)</span></td><td class="detail">API enabled; add a sub-check to verify usage</td></tr>\n' \
        "${esc_project}" "${esc_api}" >> "${crows_file}"
    fi
  done <<< "${enabled_apis}"

  # ---- 4) Executive summary row (per-project rollup) --------------------------
  printf '<tr><td>%s</td><td>%d</td><td><span class="badge b-active">%d</span></td><td><span class="badge b-passive">%d</span></td><td class="detail">%d</td></tr>\n' \
    "${esc_project}" "${p_total}" "${p_active}" "${p_passive}" "${p_filtered}" \
    >> "${SUMMARY_ROWS_FILE}"

  # ---- 6) Roll up global counters ----------------------------------------------
  TOTAL_APIS=$((TOTAL_APIS + p_total))
  TOTAL_ACTIVE=$((TOTAL_ACTIVE + p_active))
  TOTAL_PASSIVE=$((TOTAL_PASSIVE + p_passive))
  TOTAL_FILTERED=$((TOTAL_FILTERED + p_filtered))

  ui_draw "Done: ${p_total} APIs, ${p_active} active, ${p_passive} passive"
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
  # ---- Argument parse: only --zip is supported --------------------------------
  local MAKE_ZIP="${ZIP_REPORT}"
  local a
  for a in "$@"; do
    case "${a}" in
      --zip) MAKE_ZIP=true ;;
      *)
        err "Unknown argument: ${a}"
        err "This script scans ONLY the current gcloud project."
        err "Usage: $0 [--zip]"
        err "To scan a different project: gcloud config set project PROJECT_ID"
        exit 1
        ;;
    esac
  done

  ui_init
  log "GCP Deep Inventory Scan - starting"

  # ---- Preflight checks --------------------------------------------------------
  if ! command -v gcloud >/dev/null 2>&1; then
    err "gcloud CLI not found in PATH. Install the Google Cloud SDK first."
    exit 1
  fi

  ACTIVE_ACCOUNT="$(run_gcloud auth list --filter='status:ACTIVE' --format='value(account)')"
  if [ -z "${ACTIVE_ACCOUNT}" ]; then
    err "No active gcloud session. Run: gcloud auth login"
    exit 1
  fi
  ok "Authenticated as: ${ACTIVE_ACCOUNT}"

  # ---- Project resolution: CURRENT gcloud project only -----------------------------
  local projects=""
  projects="$(run_gcloud config get-value project)"
  if [ -z "${projects}" ] || [ "${projects}" = "(unset)" ]; then
    err "No current project set in gcloud config."
    err "Fix with: gcloud config set project PROJECT_ID"
    exit 1
  fi
  log "Scope: current project only (${projects})"
  TOTAL_PROJECTS="$(printf '%s' "${projects}" | grep -c . || true)"
  ok "Found ${TOTAL_PROJECTS} project(s) to scan"

  # ---- Scan loop -------------------------------------------------------------------
  register_categories_in_order
  ui_scan_start
  local idx=0 project
  while IFS= read -r project; do
    [ -z "${project}" ] && continue
    idx=$((idx + 1))
    CUR_IDX="${idx}"
    CUR_PROJ="${project}"
    CUR_PCT=$(( (idx - 1) * 100 / TOTAL_PROJECTS ))
    scan_project "${project}" "${idx}"
  done <<< "${projects}"
  ui_finish

  # ---- Aggregate multi-region findings -----------------------------------------------
  # REGIONS_FILE holds one "region|service" line per resource detected.
  TOTAL_REGIONS="$(cut -d'|' -f1 "${REGIONS_FILE}" | sort -u | grep -c . || true)"
  if [ -s "${REGIONS_FILE}" ]; then
    sort "${REGIONS_FILE}" | awk -F'|' '
      { cnt[$1]++
        if (index("," svc[$1] ",", "," $2 ",") == 0)
          svc[$1] = (svc[$1] == "" ? $2 : svc[$1] "," $2) }
      END { for (r in cnt) printf "%s|%d|%s\n", r, cnt[r], svc[r] }' \
      | sort -t'|' -k2,2nr -k1,1 > "${TMP_DIR}/region_agg.txt"
    local rg_region rg_count rg_svcs
    while IFS='|' read -r rg_region rg_count rg_svcs; do
      printf '<tr><td class="api">%s</td><td><span class="badge b-active">%d</span></td><td class="detail">%s</td></tr>\n' \
        "$(html_escape "${rg_region}")" "${rg_count}" \
        "$(html_escape "$(printf '%s' "${rg_svcs}" | sed 's/,/, /g')")" \
        >> "${REGION_ROWS_FILE}"
    done < "${TMP_DIR}/region_agg.txt"
    ok "Multi-region scan: active resources found in ${TOTAL_REGIONS} region(s)/location(s)"
  else
    printf '<tr><td colspan="3" class="detail">No regional resources detected by the deep sub-checks.</td></tr>\n' \
      >> "${REGION_ROWS_FILE}"
    ok "Multi-region scan: no regional resources detected"
  fi

  # ---- Assemble the final HTML ------------------------------------------------------
  log "Writing icon assets and building HTML dashboard: ${REPORT_FILE}"
  write_assets
  write_html_header

  {
    # Hero
    printf '<header class="hero"><div class="hero-row"><img src="%s/logo-cloud.svg" alt="GCP Inventory logo"><h1>GCP Services Inventory</h1></div>' "${ASSETS_DIR}"
    printf '<p>Deep resource scan · %s · account <code>%s</code> · Cloud Asset Inventory <strong>not</strong> used</p></header>\n' \
      "$(html_escape "${SCAN_DATE}")" "$(html_escape "${ACTIVE_ACCOUNT}")"

    # Metrics grid
    printf '<div class="metrics">\n'
    printf '<div class="metric"><img src="%s/metric-projects.svg" alt=""><div class="num">%d</div><div class="lbl">Projects Scanned</div></div>\n' "${ASSETS_DIR}" "${TOTAL_PROJECTS}"
    printf '<div class="metric"><img src="%s/metric-apis.svg" alt=""><div class="num">%d</div><div class="lbl">APIs Discovered</div></div>\n' "${ASSETS_DIR}" "${TOTAL_APIS}"
    printf '<div class="metric m-active"><img src="%s/metric-active.svg" alt=""><div class="num">%d</div><div class="lbl">Active Resource Services</div></div>\n' "${ASSETS_DIR}" "${TOTAL_ACTIVE}"
    printf '<div class="metric m-regions"><img src="%s/metric-regions.svg" alt=""><div class="num">%d</div><div class="lbl">Regions in Use</div></div>\n' "${ASSETS_DIR}" "${TOTAL_REGIONS}"
    printf '<div class="metric m-filtered"><img src="%s/metric-system.svg" alt=""><div class="num">%d</div><div class="lbl">System / Baseline Services</div></div>\n' "${ASSETS_DIR}" "${TOTAL_FILTERED}"
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
        printf '<div class="card"><h2>%s <small>%d services | %d active | %d passive | %d system</small></h2>\n' \
          "$(html_escape "${cname}")" "${CAT_TOTAL[${cname}]}" "${CAT_ACTIVE[${cname}]}" \
          "${CAT_PASSIVE[${cname}]}" "${CAT_SYSTEM[${cname}]}"
        printf '<table><thead><tr><th>Project</th><th>API / Service</th><th>Deep Check</th><th>Status</th><th>Details</th></tr></thead><tbody>\n'
        cat "${crf}"
        printf '</tbody></table></div></section>\n'
      } >> "${TABS_PANELS_FILE}"
    done

    # Tab bar (Executive Summary + one button per SERVICE CATEGORY)
    printf '<nav class="tabbar"><button class="active" data-target="summary">Executive Summary</button>\n'
    cat "${TABS_BUTTONS_FILE}"
    printf '</nav>\n'

    # Executive summary panel: region rollup + category rollup + project rollup
    printf '<section class="panel active" id="summary">\n'

    printf '<div class="card"><h2><img src="%s/metric-regions.svg" alt="Globe">Regions in Use <small>locations where the deep sub-checks found live resources</small></h2>\n' "${ASSETS_DIR}"
    printf '<table><thead><tr><th>Region / Location</th><th>Resources Detected</th><th>Services Using It</th></tr></thead><tbody>\n'
    cat "${REGION_ROWS_FILE}"
    printf '</tbody></table></div>\n'

    printf '<div class="card"><h2>Services by Category <small>click a category to open its tab</small></h2>\n'
    printf '<table><thead><tr><th>Category</th><th>Services</th><th>Active w/ Resources</th><th>Passive / Enabled Only</th><th>System / Baseline</th></tr></thead><tbody>\n'
    for ci in "${!CAT_ORDER[@]}"; do
      cname="${CAT_ORDER[${ci}]}"
      [ "${CAT_TOTAL[${cname}]:-0}" -eq 0 ] && continue
      printf '<tr><td><button class="projlink" onclick="showTab(%s)">%s</button></td><td>%d</td><td><span class="badge b-active">%d</span></td><td><span class="badge b-passive">%d</span></td><td class="detail">%d</td></tr>\n' \
        "'cat-${ci}'" "$(html_escape "${cname}")" "${CAT_TOTAL[${cname}]}" \
        "${CAT_ACTIVE[${cname}]}" "${CAT_PASSIVE[${cname}]}" "${CAT_SYSTEM[${cname}]}"
    done
    printf '</tbody></table></div>\n'

    printf '<div class="card"><h2>Projects <small>per-project rollup</small></h2>\n'
    printf '<table><thead><tr><th>Project</th><th>APIs Enabled</th><th>Active w/ Resources</th><th>Passive / Enabled Only</th><th>System / Baseline</th></tr></thead><tbody>\n'
    cat "${SUMMARY_ROWS_FILE}"
    printf '</tbody></table></div>\n'

    printf '</section>\n'

    # Category detail panels
    cat "${TABS_PANELS_FILE}"

    printf '<footer>Generated by gcp_inventory_scan.sh v%s · Author: %s · read-only scan · no Cloud Asset Inventory permissions used</footer>\n' \
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
# Simplest option: grant `roles/viewer` on each project (or at the folder/org
# level). Everything below is included in Viewer.
#
# Least-privilege alternative (custom role or granular grants):
#   resourcemanager.projects.get              -> project access
#   serviceusage.services.list                -> enabled API listing
#   container.clusters.list                   -> GKE sub-check
#   aiplatform.endpoints.list
#   aiplatform.models.list                    -> Vertex AI sub-check
#   firebase.projects.get                     -> Firebase association check
#   pubsub.topics.list
#   pubsub.subscriptions.list                 -> Pub/Sub sub-check
#   cloudfunctions.functions.list             -> Cloud Functions sub-check
#   compute.instances.list                    -> Compute Engine sub-check
#   storage.buckets.list                      -> Cloud Storage sub-check
#   run.services.list                         -> Cloud Run sub-check
#   cloudsql.instances.list                   -> Cloud SQL sub-check
#
# Explicitly NOT required: any cloudasset.assets.* permission.
#===============================================================================
