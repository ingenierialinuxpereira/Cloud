#!/bin/bash
#
# ==============================================================================
# Script Name: cloudwatch_multiservice_log_analyzer.sh
#
# Description:
#   High-performance CloudWatch Log Analyzer for:
#
#     - AWS ECS / Fargate
#     - Amazon EC2
#     - Amazon S3
#
#     - Features:
#
#     - No describe-log-streams calls
#     - No unnecessary sleep timers
#     - Prefix filtering
#     - Parallel processing
#     - Reduced AWS API calls
#     - Faster metric collection
#     - Throttling protection
#
#   Calculates:
#
#     - Current stored log size
#     - IncomingBytes for last 10 days
#     - IncomingBytes for last 30 days
#
# Author:
#   Francisco Gutierrez G.
#   Cloud Linux Engineer
#
# Company:
#   Amrize
#
# Date:
#   May 2026
#
# ==============================================================================

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------

MAX_RETRIES=5
PARALLEL_JOBS=10

END_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_10D=$(date -u -d "10 days ago" +"%Y-%m-%dT%H:%M:%SZ")
START_30D=$(date -u -d "30 days ago" +"%Y-%m-%dT%H:%M:%SZ")

TMP_DIR="/tmp/cwlog_analysis_$$"
mkdir -p "$TMP_DIR"

# ------------------------------------------------------------------------------
# AWS RETRY FUNCTION
# ------------------------------------------------------------------------------

aws_retry() {

  local CMD="$1"
  local RETRY=0

  while true; do

    OUTPUT=$(eval "$CMD" 2>&1)
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ]; then
      echo "$OUTPUT"
      return 0
    fi

    if echo "$OUTPUT" | grep -qi "Throttling"; then

      ((RETRY++))

      if [ $RETRY -ge $MAX_RETRIES ]; then
        echo "[ERROR] Max retries reached"
        return 1
      fi

      WAIT_TIME=$((RETRY * 2))

      echo "[WARNING] Throttling detected. Retrying in ${WAIT_TIME}s..."

      sleep $WAIT_TIME

    else
      echo "$OUTPUT"
      return 1
    fi

  done
}

# ------------------------------------------------------------------------------
# FUNCTION: GET INCOMING BYTES
# ------------------------------------------------------------------------------

get_incoming_bytes() {

  local LOG_GROUP="$1"
  local START_DATE="$2"

  aws cloudwatch get-metric-statistics \
    --namespace AWS/Logs \
    --metric-name IncomingBytes \
    --dimensions Name=LogGroupName,Value="$LOG_GROUP" \
    --start-time "$START_DATE" \
    --end-time "$END_DATE" \
    --period 86400 \
    --statistics Sum \
    --query 'Datapoints[*].Sum' \
    --output text 2>/dev/null | \
    awk '{sum=0; for(i=1;i<=NF;i++) sum+=$i; print sum+0}'
}

# ------------------------------------------------------------------------------
# FUNCTION: CONVERT TO GB
# ------------------------------------------------------------------------------

convert_to_gb() {
  echo "scale=2; $1 / 1024 / 1024 / 1024" | bc
}

# ------------------------------------------------------------------------------
# FUNCTION: PROCESS LOG GROUP
# ------------------------------------------------------------------------------

process_log_group() {

  local LOG_NAME="$1"
  local STORED_BYTES="$2"

  SERVICE="UNKNOWN"

  # --------------------------------------------------------------------------
  # SERVICE DETECTION USING LOG GROUP NAME
  # --------------------------------------------------------------------------

  if [[ "$LOG_NAME" =~ ecs|fargate|/ecs/ ]]; then
    SERVICE="FARGATE"

  elif [[ "$LOG_NAME" =~ ec2|syslog|messages|secure|cloud-init|/ec2/ ]]; then
    SERVICE="EC2"

  elif [[ "$LOG_NAME" =~ s3|bucket|access-log ]]; then
    SERVICE="S3"

  else
    return
  fi

  # --------------------------------------------------------------------------
  # METRICS
  # --------------------------------------------------------------------------

  LAST_10D=$(get_incoming_bytes "$LOG_NAME" "$START_10D")
  LAST_30D=$(get_incoming_bytes "$LOG_NAME" "$START_30D")

  [ -z "$LAST_10D" ] && LAST_10D=0
  [ -z "$LAST_30D" ] && LAST_30D=0
  [ -z "$STORED_BYTES" ] && STORED_BYTES=0

  echo "${SERVICE}|${LOG_NAME}|${STORED_BYTES}|${LAST_10D}|${LAST_30D}" \
    >> "$TMP_DIR/results.txt"
}

export -f process_log_group
export -f get_incoming_bytes
export -f aws_retry

export START_10D
export START_30D
export END_DATE
export TMP_DIR

# ------------------------------------------------------------------------------
# START
# ------------------------------------------------------------------------------

echo "=============================================================="
echo " Optimized CloudWatch Log Analyzer"
echo "=============================================================="
echo "Services:"
echo " - ECS / Fargate"
echo " - EC2"
echo " - S3"
echo "=============================================================="
echo ""

START_TIME=$(date +%s)

# ------------------------------------------------------------------------------
# GET LOG GROUPS
# ------------------------------------------------------------------------------

echo "[INFO] Retrieving CloudWatch Log Groups..."

aws logs describe-log-groups \
  --query 'logGroups[*].[logGroupName,storedBytes]' \
  --output text > "$TMP_DIR/groups.txt"

if [ ! -s "$TMP_DIR/groups.txt" ]; then
  echo "[WARNING] No log groups found"
  exit 0
fi

echo "[INFO] Processing log groups in parallel..."
echo ""

# ------------------------------------------------------------------------------
# PARALLEL PROCESSING
# ------------------------------------------------------------------------------

cat "$TMP_DIR/groups.txt" | \
xargs -P $PARALLEL_JOBS -n 2 bash -c '
  process_log_group "$0" "$1"
'

# ------------------------------------------------------------------------------
# INITIALIZE TOTALS
# ------------------------------------------------------------------------------

TOTAL_FARGATE_BYTES=0
TOTAL_EC2_BYTES=0
TOTAL_S3_BYTES=0

TOTAL_FARGATE_10D=0
TOTAL_EC2_10D=0
TOTAL_S3_10D=0

TOTAL_FARGATE_30D=0
TOTAL_EC2_30D=0
TOTAL_S3_30D=0

COUNT_FARGATE=0
COUNT_EC2=0
COUNT_S3=0

# ------------------------------------------------------------------------------
# PROCESS RESULTS
# ------------------------------------------------------------------------------

while IFS="|" read -r SERVICE LOG_NAME STORED LAST10 LAST30; do

  case "$SERVICE" in

    FARGATE)

      ((COUNT_FARGATE++))

      TOTAL_FARGATE_BYTES=$((TOTAL_FARGATE_BYTES + STORED))

      TOTAL_FARGATE_10D=$(echo "$TOTAL_FARGATE_10D + $LAST10" | bc)
      TOTAL_FARGATE_30D=$(echo "$TOTAL_FARGATE_30D + $LAST30" | bc)
      ;;

    EC2)

      ((COUNT_EC2++))

      TOTAL_EC2_BYTES=$((TOTAL_EC2_BYTES + STORED))

      TOTAL_EC2_10D=$(echo "$TOTAL_EC2_10D + $LAST10" | bc)
      TOTAL_EC2_30D=$(echo "$TOTAL_EC2_30D + $LAST30" | bc)
      ;;

    S3)

      ((COUNT_S3++))

      TOTAL_S3_BYTES=$((TOTAL_S3_BYTES + STORED))

      TOTAL_S3_10D=$(echo "$TOTAL_S3_10D + $LAST10" | bc)
      TOTAL_S3_30D=$(echo "$TOTAL_S3_30D + $LAST30" | bc)
      ;;

  esac

done < "$TMP_DIR/results.txt"

# ------------------------------------------------------------------------------
# FINAL REPORT
# ------------------------------------------------------------------------------

echo ""
echo "=============================================================="
echo " FINAL REPORT"
echo "=============================================================="

printf "%-15s %-10s %-15s %-15s %-15s\n" \
  "Service" "Groups" "Stored(GB)" "Last10D(GB)" "Last30D(GB)"

printf "%-15s %-10s %-15s %-15s %-15s\n" \
  "FARGATE" \
  "$COUNT_FARGATE" \
  "$(convert_to_gb $TOTAL_FARGATE_BYTES)" \
  "$(convert_to_gb $TOTAL_FARGATE_10D)" \
  "$(convert_to_gb $TOTAL_FARGATE_30D)"

printf "%-15s %-10s %-15s %-15s %-15s\n" \
  "EC2" \
  "$COUNT_EC2" \
  "$(convert_to_gb $TOTAL_EC2_BYTES)" \
  "$(convert_to_gb $TOTAL_EC2_10D)" \
  "$(convert_to_gb $TOTAL_EC2_30D)"

printf "%-15s %-10s %-15s %-15s %-15s\n" \
  "S3" \
  "$COUNT_S3" \
  "$(convert_to_gb $TOTAL_S3_BYTES)" \
  "$(convert_to_gb $TOTAL_S3_10D)" \
  "$(convert_to_gb $TOTAL_S3_30D)"

echo "=============================================================="

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "Execution Time: ${ELAPSED} seconds"
echo ""

# ------------------------------------------------------------------------------
# CLEANUP
# ------------------------------------------------------------------------------

rm -rf "$TMP_DIR"

echo "Analysis Complete"
echo "=============================================================="
