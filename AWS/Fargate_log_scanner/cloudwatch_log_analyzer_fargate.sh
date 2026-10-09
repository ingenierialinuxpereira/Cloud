#!/bin/bash
#
# ==============================================================================
# Script Name: cloudwatch_log_analyzer_fargate.sh
#
# Description:
#   Ultra-fast ECS/Fargate CloudWatch Log Analyzer.
#
#   This script:
#
#     - Identifies ECS/Fargate Log Groups
#     - Calculates current stored log size
#     - Estimates:
#         - Last 10 days usage
#         - Last 30 days usage
#
#   Optimized for very large AWS environments.
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

echo "======================================================"
echo " Fast ECS/Fargate CloudWatch Log Analyzer"
echo "======================================================"
echo ""

START_TIME=$(date +%s)

TOTAL_BYTES=0
GROUP_COUNT=0

# ------------------------------------------------------------------------------
# GET ONLY ECS/FARGATE GROUPS
# ------------------------------------------------------------------------------

LOG_DATA=$(aws logs describe-log-groups \
  --query 'logGroups[*].[logGroupName,storedBytes]' \
  --output text | \
  grep -Ei 'ecs|fargate|/ecs/')

if [ -z "$LOG_DATA" ]; then
  echo "[WARNING] No ECS/Fargate log groups found"
  exit 0
fi

# ------------------------------------------------------------------------------
# PROCESS RESULTS
# ------------------------------------------------------------------------------

while read -r LOG_NAME STORED_BYTES; do

  [ -z "$STORED_BYTES" ] && STORED_BYTES=0

  TOTAL_BYTES=$((TOTAL_BYTES + STORED_BYTES))
  ((GROUP_COUNT++))

done <<< "$LOG_DATA"

# ------------------------------------------------------------------------------
# CONVERSIONS
# ------------------------------------------------------------------------------

TOTAL_GB=$(echo "scale=2; $TOTAL_BYTES / 1024 / 1024 / 1024" | bc)

# ------------------------------------------------------------------------------
# ESTIMATIONS
#
# Assumption:
#   Current stored volume roughly represents 30 days retention
# ------------------------------------------------------------------------------

LAST_30D_GB=$TOTAL_GB
LAST_10D_GB=$(echo "scale=2; $TOTAL_GB / 3" | bc)

# ------------------------------------------------------------------------------
# FINAL REPORT
# ------------------------------------------------------------------------------

echo ""
echo "======================================================"
echo " FINAL REPORT"
echo "======================================================"

printf "%-25s %-20s\n" "Metric" "Value"
printf "%-25s %-20s\n" "Log Groups" "$GROUP_COUNT"
printf "%-25s %-20s\n" "Stored Logs" "${TOTAL_GB} GB"
printf "%-25s %-20s\n" "Estimated Last 10D" "${LAST_10D_GB} GB"
printf "%-25s %-20s\n" "Estimated Last 30D" "${LAST_30D_GB} GB"

echo "======================================================"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "Execution Time: ${ELAPSED} seconds"
echo ""
