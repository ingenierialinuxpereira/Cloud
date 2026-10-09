# Fast ECS/Fargate CloudWatch Log Analyzer

## Overview

This script provides a quick estimation of the total CloudWatch Logs storage used by ECS/Fargate services in AWS.

It scans all CloudWatch Log Groups, filters ECS/Fargate-related log groups, calculates the total stored log size, and generates an estimated usage report for the last 10 and 30 days.

The script is useful for:

- CloudWatch cost estimation
- Log retention analysis
- Monitoring storage growth
- Capacity planning
- Operational reporting for ECS/Fargate environments

---

# Features

- Fast execution using AWS CLI queries
- Automatically filters ECS/Fargate log groups
- Calculates total stored log volume
- Provides estimated log usage for:
  - Last 10 days
  - Last 30 days
- Displays execution time
- Lightweight Bash implementation

---

# Requirements

Before running the script, ensure the following requirements are met.

## Required Tools

- Bash shell
- AWS CLI
- `bc` utility

## AWS Permissions

The AWS account or IAM role executing the script requires:

```json
{
  "Effect": "Allow",
  "Action": [
    "logs:DescribeLogGroups"
  ],
  "Resource": "*"
}
```

---

# How It Works

The script performs the following steps:

1. Queries all CloudWatch Log Groups
2. Filters log groups matching:
   - `ecs`
   - `fargate`
   - `/ecs/`
3. Reads the `storedBytes` value from each log group
4. Aggregates the total storage usage
5. Converts bytes to GB
6. Estimates:
   - Last 10 days usage
   - Last 30 days usage
7. Prints a summary report

---

# Script Assumptions

The script assumes:

- Current CloudWatch stored volume approximately represents 30 days of retention.
- The last 10 days estimate is calculated as:

```text
Total_GB / 3
```

These values are estimations and may vary depending on:

- Actual retention policies
- Log ingestion spikes
- Traffic patterns
- Service activity

---

# Example Output

```text
======================================================
 Fast ECS/Fargate CloudWatch Log Analyzer
======================================================

======================================================
 FINAL REPORT
======================================================
Metric                    Value
Log Groups                15
Stored Logs               128.45 GB
Estimated Last 10D        42.81 GB
Estimated Last 30D        128.45 GB
======================================================

Execution Time: 2 seconds
```

---

# Installation

Save the script as:

```bash
ecs-log-analyzer.sh
```

Make it executable:

```bash
chmod +x ecs-log-analyzer.sh
```

---

# Usage

Run the script:

```bash
./ecs-log-analyzer.sh
```

Or:

```bash
bash ecs-log-analyzer.sh
```

---

# Output Metrics

| Metric | Description |
|---|---|
| Log Groups | Total ECS/Fargate log groups found |
| Stored Logs | Current total stored logs in GB |
| Estimated Last 10D | Estimated log volume for the last 10 days |
| Estimated Last 30D | Estimated log volume for the last 30 days |
| Execution Time | Total script execution duration |

---

# Supported Environments

- Amazon ECS
- AWS Fargate
- CloudWatch Logs
- Linux/macOS environments with Bash

---

# Limitations

- Estimations are approximate
- Depends on naming conventions containing:
  - `ecs`
  - `fargate`
- Does not calculate ingestion rates directly
- Does not analyze individual log streams
- Requires AWS CLI configured locally

---

# Possible Future Enhancements

Potential improvements for future versions:

- Per-service log size breakdown
- CSV/JSON export
- Historical trend analysis
- CloudWatch ingestion rate calculation
- Retention policy validation
- Multi-region support
- Cost estimation integration
- Parallel processing for large environments

---

# Author

Francisco Gutierrez  
GlobalLogic - 2026

