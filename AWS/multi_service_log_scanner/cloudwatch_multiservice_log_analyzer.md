# Optimized CloudWatch Log Analyzer

## Overview

This script provides an optimized and parallelized analysis of AWS CloudWatch Logs usage across multiple AWS services.

It retrieves CloudWatch Log Groups, categorizes them by service type, calculates current stored log volume, and analyzes historical log ingestion metrics for the last 10 and 30 days.

The script supports:

- ECS / Fargate
- EC2
- S3

The analyzer is designed for:

- CloudWatch storage analysis
- Cost estimation
- Retention monitoring
- Log ingestion tracking
- Capacity planning
- Infrastructure reporting
- Multi-service log visibility

---

# Features

- Parallel processing for faster execution
- Automatic service detection
- CloudWatch metric analysis using `IncomingBytes`
- Historical ingestion estimation
- Retry mechanism for AWS API throttling
- Temporary workspace isolation
- Aggregated reporting by service type
- Lightweight Bash implementation

---

# Supported Services

| Service | Detection Method |
|---|---|
| ECS / Fargate | Log group names containing `ecs`, `fargate`, `/ecs/` |
| EC2 | Log group names containing `ec2`, `syslog`, `messages`, `secure`, `cloud-init` |
| S3 | Log group names containing `s3`, `bucket`, `access-log` |

---

# Requirements

Before running the script, ensure the following requirements are installed and configured.

## Required Tools

- Bash shell
- AWS CLI
- `bc`
- GNU `xargs`
- `awk`
- `grep`

---

# AWS Permissions

The AWS account or IAM role executing the script requires the following permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "logs:DescribeLogGroups",
    "cloudwatch:GetMetricStatistics"
  ],
  "Resource": "*"
}
```

---

# How It Works

The script performs the following operations:

1. Retrieves all CloudWatch Log Groups
2. Stores log group metadata temporarily
3. Processes log groups in parallel
4. Detects the service type automatically
5. Queries CloudWatch `IncomingBytes` metrics
6. Calculates:
   - Current stored logs
   - Last 10 days ingestion
   - Last 30 days ingestion
7. Aggregates totals by service category
8. Generates a formatted summary report
9. Cleans temporary files automatically

---

# Architecture Overview

## Parallel Processing

The script uses:

```bash
xargs -P $PARALLEL_JOBS
```

This allows simultaneous processing of multiple log groups for faster execution in large AWS environments.

Default configuration:

```bash
PARALLEL_JOBS=10
```

---

# AWS Retry Logic

To improve reliability, the script includes retry logic for AWS API throttling.

## Retry Configuration

```bash
MAX_RETRIES=5
```

## Retry Behavior

When throttling is detected:

- The script waits progressively longer between retries
- Uses exponential-style backoff
- Prevents premature failures during high API usage

Example:

```text
Retry 1 -> wait 2s
Retry 2 -> wait 4s
Retry 3 -> wait 6s
```

---

# Metrics Collected

The script retrieves:

| Metric | Description |
|---|---|
| Stored Bytes | Current CloudWatch log storage size |
| IncomingBytes | Historical log ingestion volume |
| Last10D | Estimated ingestion during the last 10 days |
| Last30D | Estimated ingestion during the last 30 days |

---

# CloudWatch Metric Used

The analyzer uses the following AWS metric:

```text
AWS/Logs -> IncomingBytes
```

This metric represents the amount of log data ingested into CloudWatch Logs.

---

# Example Output

```text
==============================================================
 Optimized CloudWatch Log Analyzer
==============================================================
Services:
 - ECS / Fargate
 - EC2
 - S3
==============================================================

[INFO] Retrieving CloudWatch Log Groups...
[INFO] Processing log groups in parallel...

==============================================================
 FINAL REPORT
==============================================================
Service         Groups     Stored(GB)     Last10D(GB)   Last30D(GB)
FARGATE         12         250.45         82.13         245.88
EC2             8          120.34         41.22         118.90
S3              5          45.20          15.10         44.80
==============================================================

Execution Time: 18 seconds

Analysis Complete
==============================================================
```

---

# Installation

Save the script as:

```bash
optimized-cloudwatch-log-analyzer.sh
```

Make it executable:

```bash
chmod +x optimized-cloudwatch-log-analyzer.sh
```

---

# Usage

Run the script:

```bash
./optimized-cloudwatch-log-analyzer.sh
```

Or:

```bash
bash optimized-cloudwatch-log-analyzer.sh
```

---

# Output Explanation

| Column | Description |
|---|---|
| Service | AWS service category |
| Groups | Number of matching log groups |
| Stored(GB) | Current stored log volume |
| Last10D(GB) | Log ingestion during the last 10 days |
| Last30D(GB) | Log ingestion during the last 30 days |

---

# Performance Optimization

The script improves performance by:

- Using parallel execution
- Reducing sequential AWS API calls
- Minimizing CloudWatch query overhead
- Using lightweight shell utilities
- Temporary file buffering

This makes it suitable for large AWS environments with many log groups.

---

# Temporary File Handling

The script creates a temporary workspace:

```bash
/tmp/cwlog_analysis_<PID>
```

The directory is automatically removed after execution.

---

# Limitations

- Service detection depends on log group naming conventions
- Historical metrics depend on CloudWatch metric availability
- Large environments may still encounter AWS throttling
- Estimates are based on ingestion metrics only
- Cross-region analysis is not included by default

---

# Possible Future Enhancements

Potential future improvements include:

- CSV export support
- JSON output mode
- Multi-region analysis
- AWS Organizations support
- Per-log-group detailed reports
- Cost estimation integration
- Grafana/Prometheus integration
- Retention policy validation
- Email reporting
- HTML dashboard generation

---

# Best Practices

Recommended usage:

- Execute during off-peak hours in large environments
- Use AWS profiles with read-only permissions
- Schedule via cron for periodic reporting
- Export results for long-term trend analysis
- Monitor AWS API limits

---

# Author

Francisco Gutierrez  
GlobalLogic - 2026

