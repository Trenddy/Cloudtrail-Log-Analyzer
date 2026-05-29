# Usage Guide

## Requirements
- Python 3.8+
- No external dependencies required

## Setup

Clone the repository:

    git clone https://github.com/Trenddy/cloudtrail-log-analyzer.git
    cd cloudtrail-log-analyzer

## Running the Analyzer

Basic analysis using the sample log:

    python analyzer.py --log sample_log.json

Save the report to a file:

    python analyzer.py --log sample_log.json --output report.txt

Use your own CloudTrail log:

    python analyzer.py --log /path/to/your/cloudtrail.json

## Expected Output

    === CloudTrail Security Analysis Report ===

    [CRITICAL] Root account usage detected: 2 event(s)
               - ListBuckets at 2026-05-29T14:25:00Z
               - DescribeInstances at 2026-05-29T14:26:00Z

    [HIGH]     Unauthorized API calls detected: 2 event(s)
               - GetObject (AccessDenied) at 2026-05-29T14:30:00Z
               - PutObject (UnauthorizedOperation) at 2026-05-29T14:31:00Z

    [HIGH]     Console logins without MFA: 1 event(s)
               - ConsoleLogin at 2026-05-29T14:23:11Z

    [HIGH]     IAM policy changes detected: 2 event(s)
               - PutRolePolicy at 2026-05-29T14:45:00Z
               - AttachRolePolicy at 2026-05-29T14:46:00Z

    Total events analyzed: 10
    Analysis complete.

## How It Works

- Parses CloudTrail JSON log files
- Flags root account activity
- Detects unauthorized API calls and access denied errors
- Identifies console logins where MFA was not used
- Tracks IAM policy changes
- Detects unusual spikes in API activity
- Outputs a prioritized report by severity
