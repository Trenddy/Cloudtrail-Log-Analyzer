# CloudTrail Log Analyzer

A Python-based security tool that parses AWS CloudTrail logs to detect anomalies, identify suspicious activity, and generate summary reports for cloud security monitoring workflows.

## Features
- Detects unauthorized API calls and access denied errors
- Flags root account usage
- Identifies console logins without MFA
- Detects IAM policy changes
- Identifies activity spikes across time windows
- Generates a clean summary report

## Requirements
- Python 3.8+
- No external dependencies — built with Python standard library only

## Usage

```bash
python analyzer.py --log sample_log.json
```
## Output Example

    === CloudTrail Security Analysis Report ===

    [CRITICAL] Root account usage detected: 2 event(s)
    [HIGH]     Unauthorized API calls detected: 5 event(s)
    [HIGH]     Console logins without MFA: 1 event(s)
    [HIGH]     IAM policy changes detected: 3 event(s)
    [INFO]     Activity spike detected between 14:00 - 15:00: 47 events

    Total events analyzed: 150
    Analysis complete.
    
## Files
- `analyzer.py` — main analysis engine
- `sample_log.json` — sample CloudTrail log for testing
- `report.txt` — generated output report

## Author
Troy Johnson  
Security+ | AWS Solutions Architect | AWS AI Practitioner
