import json
import argparse
from collections import defaultdict
from datetime import datetime


def load_log(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data.get('Records', [])


def analyze(records):
    findings = {
        'root_usage': [],
        'unauthorized_calls': [],
        'no_mfa_logins': [],
        'iam_policy_changes': [],
    }

    hourly_activity = defaultdict(int)

    iam_change_events = {
        'DeleteGroupPolicy', 'DeleteRolePolicy', 'PutGroupPolicy',
        'PutRolePolicy', 'PutUserPolicy', 'CreatePolicy',
        'DeletePolicy', 'AttachRolePolicy', 'DetachRolePolicy'
    }

    for record in records:
        event_name = record.get('eventName', '')
        event_time = record.get('eventTime', '')
        user_identity = record.get('userIdentity', {})
        error_code = record.get('errorCode', '')
        additional_data = record.get('additionalEventData', {})

        # Track hourly activity
        if event_time:
            try:
                hour = datetime.strptime(event_time, '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:00')
                hourly_activity[hour] += 1
            except ValueError:
                pass

        # Root account usage
        if user_identity.get('type') == 'Root':
            findings['root_usage'].append({
                'event': event_name,
                'time': event_time
            })

        # Unauthorized API calls
        if error_code in ('AccessDenied', 'UnauthorizedOperation'):
            findings['unauthorized_calls'].append({
                'event': event_name,
                'time': event_time,
                'error': error_code
            })

        # Console login without MFA
        if event_name == 'ConsoleLogin':
            mfa_used = additional_data.get('MFAUsed', 'No')
            if mfa_used != 'Yes':
                findings['no_mfa_logins'].append({
                    'event': event_name,
                    'time': event_time
                })

        # IAM policy changes
        if event_name in iam_change_events:
            findings['iam_policy_changes'].append({
                'event': event_name,
                'time': event_time
            })

    return findings, hourly_activity


def detect_spikes(hourly_activity, threshold=20):
    spikes = []
    if not hourly_activity:
        return spikes
    avg = sum(hourly_activity.values()) / len(hourly_activity)
    for hour, count in hourly_activity.items():
        if count >= threshold and count > avg * 2:
            spikes.append((hour, count))
    return spikes


def generate_report(findings, hourly_activity, total_events, output_file=None):
    lines = []
    lines.append('=== CloudTrail Security Analysis Report ===\n')

    if findings['root_usage']:
        lines.append(f"[CRITICAL] Root account usage detected: {len(findings['root_usage'])} event(s)")
        for e in findings['root_usage']:
            lines.append(f"           - {e['event']} at {e['time']}")

    if findings['unauthorized_calls']:
        lines.append(f"[HIGH]     Unauthorized API calls detected: {len(findings['unauthorized_calls'])} event(s)")
        for e in findings['unauthorized_calls']:
            lines.append(f"           - {e['event']} ({e['error']}) at {e['time']}")

    if findings['no_mfa_logins']:
        lines.append(f"[HIGH]     Console logins without MFA: {len(findings['no_mfa_logins'])} event(s)")
        for e in findings['no_mfa_logins']:
            lines.append(f"           - {e['event']} at {e['time']}")

    if findings['iam_policy_changes']:
        lines.append(f"[HIGH]     IAM policy changes detected: {len(findings['iam_policy_changes'])} event(s)")
        for e in findings['iam_policy_changes']:
            lines.append(f"           - {e['event']} at {e['time']}")

    spikes = detect_spikes(hourly_activity)
    if spikes:
        for hour, count in spikes:
            lines.append(f"[INFO]     Activity spike detected at {hour}: {count} events")

    if not any([findings['root_usage'], findings['unauthorized_calls'],
                findings['no_mfa_logins'], findings['iam_policy_changes'], spikes]):
        lines.append('[OK]       No anomalies detected.')

    lines.append(f'\nTotal events analyzed: {total_events}')
    lines.append('Analysis complete.')

    report = '\n'.join(lines)
    print(report)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
        print(f'\nReport saved to {output_file}')


def main():
    parser = argparse.ArgumentParser(description='CloudTrail Log Analyzer')
    parser.add_argument('--log', required=True, help='Path to CloudTrail JSON log file')
    parser.add_argument('--output', help='Optional path to save report to a file', default=None)
    args = parser.parse_args()

    records = load_log(args.log)
    findings, hourly_activity = analyze(records)
    generate_report(findings, hourly_activity, len(records), args.output)


if __name__ == '__main__':
    main()
