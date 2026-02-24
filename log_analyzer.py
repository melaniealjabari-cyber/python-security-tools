from collections import defaultdict
import sys

def parse_line(line: str) -> dict | None:
    """
    Expected format:
    2026-02-24T02:14:33Z FAIL user=admin ip=10.0.0.5 service=rdp
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split()
    if len(parts) < 3:
        return None

    timestamp = parts[0]
    status = parts[1]  # FAIL or SUCCESS

    fields = {"timestamp": timestamp, "status": status}

    for token in parts[2:]:
        if "=" in token:
            k, v = token.split("=", 1)
            fields[k] = v

    # Require at least user and ip to be useful
    if "user" not in fields or "ip" not in fields:
        return None

    return fields


def analyze_log(file_path: str):
    failed_by_ip = defaultdict(int)
    failed_by_user = defaultdict(int)
    success_after_failures = set()  # (user, ip)
    events = []

    with open(file_path, "r") as f:
        for line in f:
            evt = parse_line(line)
            if not evt:
                continue
            events.append(evt)

            user = evt["user"]
            ip = evt["ip"]
            status = evt["status"]

            if status == "FAIL":
                failed_by_ip[ip] += 1
                failed_by_user[user] += 1

            elif status == "SUCCESS":
                # compromise pattern: any prior failures for same ip or same user
                if failed_by_ip[ip] > 0 or failed_by_user[user] > 0:
                    success_after_failures.add((user, ip))

    return dict(failed_by_ip), dict(failed_by_user), success_after_failures, events


if __name__ == "__main__":
    # Usage: python3 log_analyzer.py sample_log.txt 3
    log_file = sys.argv[1] if len(sys.argv) > 1 else "sample_log.txt"
    threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 3

    failed_by_ip, failed_by_user, compromise_pairs, events = analyze_log(log_file)

    # Build alert lines
    alert_lines = []
    alert_lines.append("SOC Alert Summary")
    alert_lines.append("=================")
    alert_lines.append(f"Source log: {log_file}")
    alert_lines.append(f"Threshold: {threshold}")
    alert_lines.append("")

    # Severity logic
    # HIGH: success after failures for a (user, ip) pair
    for (user, ip) in sorted(compromise_pairs):
        count_ip = failed_by_ip.get(ip, 0)
        alert_lines.append(
            f"[HIGH] Possible compromise: user={user} ip={ip} failures={count_ip} then SUCCESS"
        )

    # MED: brute force suspected based on failures by IP
    for ip, count in sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True):
        if count >= threshold and all(ip != pair[1] for pair in compromise_pairs):
            alert_lines.append(f"[MED] Brute force suspected: ip={ip} failures={count}")

    # LOW: small failure counts
    for ip, count in sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True):
        if count < threshold:
            alert_lines.append(f"[LOW] Noise: ip={ip} failures={count}")

    # Print to terminal
    print("\n".join(alert_lines))

    # Write to file
    with open("alert_summary.txt", "w") as out:
        out.write("\n".join(alert_lines) + "\n")

    print("\nAlert summary written to alert_summary.txt")
