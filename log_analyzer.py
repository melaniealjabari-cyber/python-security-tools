
from collections import defaultdict
import sys

def analyze_log(file_path: str):
    failed_attempts = defaultdict(int)
    success_after_failures = set()

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            # Example: "FAILED LOGIN attempt from 10.0.0.5"
            if "FAILED LOGIN" in line:
                ip = line.split()[-1]
                failed_attempts[ip] += 1

            # Example: "SUCCESS LOGIN from 10.0.0.5"
            if "SUCCESS LOGIN" in line:
                ip = line.split()[-1]
                if failed_attempts[ip] > 0:
                    success_after_failures.add(ip)

    return dict(failed_attempts), success_after_failures


if __name__ == "__main__":
    # Usage: python3 log_analyzer.py sample_log.txt 3
    log_file = sys.argv[1] if len(sys.argv) > 1 else "sample_log.txt"
    threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 3

    failed_counts, success_after = analyze_log(log_file)

    print("Login Analysis:\n")

    for ip, count in failed_counts.items():
        # HIGH: success after failures (possible compromise)
        if ip in success_after and count >= threshold:
            print(f"[HIGH] Possible compromise: {ip} had {count} failed attempts THEN a SUCCESS login")
        # MED: lots of failures, no success
        elif count >= threshold:
            print(f"[MED] Brute force suspected: {ip} has {count} failed attempts")
        # LOW: small noise
        else:
            print(f"[LOW] {ip} : {count} failed attempts")
