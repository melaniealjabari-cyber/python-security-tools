from collections import defaultdict

def analyze_log(file_path):
    failed_attempts = defaultdict(int)

    with open(file_path, "r") as file:
        for line in file:
            if "FAILED LOGIN" in line:
                parts = line.strip().split()
                ip_address = parts[-1]
                failed_attempts[ip_address] += 1

    return failed_attempts


THRESHOLD = 3

import sys

if __name__ == "__main__":
    # Usage: python3 log_analyzer.py sample_log.txt 3
    log_file = sys.argv[1] if len(sys.argv) > 1 else "sample_log.txt"
    threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 3

    results = analyze_log(log_file)

    print("Failed Login Attempts by IP:\n")

    for ip, count in results.items():
        if count >= threshold:
            print(f"[ALERT] {ip} exceeded threshold with {count} failed attempts")
        else:
            print(f"{ip} : {count} failed attempts")
