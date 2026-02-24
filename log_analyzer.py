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


if __name__ == "__main__":
    log_file = "sample_log.txt"
    results = analyze_log(log_file)

    print("Failed Login Attempts by IP:\n")

    for ip, count in results.items():
        print(f"{ip} : {count} failed attempts")
