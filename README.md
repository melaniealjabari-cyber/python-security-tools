# Blue team python security tools

A collection of small defensive security scripts built to strengthen hands-on blue team skills.

## Focus Areas
- Password auditing
- Log analysis
- Brute force detection
- Basic anomaly detection

## Purpose
These tools are built as part of my cybersecurity training to simulate real-world SOC tasks.

## How to Run

### password_strength_checker.py
Run the script and enter a password when prompted to evaluate its strength.

### log_analyzer.py
Analyzes `sample_log.txt` and flags IP addresses that exceed the failed login threshold.
## Usage

### Password checker
```bash
python3 password_strength_checker.py
- Detects brute force attempts and flags **possible compromise** when a SUCCESS login follows repeated FAILURES.
