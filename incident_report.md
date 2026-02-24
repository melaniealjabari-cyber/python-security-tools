## MITRE ATT&CK Mapping


Technique: T1110 – Brute Force  
Repeated failed login attempts align with brute force password guessing behavior.# Incident Report: Suspicious Login Activity

## Summary
Multiple failed login attempts were detected from IP address 10.0.0.5.

## Findings
- IP 10.0.0.5 generated 3 failed login attempts.
- Threshold for alerting is set at 3 attempts.
- Alert condition was triggered.

## Potential Risk
Repeated failed login attempts may indicate:
- Brute force attack
- Credential stuffing attempt
- Automated login scanning

## Recommended Action
- Investigate source IP
- Check for additional activity from same subnet
- Consider temporary block if pattern continues

## Tool Used
Custom Python log analyzer script (`log_analyzer.py`)

## Escalation: Possible Compromise Detected
The analyzer detected a **SUCCESS login after repeated FAILED attempts** from the same IP (10.0.0.5).  
This pattern can indicate **credential compromise** (failed guessing followed by successful access).
