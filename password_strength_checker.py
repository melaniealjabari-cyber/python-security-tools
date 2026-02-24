import re

def evaluate_password(password):
    issues = []

    if len(password) < 12:
        issues.append("Password is less than 12 characters.")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase letter.")
    if not re.search(r"[a-z]", password):
        issues.append("Missing lowercase letter.")
    if not re.search(r"\d", password):
        issues.append("Missing number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        issues.append("Missing special character.")

    return issues

if __name__ == "__main__":
    user_input = input("Enter a password to evaluate: ")
    results = evaluate_password(user_input)

    if results:
        print("\nWeak password:")
        for issue in results:
            print("-", issue)
    else:
        print("\nStrong password.")
