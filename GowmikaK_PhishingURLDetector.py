"""
Project: Phishing URL Risk Detector
Author: Gowmika K
Purpose: Educational cybersecurity project that flags suspicious URL patterns.
Note: This is a heuristic demo, not a guarantee that a URL is safe or malicious.
"""

from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_WORDS = {
    "login", "verify", "update", "secure", "account", "password",
    "banking", "confirm", "wallet", "free", "prize", "urgent"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly"
}


def normalize_url(raw_url):
    """Add a scheme for parsing when the user enters a bare domain."""
    raw_url = raw_url.strip()
    if not raw_url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "http://" + raw_url
    return raw_url


def analyze_url(raw_url):
    """Return a risk score, observations, and a cautious classification."""
    normalized = normalize_url(raw_url)
    if not normalized:
        return None

    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    full_url = normalized.lower()
    score = 0
    findings = []

    if not host:
        return {
            "url": raw_url,
            "score": 100,
            "level": "Invalid URL",
            "findings": ["The URL could not be parsed. Check the address and try again."]
        }

    if len(raw_url) > 75:
        score += 1
        findings.append("The URL is unusually long.")

    try:
        ipaddress.ip_address(host)
        score += 2
        findings.append("The address uses an IP address instead of a domain name.")
    except ValueError:
        pass

    if "@" in parsed.netloc:
        score += 2
        findings.append("The URL contains '@', which can be used to confuse users.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        findings.append("The domain contains an internationalized/punycode label.")

    if host in SHORTENER_DOMAINS:
        score += 2
        findings.append("The domain is a URL-shortening service, hiding the final destination.")

    if parsed.scheme != "https":
        score += 1
        findings.append("The URL does not use HTTPS. This alone does not prove it is malicious.")

    if host.count("-") >= 2:
        score += 1
        findings.append("The domain contains multiple hyphens.")

    matched_words = sorted(word for word in SUSPICIOUS_WORDS if word in full_url)
    if matched_words:
        score += min(2, len(matched_words))
        findings.append("Potentially deceptive words found: " + ", ".join(matched_words) + ".")

    if len(host.split(".")) >= 5:
        score += 1
        findings.append("The domain has many subdomain levels.")

    if not findings:
        findings.append("No obvious warning patterns were detected by these basic checks.")

    if score >= 5:
        level = "HIGH RISK — be cautious"
    elif score >= 3:
        level = "MEDIUM RISK — inspect carefully"
    else:
        level = "LOWER RISK — still verify independently"

    return {
        "url": raw_url,
        "score": score,
        "level": level,
        "findings": findings
    }


def main():
    print("=" * 56)
    print("          PHISHING URL RISK DETECTOR")
    print("               Project by Gowmika K")
    print("=" * 56)
    print("Educational demo: it checks URL patterns only.")
    print("It does not visit the website or guarantee safety.\n")

    while True:
        url = input("Enter a URL (or type 'exit' to quit): ").strip()
        if url.lower() == "exit":
            print("Thank you for using the Phishing URL Risk Detector.")
            break

        result = analyze_url(url)
        if result is None:
            print("Please enter a URL.\n")
            continue

        print("\n--- Analysis Result ---")
        print("URL:       ", result["url"])
        print("Risk score:", result["score"])
        print("Assessment:", result["level"])
        print("Observations:")
        for item in result["findings"]:
            print(" -", item)
        print("\nReminder: Do not enter passwords or personal details on suspicious sites.")
        print("A low score does not prove a website is safe.\n")


if __name__ == "__main__":
    main()
