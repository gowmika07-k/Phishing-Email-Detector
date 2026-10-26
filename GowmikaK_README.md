# Phishing URL Risk Detector
**Author:** Gowmika K  
**Program:** IBM SkillsBuild Cyber Security 2026 — BharatCares

## Project overview
A beginner-friendly Python cybersecurity project that checks a URL for common suspicious patterns and gives a cautious risk assessment. It does not open or connect to the submitted website.

## Features
- Checks URL length and HTTPS usage
- Looks for IP-address hosts, `@` symbols, URL shorteners, punycode labels, multiple hyphens, many subdomains, and suspicious words
- Displays a simple risk score, observations, and a risk category
- Runs in the terminal and uses only Python's standard library

## Technologies
- Python 3
- `urllib.parse`, `ipaddress`, and `re` (standard-library modules)

## Files
- `GowmikaK_PhishingURLDetector.py` — complete source code
- `requirements.txt` — dependency list
- `GowmikaK_PhishingURLDetector.ipynb` — notebook version
- `GowmikaK_PhishingURLDetector_Report.docx` — project report

## Setup and run
1. Install Python 3.10 or later from https://www.python.org/downloads/
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Run:

   ```bash
   python GowmikaK_PhishingURLDetector.py
   ```

5. Enter a test URL, for example `http://secure-login-example.test/account`, or type `exit` to quit.

No `pip install` command is required because the project uses only the Python standard library.

## Example test cases
Use fictional/example domains for demonstrations. Do not enter passwords or other personal information.

- `https://www.example.com` — likely to receive a lower score from these basic checks
- `http://secure-login-example.test/account` — likely to receive a higher score due to HTTP and suspicious words
- `http://192.0.2.10/verify` — likely to receive a higher score due to IP address, HTTP, and suspicious words

## Limitations and ethical use
This is a learning prototype, not a production anti-phishing product. It uses simple rules rather than a trained machine-learning model or live threat-intelligence feeds. Attackers can evade these checks, and legitimate URLs can be flagged. A low score does not mean a website is safe. Never test by visiting suspicious websites or entering credentials.
