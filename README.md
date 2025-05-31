# payload_analyzer
Automated tool for testing and analyzing web payloads such as XSS or SQLi with summary reports.

This project is intended for educational use only.

---

# Disclaimer

> This tool is created for **learning and educational purposes only**.  
> Unauthorized scanning or access to systems you don't own is **strictly prohibited**.  
> The author is **not responsible** for any misuse.

---

# Folder Structure

payload_analyzer/
- analyzer.py               # Main script to send and analyze payloads
- utils/
    - detectors.py          # Contains analysis logic for interpreting responses
- payloads/
    - xss.json              # List of payloads (e.g., XSS payloads)
- targets/
    - testsite.json         # List of target URLs and request settings
- results/
    - report.json           # Generated JSON report
    - report.csv            # Generated CSV report
- .gitignore
- LICENSE
- README.md

---

# Features

- Send multiple payloads to multiple target URLs automatically
- Analyze HTTP responses for:
  - Reflected payloads
  - Blocked or error responses
  - Unusual delays (e.g., time-based attacks)
- Generate detailed reports in `.json` and `.csv` format
- Print summary results with Passed / Blocked / Suspicious payloads

---

# Requirements

- Python 3.7 or higher
- No external libraries required

---

# Possible Improvements
