# PhishRadar

*PhishRadar* is a Flask-based backend designed to detect phishing attempts in URLs, domains, emails/text, and attachments. This project is built for *demo and educational purposes* and provides heuristic checks, optional VirusTotal integration, and a basic ML-based classifier for phishing detection.

---

## Features

- *URL/Domain Analysis*
  - Heuristic checks (HTTPS, redirects, SSL validation)
  - Domain age analysis using WHOIS
  - Optional VirusTotal lookup for URLs

- *Email/Text Analysis*
  - Basic heuristics for suspicious keywords
  - Optional transformer-based text classification for phishing-like patterns

- *Attachment Analysis*
  - Computes SHA256 hash
  - Optional VirusTotal scan for files

- *Developer Notes*
  - Demo/educational use only
  - For production, you must add authentication, input sanitization, and rate-limiting

---

## Setup

1. *Clone the repository*
   ```bash
   git clone https://github.com/Vasundharaaaa/PhishRadar.git
   cd PhishRadar
2. *Create a virtual environment*
    ```bash
    .\venv\Scripts\Activate.ps1
3. *Activate the virtual environment*
   ```bash
   git clone https://github.com/Vasundharaaaa/PhishRadar.git
   cd PhishRadar
4. *Install required dependencies*
    ```bash
    pip install -r requirements.txt
5. *Usage*
   ```bash
   python app.py
   http://127.0.0.1:5000
6. *License*
This project is licensed under the MIT License.

Created by Vasuntthara
