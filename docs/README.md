# Palmera

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)
![GitHub Stars](https://img.shields.io/github/stars/AhmadGhaleb/palmera?style=social)

Palmera is a powerful security tool designed to help cybersecurity researchers and penetration testers identify vulnerabilities in web applications. It provides features like **crawling**, **fuzzing**, and **vulnerability scanning** to automate the process of finding common security issues.

---

## Features

- **Crawling**: Discover endpoints and parameters on a target website.
- **Fuzzing**: Test inputs for vulnerabilities using customizable payloads.
- **Vulnerability Scanning**: Detect common vulnerabilities such as:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Path Traversal
  - Open Redirect
- **User-Friendly GUI**: Intuitive interface for easy interaction.
- **Extensible**: Add custom payloads and plugins for advanced testing.

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Kali Linux (recommended)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/palmera.git
   cd palmera

2. Install dependencies:
pip install -r requirements.txt


3. Run the tool:
python3 src/main.py

Usage

Run the tool directly from the command line:
python3 src/main.py

Example Commands

Crawl a website:
python3 src/main.py --crawl --url http://example.com

Scan for vulnerabilities:
python3 src/main.py --scan --url http://example.com

Fuzz parameters:
python3 src/main.py --fuzz --url http://example.com
