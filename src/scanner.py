import logging
from typing import Dict, List
import requests

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Scanner:
    """
    A vulnerability scanner to detect common web vulnerabilities.
    """

    def __init__(self, target_url: str):
        """
        Initialize the scanner with a target URL.

        :param target_url: The URL to scan.
        """
        self.target_url = target_url
        self.session = requests.Session()

    def scan_sql_injection(self) -> bool:
        """
        Scan for SQL injection vulnerabilities.

        :return: True if a vulnerability is detected, otherwise False.
        """
        payload = "' OR '1'='1"
        try:
            response = self.session.get(self.target_url, params={"id": payload})
            if "error" in response.text.lower():
                logger.warning(f"SQL Injection vulnerability detected at {self.target_url}")
                return True
            return False
        except requests.RequestException as e:
            logger.error(f"Failed to scan {self.target_url}: {e}")
            return False

    def scan_xss(self) -> bool:
        """
        Scan for Cross-Site Scripting (XSS) vulnerabilities.

        :return: True if a vulnerability is detected, otherwise False.
        """
        payload = "<script>alert('XSS')</script>"
        try:
            response = self.session.post(self.target_url, data={"input": payload})
            if payload in response.text:
                logger.warning(f"XSS vulnerability detected at {self.target_url}")
                return True
        except requests.RequestException as e:
            logger.error(f"Failed to scan {self.target_url}: {e}")
        return False

    def scan_command_injection(self) -> bool:
        """
        Scan for command injection vulnerabilities.

        :return: True if a vulnerability is detected, otherwise False.
        """
        payload = "; ls -la"
        try:
            response = self.session.get(self.target_url, params={"input": payload})
            if "root" in response.text.lower():
                logger.warning(f"Command Injection vulnerability detected at {self.target_url}")
                return True
            return False
        except requests.RequestException as e:
            logger.error(f"Failed to scan {self.target_url}: {e}")
            return False

    def scan_path_traversal(self) -> bool:
        """
        Scan for path traversal vulnerabilities.

        :return: True if a vulnerability is detected, otherwise False.
        """
        payload = "../../../../etc/passwd"
        try:
            response = self.session.get(self.target_url, params={"file": payload})
            if "root:" in response.text:
                logger.warning(f"Path Traversal vulnerability detected at {self.target_url}")
                return True
            return False
        except requests.RequestException as e:
            logger.error(f"Failed to scan {self.target_url}: {e}")
            return False

    def scan_open_redirect(self) -> bool:
        """
        Scan for open redirect vulnerabilities.

        :return: True if a vulnerability is detected, otherwise False.
        """
        payload = "https://evil.com"
        try:
            response = self.session.get(self.target_url, params={"redirect": payload})
            if "evil.com" in response.url:
                logger.warning(f"Open Redirect vulnerability detected at {self.target_url}")
                return True
            return False
        except requests.RequestException as e:
            logger.error(f"Failed to scan {self.target_url}: {e}")
            return False
