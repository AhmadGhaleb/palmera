import logging
from src.crawler import Crawler
from src.scanner import Scanner
from src.fuzzer import Fuzzer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """
    Main entry point for the Palmera tool.
    """
    # Allow user to input target URL
    target_url = input("Enter the target URL to scan: ").strip()
    if not target_url.startswith(("http://", "https://")):
        logger.error("Invalid URL. Please include http:// or https://")
        return

    logger.info(f"Starting Palmera scan on {target_url}")

    # Crawl the website
    crawler = Crawler(target_url)
    discovered_urls = crawler.crawl(target_url)
    logger.info(f"Discovered URLs: {discovered_urls}")

    # Scan for vulnerabilities
    scanner = Scanner(target_url)
    if scanner.scan_sql_injection():
        logger.warning("SQL Injection vulnerability detected!")
    if scanner.scan_xss():
        logger.warning("XSS vulnerability detected!")
    if scanner.scan_command_injection():
        logger.warning("Command Injection vulnerability detected!")
    if scanner.scan_path_traversal():
        logger.warning("Path Traversal vulnerability detected!")
    if scanner.scan_open_redirect():
        logger.warning("Open Redirect vulnerability detected!")

    # Fuzz parameters
    fuzzer = Fuzzer(target_url)
    payloads = ["' OR '1'='1", "<script>alert('XSS')</script>", "; ls -la", "../../../../etc/passwd"]
    results = fuzzer.fuzz_parameters({"id": "1"}, payloads)
    for result in results:
        logger.warning(result)

if __name__ == "__main__":
    main()
