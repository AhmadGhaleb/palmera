import logging
from typing import List, Dict
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Crawler:
    """
    A web crawler to discover URLs and endpoints on a website.
    """

    def __init__(self, base_url: str):
        """
        Initialize the crawler with a base URL.

        :param base_url: The starting URL for crawling.
        """
        self.base_url = base_url
        self.visited_urls = set()
        self.session = requests.Session()

    def get_links(self, url: str) -> List[str]:
        """
        Extract all links from a given URL.

        :param url: The URL to extract links from.
        :return: A list of absolute URLs.
        """
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            links = []
            for link in soup.find_all("a", href=True):
                absolute_url = urljoin(url, link["href"])
                links.append(absolute_url)
            return links
        except requests.RequestException as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return []

    def crawl(self, url: str, max_depth: int = 2) -> List[str]:
        """
        Recursively crawl a website up to a specified depth.

        :param url: The URL to start crawling from.
        :param max_depth: The maximum depth to crawl.
        :return: A list of discovered URLs.
        """
        if max_depth == 0 or url in self.visited_urls:
            return []

        self.visited_urls.add(url)
        logger.info(f"Crawling: {url}")

        links = self.get_links(url)
        for link in links:
            if link not in self.visited_urls:
                self.crawl(link, max_depth - 1)  # Recursively crawl

        return list(self.visited_urls)  # Return all visited URLs
