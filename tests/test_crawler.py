import unittest
from unittest.mock import patch, Mock
from src.crawler import Crawler

class TestCrawler(unittest.TestCase):
    """
    Unit tests for the Crawler class.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.base_url = "http://example.com"
        self.crawler = Crawler(self.base_url)

    @patch("requests.Session.get")
    def test_get_links(self, mock_get):
        """
        Test the get_links method.
        """
        # Mock the response
        mock_response = Mock()
        mock_response.text = """
        <html>
            <a href="/page1">Page 1</a>
            <a href="/page2">Page 2</a>
        </html>
        """
        mock_get.return_value = mock_response

        # Test get_links
        links = self.crawler.get_links(self.base_url)
        expected_links = [
            "http://example.com/page1",
            "http://example.com/page2",
        ]
        self.assertEqual(links, expected_links)

    @patch("requests.Session.get")
    def test_crawl(self, mock_get):
        """
        Test the crawl method.
        """
        # Mock the response
        mock_response = Mock()
        mock_response.text = """
        <html>
            <a href="/page1">Page 1</a>
            <a href="/page2">Page 2</a>
        </html>
        """
        mock_get.return_value = mock_response

        # Test crawl
        discovered_urls = self.crawler.crawl(self.base_url, max_depth=1)
        expected_urls = [
            "http://example.com",
            "http://example.com/page1",
            "http://example.com/page2",
        ]
        self.assertEqual(discovered_urls, expected_urls)

if __name__ == "__main__":
    unittest.main()
