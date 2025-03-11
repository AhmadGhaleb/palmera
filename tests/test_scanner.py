import unittest
from unittest.mock import patch, Mock
from src.scanner import Scanner

class TestScanner(unittest.TestCase):
    """
    Unit tests for the Scanner class.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.target_url = "http://example.com"
        self.scanner = Scanner(self.target_url)

    @patch("requests.Session.get")
    def test_scan_sql_injection(self, mock_get):
        """
        Test the scan_sql_injection method.
        """
        # Mock the response for SQL injection vulnerability
        mock_response_vulnerable = Mock()
        mock_response_vulnerable.text = "SQL syntax error"
        mock_get.return_value = mock_response_vulnerable

        # Test SQL injection scan (vulnerable)
        result = self.scanner.scan_sql_injection()
        self.assertTrue(result)

        # Mock the response for no vulnerability
        mock_response_safe = Mock()
        mock_response_safe.text = "No error"
        mock_get.return_value = mock_response_safe

        # Test SQL injection scan (not vulnerable)
        result = self.scanner.scan_sql_injection()
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
