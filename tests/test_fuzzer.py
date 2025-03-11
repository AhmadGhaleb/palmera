import unittest
from unittest.mock import patch, Mock
from src.fuzzer import Fuzzer

class TestFuzzer(unittest.TestCase):
    """
    Unit tests for the Fuzzer class.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.target_url = "http://example.com"
        self.fuzzer = Fuzzer(self.target_url)

    @patch("requests.Session.get")
    def test_fuzz_parameters(self, mock_get):
        """
        Test the fuzz_parameters method.
        """
        # Mock the response for fuzzing
        mock_response = Mock()
        mock_response.text = "error"
        mock_get.return_value = mock_response

        # Test fuzzing
        params = {"id": "1"}
        payloads = ["' OR '1'='1", "<script>alert('XSS')</script>"]
        results = self.fuzzer.fuzz_parameters(params, payloads)
        expected_results = [
            "Potential vulnerability found with payload: ' OR '1'='1",
            "Potential vulnerability found with payload: <script>alert('XSS')</script>",
        ]
        self.assertEqual(results, expected_results)

if __name__ == "__main__":
    unittest.main()
