import logging
from typing import List, Dict
import requests

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Fuzzer:
    """
    A fuzzer to test inputs for vulnerabilities.
    """

    def __init__(self, target_url: str):
        """
        Initialize the fuzzer with a target URL.

        :param target_url: The URL to fuzz.
        """
        self.target_url = target_url
        self.session = requests.Session()

    def fuzz_parameters(self, params: Dict[str, str], payloads: List[str]) -> List[str]:
        """
        Fuzz parameters with a list of payloads.

        :param params: The parameters to fuzz.
        :param payloads: The list of payloads to test.
        :return: A list of responses indicating potential vulnerabilities.
        """
        results = []
        for payload in payloads:
            try:
                fuzzed_params = {key: payload for key in params.keys()}
                response = self.session.get(self.target_url, params=fuzzed_params)
                if "error" in response.text.lower():
                    results.append(f"Potential vulnerability found with payload: {payload}")
            except requests.RequestException as e:
                logger.error(f"Failed to fuzz {self.target_url}: {e}")
        return results

    def fuzz_headers(self, headers: Dict[str, str], payloads: List[str]) -> List[str]:
        """
        Fuzz HTTP headers with a list of payloads.

        :param headers: The headers to fuzz.
        :param payloads: The list of payloads to test.
        :return: A list of responses indicating potential vulnerabilities.
        """
        results = []
        for payload in payloads:
            try:
                fuzzed_headers = {key: payload for key in headers.keys()}
                response = self.session.get(self.target_url, headers=fuzzed_headers)
                if "error" in response.text.lower():
                    results.append(f"Potential vulnerability found with payload: {payload}")
            except requests.RequestException as e:
                logger.error(f"Failed to fuzz {self.target_url}: {e}")
        return results
