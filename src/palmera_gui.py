import tkinter as tk
from tkinter import scrolledtext
from .crawler import Crawler  # Relative import
from .scanner import Scanner  # Relative import
from .fuzzer import Fuzzer    # Relative import
import logging
import threading

# Rest of the code remains the same

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PalmeraGUI:
    def __init__(self, root):
        """
        Initialize the Palmera GUI.
        """
        self.root = root
        self.root.title("Palmera - Security Tool")
        self.root.geometry("800x600")

        # Input Field for Target URL
        self.url_label = tk.Label(root, text="Target URL:")
        self.url_label.pack(pady=5)
        self.url_entry = tk.Entry(root, width=80)
        self.url_entry.pack(pady=5)

        # Buttons
        self.crawl_button = tk.Button(root, text="Crawl", command=self.start_crawl)
        self.crawl_button.pack(pady=5)

        self.scan_button = tk.Button(root, text="Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)

        self.fuzz_button = tk.Button(root, text="Fuzz", command=self.start_fuzz)
        self.fuzz_button.pack(pady=5)

        # Output Area
        self.output_area = scrolledtext.ScrolledText(root, width=100, height=20)
        self.output_area.pack(pady=10)

        # Logs Area
        self.logs_area = scrolledtext.ScrolledText(root, width=100, height=10)
        self.logs_area.pack(pady=10)

    def start_crawl(self):
        """
        Start crawling the target URL in a separate thread.
        """
        target_url = self.url_entry.get().strip()
        if not target_url:
            self.log("Please enter a target URL.")
            return

        self.log(f"Starting crawl on {target_url}...")
        threading.Thread(target=self._crawl, args=(target_url,), daemon=True).start()

    def _crawl(self, target_url):
        """
        Backend logic for crawling.
        """
        try:
            crawler = Crawler(target_url)
            discovered_urls = crawler.crawl(target_url)
            self.log(f"Discovered URLs: {discovered_urls}")
        except Exception as e:
            self.log(f"Error during crawl: {e}")

    def start_scan(self):
        """
        Start scanning the target URL in a separate thread.
        """
        target_url = self.url_entry.get().strip()
        if not target_url:
            self.log("Please enter a target URL.")
            return

        self.log(f"Starting scan on {target_url}...")
        threading.Thread(target=self._scan, args=(target_url,), daemon=True).start()

    def _scan(self, target_url):
        """
        Backend logic for scanning.
        """
        try:
            scanner = Scanner(target_url)
            if scanner.scan_sql_injection():
                self.log("SQL Injection vulnerability detected!")
            if scanner.scan_xss():
                self.log("XSS vulnerability detected!")
            if scanner.scan_command_injection():
                self.log("Command Injection vulnerability detected!")
            if scanner.scan_path_traversal():
                self.log("Path Traversal vulnerability detected!")
            if scanner.scan_open_redirect():
                self.log("Open Redirect vulnerability detected!")
        except Exception as e:
            self.log(f"Error during scan: {e}")

    def start_fuzz(self):
        """
        Start fuzzing the target URL in a separate thread.
        """
        target_url = self.url_entry.get().strip()
        if not target_url:
            self.log("Please enter a target URL.")
            return

        self.log(f"Starting fuzz on {target_url}...")
        threading.Thread(target=self._fuzz, args=(target_url,), daemon=True).start()

    def _fuzz(self, target_url):
        """
        Backend logic for fuzzing.
        """
        try:
            fuzzer = Fuzzer(target_url)
            payloads = ["' OR '1'='1", "<script>alert('XSS')</script>", "; ls -la", "../../../../etc/passwd"]
            results = fuzzer.fuzz_parameters({"id": "1"}, payloads)
            for result in results:
                self.log(result)
        except Exception as e:
            self.log(f"Error during fuzz: {e}")

    def log(self, message: str):
        """
        Log messages to the logs area.
        """
        self.logs_area.insert(tk.END, message + "\n")
        self.logs_area.see(tk.END)  # Auto-scroll to the end

# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PalmeraGUI(root)
    root.mainloop()
