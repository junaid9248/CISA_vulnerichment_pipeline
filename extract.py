
import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

url = 'https://github.com/cisagov/vulnrichment/tree/develop/1999'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cve_extraction.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class CveExtractor:
    def __init__(self, token: Optional[str] = None, output_dir: str = "cve_data"):

        self.base_url = "https://api.github.com"
        self.repo_owner = "cisagov"
        self.repo_name = "vulnrichment"
        self.token = token
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Create subdirectories for imports
        (self.output_dir / "raw_json").mkdir(exist_ok=True)
        (self.output_dir / "processed").mkdir(exist_ok=True)
        (self.output_dir / "logs").mkdir(exist_ok=True)

        self.session = self.setup_session()

        # Rate limiting
        self.rate_limit_remaining = 5000 if token else 60
        self.rate_limit_reset = 0
        self.request_lock = threading.Lock()

        # Statistics
        self.stats = {
            "total_files": 0,
            "successful_downloads": 0,
            "failed_downloads": 0,
            "total_cves": 0,
            "start_time": datetime.now(),
            "errors": []
        }

    def _check_rate_limit(self):
        """Check and handle GitHub API rate limits"""
        with self.request_lock:
            if self.rate_limit_remaining <= 1:
                wait_time = self.rate_limit_reset - time.time()
                if wait_time > 0:
                    logger.warning(f"Rate limit reached. Waiting {wait_time:.2f} seconds...")
                    time.sleep(wait_time + 5)  # Add 5 second buffer

    def _update_rate_limit(self, response: requests.Response):
        """Update rate limit information from response headers"""
        with self.request_lock:
            self.rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', self.rate_limit_remaining))
            self.rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', self.rate_limit_reset))


    #function setting up the session with retry strategy
    def set_session(self) -> requests.Session:
        s = requests.Session()

        headers = {
            "User-Agent": "CVE-Extractor/1.0",
            "Accept": "application/vnd.github.v3+json"
        }

        if self.token:
            headers["Authorization"] = f"token {self.token}"

        s.headers.update(headers)

        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        s.mount("http://", adapter)
        s.mount("https://", adapter)

        return s

    def make_request(self, url: str, params:Optional[Dict]= None) -> requests.Response:
        
        self._check_rate_limit()

        try:
            response = self.s.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            raise