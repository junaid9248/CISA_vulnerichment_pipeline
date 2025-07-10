#!/usr/bin/env python3
"""
CISA Vulnrichment CVE Data Extractor

This script extracts CVE JSON files from the CISA Vulnrichment GitHub repository
and processes them for comprehensive vulnerability analysis. It demonstrates
professional software development practices including:

- GitHub API integration with proper authentication
- Rate limiting and error handling
- Concurrent processing for improved performance
- Progress tracking and logging
- Data validation and quality assurance

Author: [Your Name]
Date: 2025
Repository: https://github.com/cisagov/vulnrichment
"""

import os
import sys
import json
import time
import logging
import argparse
import base64
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

class CVEExtractor:
    """
    Main class for extracting CVE data from CISA Vulnrichment repository
    """

    def __init__(self, token: Optional[str] = None, output_dir: str = "cve_data"):
        """
        Initialize the CVE extractor

        Args:
            token: GitHub personal access token (optional but recommended)
            output_dir: Directory to save extracted files
        """
        self.base_url = "https://api.github.com"
        self.repo_owner = "cisagov"
        self.repo_name = "vulnrichment"
        self.token = token
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Create subdirectories
        (self.output_dir / "raw_json").mkdir(exist_ok=True)
        (self.output_dir / "processed").mkdir(exist_ok=True)
        (self.output_dir / "logs").mkdir(exist_ok=True)

        # Setup session with retry strategy
        self.session = self._setup_session()

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

    def _setup_session(self) -> requests.Session:
        """Setup requests session with proper headers and retry strategy"""
        session = requests.Session()

        # Set headers
        headers = {
            "User-Agent": "CVE-Extractor/1.0",
            "Accept": "application/vnd.github.v3+json"
        }

        if self.token:
            headers["Authorization"] = f"token {self.token}"

        session.headers.update(headers)

        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

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

    def _make_request(self, url: str, params: Dict = None) -> requests.Response:
        """Make a rate-limited request to GitHub API"""
        self._check_rate_limit()

        try:
            response = self.session.get(url, params=params, timeout=30)
            self._update_rate_limit(response)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            raise

    def get_years_available(self) -> List[str]:
        """Get list of years available in the repository"""
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/"

        try:
            response = self._make_request(url)
            contents = response.json()

            years = []
            for item in contents:
                if item["type"] == "dir" and item["name"].isdigit():
                    years.append(item["name"])

            logger.info(f"Found {len(years)} years: {sorted(years)}")
            return sorted(years)

        except Exception as e:
            logger.error(f"Failed to get years: {e}")
            return []

    def get_tree_recursive(self, ref: str = "develop") -> List[Dict]:
        """Get recursive tree of all files in repository"""
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/tree/{ref}"
        params = {"recursive": "1"}

        try:
            response = self._make_request(url, params)
            tree_data = response.json()

            # Filter for JSON files only
            json_files = [
                item for item in tree_data["tree"]
                if item["type"] == "blob" and item["path"].endswith(".json")
                and "CVE-" in item["path"]  # Only CVE files
            ]

            logger.info(f"Found {len(json_files)} CVE JSON files")
            return json_files

        except Exception as e:
            logger.error(f"Failed to get tree: {e}")
            return []

    def download_file(self, file_info: Dict) -> Optional[Dict]:
        """
        Download a single JSON file and return parsed content

        Args:
            file_info: File information from GitHub API

        Returns:
            Parsed JSON content or None if failed
        """
        try:
            # Use raw.githubusercontent.com for direct file access
            raw_url = f"https://raw.githubusercontent.com/{self.repo_owner}/{self.repo_name}/develop/{file_info['path']}"

            response = requests.get(raw_url, timeout=30)
            response.raise_for_status()

            # Parse JSON
            cve_data = response.json()

            # Save raw file
            file_path = self.output_dir / "raw_json" / Path(file_info["path"]).name
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(cve_data, f, indent=2, ensure_ascii=False)

            self.stats["successful_downloads"] += 1
            return cve_data

        except Exception as e:
            logger.error(f"Failed to download {file_info['path']}: {e}")
            self.stats["failed_downloads"] += 1
            self.stats["errors"].append({
                "file": file_info["path"],
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            return None

    def extract_cve_metadata(self, cve_data: Dict) -> Dict:
        """
        Extract key metadata from CVE JSON data

        Args:
            cve_data: Parsed CVE JSON data

        Returns:
            Dictionary containing extracted metadata
        """
        try:
            metadata = {
                "cve_id": cve_data.get("cveMetadata", {}).get("cveId"),
                "state": cve_data.get("cveMetadata", {}).get("state"),
                "date_published": cve_data.get("cveMetadata", {}).get("datePublished"),
                "date_updated": cve_data.get("cveMetadata", {}).get("dateUpdated"),
                "assigner": cve_data.get("cveMetadata", {}).get("assignerShortName"),
                "data_version": cve_data.get("dataVersion"),
            }

            # Extract CISA ADP information
            containers = cve_data.get("containers", {})
            adp_containers = containers.get("adp", [])

            cisa_adp = None
            for adp in adp_containers:
                if adp.get("title") == "CISA ADP Vulnrichment":
                    cisa_adp = adp
                    break

            if cisa_adp:
                # Extract SSVC scores
                metrics = cisa_adp.get("metrics", [])
                for metric in metrics:
                    other = metric.get("other", {})
                    if other.get("type") == "ssvc":
                        content = other.get("content", {})
                        options = content.get("options", [])

                        for option in options:
                            if "Exploitation" in option:
                                metadata["ssvc_exploitation"] = option["Exploitation"]
                            if "Automatable" in option:
                                metadata["ssvc_automatable"] = option["Automatable"]
                            if "Technical Impact" in option:
                                metadata["ssvc_technical_impact"] = option["Technical Impact"]

                # Check for KEV status
                for metric in metrics:
                    other = metric.get("other", {})
                    if other.get("type") == "kev":
                        metadata["kev_date_added"] = other.get("content", {}).get("dateAdded")
                        metadata["is_kev"] = True
                        break
                else:
                    metadata["is_kev"] = False

            # Extract CNA information
            cna = containers.get("cna", {})
            if cna:
                # Get CVSS scores
                cna_metrics = cna.get("metrics", [])
                for metric in cna_metrics:
                    if "cvssV3_1" in metric:
                        cvss = metric["cvssV3_1"]
                        metadata["cvss_version"] = cvss.get("version")
                        metadata["cvss_base_score"] = cvss.get("baseScore")
                        metadata["cvss_base_severity"] = cvss.get("baseSeverity")
                        metadata["cvss_vector_string"] = cvss.get("vectorString")

                # Get problem types (CWE)
                problem_types = cna.get("problemTypes", [])
                cwes = []
                for pt in problem_types:
                    descriptions = pt.get("descriptions", [])
                    for desc in descriptions:
                        if desc.get("type") == "CWE":
                            cwes.append(desc.get("cweId"))
                metadata["cwes"] = cwes

                # Get affected products
                affected = cna.get("affected", [])
                vendors = set()
                products = set()
                for item in affected:
                    if "vendor" in item:
                        vendors.add(item["vendor"])
                    if "product" in item:
                        products.add(item["product"])

                metadata["vendors"] = list(vendors)
                metadata["products"] = list(products)

            return metadata

        except Exception as e:
            logger.error(f"Failed to extract metadata: {e}")
            return {}

    def process_files_concurrently(self, file_list: List[Dict], max_workers: int = 5) -> List[Dict]:
        """
        Process multiple files concurrently

        Args:
            file_list: List of file information dictionaries
            max_workers: Maximum number of concurrent workers

        Returns:
            List of extracted metadata
        """
        logger.info(f"Processing {len(file_list)} files with {max_workers} workers")
        self.stats["total_files"] = len(file_list)

        extracted_data = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all download tasks
            future_to_file = {
                executor.submit(self.download_file, file_info): file_info
                for file_info in file_list
            }

            # Process completed downloads
            for future in as_completed(future_to_file):
                file_info = future_to_file[future]

                try:
                    cve_data = future.result()
                    if cve_data:
                        # Extract metadata
                        metadata = self.extract_cve_metadata(cve_data)
                        if metadata:
                            extracted_data.append(metadata)
                            self.stats["total_cves"] += 1

                        # Log progress
                        if len(extracted_data) % 50 == 0:
                            logger.info(f"Processed {len(extracted_data)} files...")

                except Exception as e:
                    logger.error(f"Error processing {file_info['path']}: {e}")

        return extracted_data

    def save_processed_data(self, data: List[Dict], filename: str = "processed_cves.json"):
        """Save processed data to JSON file"""
        output_path = self.output_dir / "processed" / filename

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"Saved processed data to {output_path}")

    def generate_statistics_report(self) -> Dict:
        """Generate comprehensive statistics report"""
        end_time = datetime.now()
        duration = end_time - self.stats["start_time"]

        report = {
            "execution_summary": {
                "start_time": self.stats["start_time"].isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration.total_seconds(),
                "duration_formatted": str(duration)
            },
            "file_statistics": {
                "total_files_attempted": self.stats["total_files"],
                "successful_downloads": self.stats["successful_downloads"],
                "failed_downloads": self.stats["failed_downloads"],
                "success_rate": (self.stats["successful_downloads"] / max(self.stats["total_files"], 1)) * 100
            },
            "cve_statistics": {
                "total_cves_processed": self.stats["total_cves"]
            },
            "errors": self.stats["errors"][:10]  # First 10 errors
        }

        # Save report
        report_path = self.output_dir / "logs" / f"extraction_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        return report

    def extract_by_years(self, years: List[str], max_workers: int = 5) -> List[Dict]:
        """
        Extract CVE data for specific years

        Args:
            years: List of years to extract
            max_workers: Maximum concurrent workers

        Returns:
            List of extracted CVE metadata
        """
        all_data = []

        for year in years:
            logger.info(f"Processing year {year}")

            # Get files for this year
            tree_data = self.get_tree_recursive()
            year_files = [
                item for item in tree_data
                if item["path"].startswith(f"{year}/") and "CVE-" in item["path"]
            ]

            if not year_files:
                logger.warning(f"No files found for year {year}")
                continue

            logger.info(f"Found {len(year_files)} files for year {year}")

            # Process files for this year
            year_data = self.process_files_concurrently(year_files, max_workers)
            all_data.extend(year_data)

            # Save intermediate results
            if year_data:
                year_filename = f"cves_{year}.json"
                self.save_processed_data(year_data, year_filename)

        return all_data


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Extract CVE data from CISA Vulnrichment repository")
    parser.add_argument("--token", help="GitHub personal access token", default=os.getenv("GITHUB_TOKEN"))
    parser.add_argument("--years", nargs="+", help="Specific years to extract (e.g., 2023 2024)")
    parser.add_argument("--output-dir", default="cve_data", help="Output directory")
    parser.add_argument("--max-workers", type=int, default=5, help="Maximum concurrent workers")
    parser.add_argument("--all-years", action="store_true", help="Extract all available years")

    args = parser.parse_args()

    # Create extractor
    extractor = CVEExtractor(token=args.token, output_dir=args.output_dir)

    try:
        if args.all_years:
            # Get all available years
            years = extractor.get_years_available()
        elif args.years:
            years = args.years
        else:
            # Default to recent years
            years = ["2023", "2024", "2025"]

        logger.info(f"Starting extraction for years: {years}")

        # Extract data
        all_data = extractor.extract_by_years(years, args.max_workers)

        # Save complete dataset
        if all_data:
            extractor.save_processed_data(all_data, "complete_dataset.json")

        # Generate and display report
        report = extractor.generate_statistics_report()

        print("\n" + "="*50)
        print("EXTRACTION COMPLETE")
        print("="*50)
        print(f"Total CVEs processed: {report['cve_statistics']['total_cves_processed']}")
        print(f"Success rate: {report['file_statistics']['success_rate']:.2f}%")
        print(f"Duration: {report['execution_summary']['duration_formatted']}")
        print(f"Output directory: {args.output_dir}")

        if report['file_statistics']['failed_downloads'] > 0:
            print(f"\nWarning: {report['file_statistics']['failed_downloads']} downloads failed")
            print("Check the log file for details.")

    except KeyboardInterrupt:
        logger.info("Extraction interrupted by user")
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
