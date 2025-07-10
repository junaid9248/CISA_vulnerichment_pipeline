import requests
import json
import csv
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Any


class cveExtractor:

    def __init__(self, token: Optional[str] = None):
        self.base_url = "https://api.github.com"
        self.raw_url = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
        self.repo_owner = "cisagov"
        self.repo_name = "vulnrichment"
        self.token = token
        self.headers = {
            'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
            'Accept': 'application/vnd.github.v3+json'
        }

        self.cve_list = []

        #Establish a new session
        self.session = requests.Session()
        self.session .headers.update(self.headers)
        
        # Test API connection
        self._test_connection()


    def _test_connection(self):
        try:
            response = self.session.get(f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}")
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error testing API connection: {e}")

        if response.status_code == 200:
            print("API connection successful.")
            print(f"Successfully connected to {self.repo_owner}/{self.repo_name} repository.")

            # Check rate limits
            rate_limit_remaining = response.headers.get('x-ratelimit-remaining')
            rate_limit_reset = response.headers.get('x-ratelimit-reset')

            if rate_limit_remaining:
                print(f"✓ API Rate limit remaining: {rate_limit_remaining}")
                if int(rate_limit_remaining) < 60:
                    print("⚠️  Warning: Low rate limit remaining. Consider using a GitHub token.")
        else:
            print(f"❌ Failed to get file : {response.status_code}")
            return None

    def _handle_rate_limit(self):
        """Handle GitHub API rate limiting"""
        response = self.session.get(f"{self.base_url}/rate_limit")
        if response.status_code == 403 and 'rate limit' in response.text.lower():
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            current_time = int(time.time())
            wait_time = reset_time - current_time + 10  # Add 10 seconds buffer
            
            if wait_time > 0:
                print(f"⏳ Rate limit exceeded. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                return True
        return False
    
    def get_years(self) -> List[str]:
        """Get list of years available in the repository"""
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/data"
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                years = []

                for item in data:
                    if item['type'] == 'dir' and item['name'] != '.github':
                        years.append(item['name'])
                print(f"Number of available years: {len(years)}")
                return years
            else:
                print(f"Error fetching years: {response.status_code}")
                return []
        except requests.RequestException as e:
            print(f"Error fetching years: {e}")
            return []
        
    def get_cve_files_for_year(self, year:str) -> List[Dict]:
        """Get CVE data for a specific year"""

        #Storing the cve data as a list of dictionaries
        year_data = {'year': year, 'subdirs': {}}
        
        #Defining the URL for the year directory
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/data/{year}"
        params = {'ref': self.branch}

        try:
            response = self.session.get(url)
    
            if self._handle_rate_limit(response):
                response = self.session.get(url, params=params)

            if response.status_code == 200:
                year_response_data = response.json()
                
                # Extract subdirectory data for the given year
                for item in year_response_data:
                    if item['type']=='dir':
                        #Extracting name of subdir 
                        subdir_name = item['name']

                        if not any(subdir_name in d['subdirs'] for d in year_data['subdirs']):
                            year_data['subdirs'][subdir_name] = []


                        #Constructing the URL for the subdirectory
                        subdir_url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/data/{year}/{subdir_name}"
                        subdir_response = self.session.get(subdir_url)

                        if self._handle_rate_limit(subdir_response):
                            subdir_response = self.session.get(subdir_url, params=params)

                        if subdir_response.status_code == 200:
                            for sub_item in subdir_response.json():
                                if sub_item['type'] == 'file' and sub_item['name'].endswith('.json'):
                                    year_data['subdirs'][subdir_name].append({
                                        'name': sub_item['name'],
                                        'path': sub_item['path'],
                                        'download_url': sub_item['download_url'],
                                        'sha': sub_item['sha'],
                                        'size': sub_item['size']
                                    })
                                else:
                                    print(f"Failed to get files in {subdir_name}: {subdir_response.status_code}")
                                    time.sleep(0.1)
            else:
                print(f"Failed to get year directory {year}: {response.status_code}") 
                time.sleep(0.1)

        except requests.RequestException as e:
            print(f"❌ Error getting CVE files for year {year}: {e}")

        # Count total files
        total_files = sum(len(files) for files in year_data['subdirs'].values())
        print(f"  ✓ Found {total_files} CVE files for year {year} across {len(year_data['subdirs'])} subdirectories")
        
        # Add year data to the cve_list if not already present
        if not year_data in self.cve_list:
            self.cve_list.append(year_data)
            
        return year_data




extractor = cveExtractor()

all_years = extractor.get_years()

if not (all_years):
    print("No years found in the repository.")
else:
    print(f'The years available in the repository are: {all_years}')
    