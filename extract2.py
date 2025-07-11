import requests
import json
import csv
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv

load_dotenv(override=True)

class cveExtractor:

    def __init__(self, token: Optional[str] = None, branch: str = 'develop'):

        self.branch = branch
        self.base_url = "https://api.github.com"
        self.raw_url = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
        self.repo_owner = "cisagov"
        self.repo_name = "vulnrichment"
        
        self.headers = {
            'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
            'Accept': 'application/vnd.github.v3+json'
        }

        self.cve_list = []

        #Establish a new session
        self.session = requests.Session()
        self.session .headers.update(self.headers)
        
        #Getting token from the environment variables from the .env file
        self.token = token or os.getenv('GITHUB_TOKEN')
        if self.token:
            self.session.headers['Authorization'] = f"token {self.token}"
            print(" GitHub token for authentication used to establish the session.")
        else:
            print(" ⚠️ No GitHub token found. Using unauthenticated requests, which may have lower rate limits. ⚠️")


        # Test API connection
        #self._test_connection()


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

    def _handle_rate_limit(self, response):
        """Handle GitHub API rate limiting"""
        if response.status_code == 403 and 'rate limit' in response.text.lower():
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            current_time = int(time.time())
            wait_time = reset_time - current_time + 5 # Add 5 seconds buffer
            
            if wait_time > 0:
                print(f"⏳ Rate limit exceeded. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                return True
        return False
    
    def get_years(self) -> List[str]:
        """Get list of years available in the repository"""
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents"
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                years = []

                for item in data:
                    if item['type'] == 'dir' and item['name'] not in ['.github', 'assets']:
                        years.append(item['name'])
                print(f"Number of available years: {len(years)}")
                return years
            else:
                print(f"Error fetching years: {response.status_code}")
                return []
        except requests.RequestException as e:
            print(f"Error fetching years: {e}")
            return []
        
    def get_cve_files_for_year(self, year: str) -> Dict:
        """Get CVE data for a specific year - DEBUG VERSION"""
        
        year_data = {'year': year, 'subdirs': {}}  
        
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/{year}"
        params = {'ref': self.branch}
        
        try:
            response = self.session.get(url, params=params)  # Add params here too
            print(f"📊 Response status: {response.status_code}")
            
            if self._handle_rate_limit(response):
                response = self.session.get(url, params=params)

            if response.status_code == 200:
                year_response_data = response.json()
                print(f"📁 Found {len(year_response_data)} items in year directory")
                
                # Show what we actually got
                for item in year_response_data:
                    print(f"   - {item['name']} ({item['type']})")
                
                # Process directories only
                subdirs = [item for item in year_response_data if item['type'] == 'dir']
                print(f"📂 Found {len(subdirs)} subdirectories")
                
                for i, item in enumerate(subdirs):
                    subdir_name = item['name']
                    print(f"    📂 [{i+1}/{len(subdirs)}] Processing {subdir_name}...")
                    
                    # Initialize subdirectory
                    year_data['subdirs'][subdir_name] = []
                    
                    # FIXED URL - no extra slash
                    subdir_url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/{year}/{subdir_name}"
                    print(f"       🌐 Requesting: {subdir_url}")
                    
                    subdir_response = self.session.get(subdir_url, params=params)
                    print(f"       📊 Subdir response: {subdir_response.status_code}")

                    if self._handle_rate_limit(subdir_response):
                        subdir_response = self.session.get(subdir_url, params=params)

                    if subdir_response.status_code == 200:
                        files = subdir_response.json()
                        print(f"       📄 Found {len(files)} items in {subdir_name}")
                        
                        file_count = 0
                        for file_item in files:
                            if (file_item['type'] == 'file' and 
                                file_item['name'].startswith('CVE-') and
                                file_item['name'].endswith('.json')):
                                
                                year_data['subdirs'][subdir_name].append({
                                    'name': file_item['name'],
                                    'path': file_item['path'],
                                    'download_url': file_item['download_url'],
                                    'sha': file_item['sha'],
                                    'size': file_item['size']
                                })
                                file_count += 1
                        
                        print(f"       ✅ Added {file_count} CVE files from {subdir_name}")
                    else:
                        print(f"       ❌ Failed to get {subdir_name}: {subdir_response.status_code}")
                        if subdir_response.status_code != 200:
                            print(f"       📝 Error details: {subdir_response.text[:200]}")
            else:
                print(f"❌ Failed to get year {year}: {response.status_code}")
                print(f"📝 Error details: {response.text[:200]}")

        except requests.RequestException as e:
            print(f"❌ Network error: {e}")

        # Summary
        total_files = sum(len(files) for files in year_data['subdirs'].values())
        print(f"✅ Summary: {total_files} total CVE files across {len(year_data['subdirs'])} subdirectories")
        
        return year_data
    
    def get_cve_files(self, file_path: str) -> Optional[Dict[str, Any]]:

        try:
            response = self.session.get(file_path)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ Failed to get CVE files: {response.status_code}")
                print(f"📝 Error details: {response.text[:200]}")
        except requests.RequestException as e:
            print(f"❌ Network error: {e}")

        return None


if __name__ == "__main__":
    
    extractor = cveExtractor()

    #Getting an array of all years
    all_years = extractor.get_years()


    if all_years:
        print(f"Available years: {all_years}")
        extract_data = extractor.get_cve_files_for_year(all_years[0])
        print(extract_data)