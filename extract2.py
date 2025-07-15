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
    
    def get_cve_data_json(self, year_data: Dict):

        try:
            for subdir in year_data['subdirs']:
                print(f"🔍 Processing subdirectory: {subdir}")
                for file in year_data['subdirs'][subdir]:

                    file_name = file['name']
                    download_url = file['download_url']
                    
                    print(f"📥 Downloading {file_name}")
                    
                    response = self.session.get(download_url)
                    
                    if self._handle_rate_limit(response):
                        response = self.session.get(download_url)

                    if response.status_code == 200:
                        cve_data = response.json()
                        #passing for extraction immediately
                        self.extract_cve_data(cve_data)
                        print(f"✅ Successfully downloaded {file_name}")
                    else:
                        print(f"❌ Failed to download {file_name}: {response.status_code}")
                        print(f"📝 Error details: {response.text[:200]}")
        except:
            print("❌ Error processing year data. Please check the structure of the data.")
            return


    def extract_cve_data(self, cve_data_json: Dict):
        
        cve_entry_template={
            'cve_id': '',

            'published_date': '',
            'updated_date': '',

            'cisa_kev': 'FALSE',
            'cisa_kev_date': '',

            'base_severity': '',
            'base_score': '',
            'exploitability_score': '',
            'impact_score': '',
            'epss_score': '',
            'epss_percentile': '',
            
            'attack_vector': '',
            'attack_complexity': '',
            'privileges_required': '',
            'user_interaction': '',
            'scope': '',
            'confidentiality_impact': '',
            'integrity_impact': '',
            'availability_impact': '',

            'impacted_vendor': '',
            'impacted_products': [],
            'vulnerable_versions': [],

            'cwe_number': '',
            'cwe_description': '',

        }

        try:
            #Extract CVE Id, date publsihed and date updated values
            cve_entry_template['cve_id'] = cve_data_json.get('cveMetadata', {}).get('cveId', '')
            cve_entry_template['published_date'] = cve_data_json.get('cveMetadata', {}).get('datePublished', '')
            cve_entry_template['updated_date'] = cve_data_json.get('cveMetadata', {}).get('dateUpdated', '')

            # Finding the ADP and cna containers in containersarray
            if 'adp' in cve_data_json.get('containers', {}):
                adp_containers = cve_data_json['containers']['adp']

                cisa_adp_container = None

                for adp_container in adp_containers:
                    # Find the specific CISA ADP container that has metrics
                    if adp_container.get('title') == "CISA ADP Vulnrichment":
                        cisa_adp_container = adp_container
                        
                
                if cisa_adp_container:
                    # Finding the metrics list in the CISA ADP container
                    cisa_adp_metrics_container = cisa_adp_container.get('metrics', [])

                    # Iterating over the metrics list
                    for metric in cisa_adp_metrics_container:
                        if 'cvssV3_1' in metric:
                            # Extracting the CVSS v3.1 metrics
                            cve_entry_template['attack_vector'] = metric['cvssV3_1'].get('attackVector', '')
                            cve_entry_template['attack_complexity'] = metric['cvssV3_1'].get('attackComplexity', '')
                            cve_entry_template['integrity_impact'] = metric['cvssV3_1'].get('integrityImpact', '')
                            cve_entry_template['availability_impact'] = metric['cvssV3_1'].get('availabilityImpact', '')
                            cve_entry_template['confidentiality_impact'] = metric['cvssV3_1'].get('confidentialityImpact', '')
                            cve_entry_template['privileges_required'] = metric['cvssV3_1'].get('privilegesRequired', '')
                            cve_entry_template['user_interaction'] = metric['cvssV3_1'].get('userInteraction', '')
                            cve_entry_template['base_severity'] = metric['cvssV3_1'].get('baseSeverity', '')
                            cve_entry_template['base_score'] = metric['cvssV3_1'].get('baseScore', '')
                            continue

                        if 'other' in metric and metric['other'].get('type') == 'kev':
                            # Extracting the CISA KEV information including date added
                            cve_entry_template['cisa_kev'] = 'TRUE'
                            cve_entry_template['cisa_kev_date'] = metric['other']['content']['dateAdded']
                            continue
                    
                    #Finding the problem types in the CISA ADP container 
                    cisa_adp_problem_container = cisa_adp_container.get('problemTypes', [])

                    for problem_type in cisa_adp_problem_container:
                        if 'descriptions' in problem_type:
                            cve_entry_template['cwe_number'] = problem_type['descriptions'].get('cweId', '')
                            cve_entry_template['cwe_description'] = problem_type['descriptions'].get('description', '')

            #Finding the cna container in containers array
            if 'cna' in cve_data_json.get('containers', {}):
                cna_container = cve_data_json['containers']['cna']

            affected_list = cna_container.get('affected', [])
            for affected_item in affected_list:
                # Extract vendor and product
                vendor = affected_item.get('vendor', '')
                product = affected_item.get('product', '')

                cve_entry_template['impacted_vendor'] = vendor
                cve_entry_template['impacted_products'].append(product)

                versions_list = affected_item.get('versions', [])  # ← Fixed: versions is a list
                for version_item in versions_list:
                    cve_entry_template['vulnerable_versions'].append(version_item.get('version', ''))

        except KeyError as e:
            print(f"❌ KeyError while extracting CVE data: {e}")
            return
       

if __name__ == "__main__":
    
    extractor = cveExtractor()

    #Getting an array of all years
    all_years = extractor.get_years()


    if all_years:
        print(f"Available years: {all_years}")
        extract_data = extractor.get_cve_files_for_year(all_years[0])
        extractor.get_cve_data(extract_data)
        print(extract_data)