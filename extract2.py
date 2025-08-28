import requests
import json
import csv
import os
import time
import sys
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv


logging.basicConfig(level=logging.INFO) 

#For local environment variables, will not execute if .env file is not present
load_dotenv(override=True)

#For extraction from secrets in GitHub Actions
GITHUB_TOKEN = os.getenv('GH_TOKEN')

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
        
        #Getting token from the environment variables from the .env file OR the github secrets
        self.token = os.getenv('GH_TOKEN') or token
        if self.token:
            self.session.headers['Authorization'] = f"token {self.token}"
            logging.info(" GitHub token for authentication used to establish the session.")
        else:
            logging.warning(" ⚠️ No GitHub token found. Using unauthenticated requests, which may have lower rate limits. ⚠️")

        # Test API connection
        #self._test_connection()


    def _test_connection(self):
        try:
            response = self.session.get(f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}")
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"Error testing API connection: {e}")

        if response.status_code == 200:
            logging.info("API connection successful.")
            logging.info(f"Successfully connected to {self.repo_owner}/{self.repo_name} repository.")

            # Check rate limits
            rate_limit_remaining = response.headers.get('x-ratelimit-remaining')
            rate_limit_reset = response.headers.get('x-ratelimit-reset')

            if rate_limit_remaining:
                print(f"✓ API Rate limit remaining: {rate_limit_remaining}")
                if int(rate_limit_remaining) < 60:
                    logging.warning("⚠️  Warning: Low rate limit remaining. Consider using a GitHub token.")
        else:
            logging.error(f"❌ Failed to get file : {response.status_code}")
            return None

    def _handle_rate_limit(self, response):
        if response.status_code == 403 and 'rate limit' in response.text.lower():
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            current_time = int(time.time())
            wait_time = reset_time - current_time + 5 # Add 5 seconds buffer
            
            if wait_time > 0:
                logging.warning(f"⏳ Rate limit exceeded. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                return True
        return False
    
    def get_years(self) -> List[str]:
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents"
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                years = []

                for item in data:
                    if item['type'] == 'dir' and item['name'] not in ['.github', 'assets']:
                        years.append(item['name'])
                logging.info(f"Number of available years: {len(years)}")
                return years
            else:
                logging.error(f"Error fetching years: {response.status_code}")
                return []
        except requests.RequestException as e:
            logging.error(f"Error fetching years: {e}")
            return []
    
    # Method to get all information on CVE file entries for each year directory 
    def get_cve_files_for_year(self, year: str) -> Dict:        
        year_data = {'year': year, 'subdirs': {}}  
        
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/{year}"
        params = {'ref': self.branch}
        
        try:
            response = self.session.get(url, params=params)  
            logging.info(f" Response status for year {year}: {response.status_code}")
            
            if self._handle_rate_limit(response):
                response = self.session.get(url, params=params)

            if response.status_code == 200:
                year_response_data = response.json()
                logging.info(f"📁 Found {len(year_response_data)} subdirectories in {year} year directory")
                
                # Show what we actually got
                for item in year_response_data:
                    logging.info(f"   - {item['name']}")

                # Process directories only
                subdirs = [item for item in year_response_data if item['type'] == 'dir']

                for i, item in enumerate(subdirs):
                    subdir_name = item['name']
                    logging.info(f"    - [{i+1}/{len(subdirs)}] Processing {subdir_name}...")
                    
                    # Initialize subdirectory
                    year_data['subdirs'][subdir_name] = []
                    
                    subdir_url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/{year}/{subdir_name}"
                    logging.info(f"       🌐 Requesting: {subdir_url}")

                    subdir_response = self.session.get(subdir_url, params=params)
                    logging.info(f"       🌐 Subdir response code: {subdir_response.status_code}")

                    if self._handle_rate_limit(subdir_response):
                        subdir_response = self.session.get(subdir_url, params=params)

                    if subdir_response.status_code == 200:
                        files = subdir_response.json()
                        logging.info(f"       📄 Found {len(files)} items in {subdir_name}")
                        
                        file_count = 0
                        for file_item in files:
                            if (file_item['type'] == 'file' and 
                                file_item['name'].startswith('CVE-') and
                                file_item['name'].endswith('.json')):
                                
                                year_data['subdirs'][subdir_name].append({
                                    'name': file_item['name'],
                                    #'path': file_item['path'],
                                    'download_url': file_item['download_url'],
                                    #'sha': file_item['sha'],
                                    #'size': file_item['size']
                                })
                                file_count += 1
                        
                        logging.info(f"       ✅ Added {file_count} CVE files from {subdir_name}")
                    else:
                        logging.error(f"       ❌ Failed to get {subdir_name}: {subdir_response.status_code}")
                        if subdir_response.status_code != 200:
                            logging.error(f"       📝 Error details: {subdir_response.text[:200]}")
            else:
                logging.error(f"❌ Failed to get year {year}: {response.status_code}")
                logging.error(f"📝 Error details: {response.text[:200]}")

        except requests.RequestException as e:
            logging.error(f"❌ Network error: {e}")

        total_files = sum(len(files) for files in year_data['subdirs'].values())
        logging.info(f"✅ Summary: {total_files} total CVE files across {len(year_data['subdirs'])} subdirectories for {year} year added")

        return year_data
    
    # Method to process the cve entry data object by: 
    # 1. Extracting CVE information from provided URL
    # 2. Writing the extracted information to a CSV file
    def get_cve_data_json(self, year_data: Dict):

        check_year = year_data['year']
        logging.info(f"🔍 Starting to process year data for {check_year}...")

        files_written_to_csv = 0

        try:
            for subdir in year_data['subdirs']:
                logging.info(f"    - Processing subdirectory: {subdir}")

                for file in year_data['subdirs'][subdir]:

                    file_name = file['name']
                    download_url = file['download_url']

                    try: 
                    
                        response = self.session.get(download_url)
                    
                        if self._handle_rate_limit(response):
                            response = self.session.get(download_url)

                        if response.status_code == 200:
                            logging.info(f"✅ Successfully downloaded {file_name}")

                        try: 
                            cve_data = response.json()

                            # 1. Extracting CVE information from provided URL
                            extracted_data = self.extract_cve_data(cve_data)

                            if extracted_data:
                                # 2. Writing the extracted information to a CSV file
                                self.write_to_year_csv(extracted_data, year_data['year'])

                        except json.JSONDecodeError as e:
                            logging.error(f"❌ JSON parsing error for {file_name}: {e}")
                    
                    except Exception as e:
                            logging.error(f"❌ Error processing {file_name}: {e}")
                            import traceback
                            traceback.print_exc()

                    else:
                        logging.error(f"❌ Failed to download {file_name}: {response.status_code}")
                        logging.error(f"📝 Error details: {response.text[:200]}")
                        import traceback
                        traceback.print_exc()
        except Exception as e:
            logging.error(f"❌ Unexpected error in get_cve_data_json: {e}")
            import traceback
            traceback.print_exc()
        
        return files_written_to_csv

    #Helper function to calculate SSVC score 
    def calculate_ssvc_score(self, exploitation: str, automatable: str, technical_impact: str) -> str:
        # Normalize inputs to lowercase
        exploitation = exploitation.lower()
        automatable = automatable.lower()
        technical_impact = technical_impact.lower()

        if exploitation == 'active':
            if technical_impact == 'total':
                return 'Act'
            else:  # partial
                if automatable == 'yes':
                    return 'Act'
                else:  # no
                    return 'Attend'
        
        elif exploitation == 'poc':
            if automatable == 'yes':
                if technical_impact == 'total':
                    return 'Attend'
                else:  # partial
                    return 'Attend'
            else:  # no
                if technical_impact == 'total':
                    return 'Attend'
                else:  # partial
                    return 'Track'
                
        elif exploitation == 'none':
            if automatable == 'yes':
                if technical_impact == 'total':
                    return 'Attend'
                else:  # partial
                    return 'Track'
            else:  # no
                return 'Track'
            
        return 'Unknown'  

    #Helper function to convert vector string to metric values if they are not present in the CVE data entry already
    def vector_string_to_metrics(self, cve_entry_template,vector_string: str) -> Dict[str, Any]:
        if not vector_string:
            return cve_entry_template
        
        try:
            #Splitting the vector string into individual metrics using '/' as separator
            metrics = vector_string.split('/')[1:]

            metrics_new = []
            for metric in metrics:
                metrics_new.append(metric.split(':'))

            #Converting the list of lists into a dictionary for easier access
            metrics_dict = dict(metrics_new)

            # Parse each metric
            match metrics_dict.keys()[0]:
                case 'N': cve_entry_template['attack_vector'] = 'NETWORK'
                case 'A': cve_entry_template['attack_vector'] = 'ADJACENT_NETWORK'
                case 'L': cve_entry_template['attack_vector'] = 'LOCAL'
                case 'P': cve_entry_template['attack_vector'] = 'PHYSICAL'
                case _: cve_entry_template['attack_vector'] = ''
            
            match metrics_dict.get('AC'):
                case 'L': cve_entry_template['attack_complexity'] = 'LOW'
                case 'H': cve_entry_template['attack_complexity'] = 'HIGH'
                case _: cve_entry_template['attack_complexity'] = ''
            
            match metrics_dict.get('PR'):
                case 'N': cve_entry_template['privileges_required'] = 'NONE'
                case 'L': cve_entry_template['privileges_required'] = 'LOW'
                case 'H': cve_entry_template['privileges_required'] = 'HIGH'
                case _: cve_entry_template['privileges_required'] = ''
            
            match metrics_dict.get('UI'):
                case 'N': cve_entry_template['user_interaction'] = 'NONE'
                case 'R': cve_entry_template['user_interaction'] = 'REQUIRED'
                case _: cve_entry_template['user_interaction'] = ''
            
            match metrics_dict.get('S'):
                case 'U': cve_entry_template['scope'] = 'UNCHANGED'
                case 'C': cve_entry_template['scope'] = 'CHANGED'
                case _: cve_entry_template['scope'] = ''
            
            match metrics_dict.get('C'):
                case 'N': cve_entry_template['confidentiality_impact'] = 'NONE'
                case 'L': cve_entry_template['confidentiality_impact'] = 'LOW'
                case 'H': cve_entry_template['confidentiality_impact'] = 'HIGH'
                case _: cve_entry_template['confidentiality_impact'] = ''
            
            match metrics_dict.get('I'):
                case 'N': cve_entry_template['integrity_impact'] = 'NONE'
                case 'L': cve_entry_template['integrity_impact'] = 'LOW'
                case 'H': cve_entry_template['integrity_impact'] = 'HIGH'
                case _: cve_entry_template['integrity_impact'] = ''
            
            match metrics_dict.get('A'):
                case 'N': cve_entry_template['availability_impact'] = 'NONE'
                case 'L': cve_entry_template['availability_impact'] = 'LOW'
                case 'H': cve_entry_template['availability_impact'] = 'HIGH'
                case _: cve_entry_template['availability_impact'] = ''
        except Exception as e:
            logging.error(f"❌ Error parsing vector string: {e}")
        
        return cve_entry_template 

    #Function to extract CVE data from the provided 
    def extract_cve_data(self, cve_data_json: Dict):
        
        cve_entry_template={

            'cve_id': '',
            'published_date': '',
            'updated_date': '',

            'cisa_kev': 'FALSE',
            'cisa_kev_date': '',

            #Cvss v3.1 metrics
            'base_score': '',
            'base_severity': '',
            'attack_vector': '',
            'attack_complexity': '',
            'privileges_required': '',
            'user_interaction': '',
            'scope': '',
            'confidentiality_impact': '',
            'integrity_impact': '',
            'availability_impact': '',

            #SSVC metrics
            'ssvc_timestamp': '',
            'ssvc_exploitation': '',
            'ssvc_automatable': '',
            'ssvc_technical_impact': '',
            'ssvc_decision': '',  
            
            #'exploitability_score': '',
            #'impact_score': '',
            #'epss_score': '',
            #'epss_percentile': '',           

            'impacted_vendor': '',
            'impacted_products': [],
            'vulnerable_versions': [],

            'cwe_number': '',
            'cwe_description': '',

        }
 
        try:
            cve_id = cve_data_json.get('cveMetadata', {}).get('cveId', '')
            #Extract CVE Id, date publsihed and date updated values
            cve_entry_template['cve_id'] = cve_id
            cve_entry_template['published_date'] = cve_data_json.get('cveMetadata', {}).get('datePublished', '')
            cve_entry_template['updated_date'] = cve_data_json.get('cveMetadata', {}).get('dateUpdated', '')

            #THIS IS FOR ADP CONTAINER
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
                            cve_entry_template['base_severity'] = metric['cvssV3_1'].get('baseSeverity', '')
                            cve_entry_template['base_score'] = metric['cvssV3_1'].get('baseScore', '')
                            
                            # Extract individual metrics if available
                            if 'attackVector' in metric['cvssV3_1']:
                                cve_entry_template['attack_vector'] = metric['cvssV3_1'].get('attackVector', '')
                            if 'attackComplexity' in metric['cvssV3_1']:
                                cve_entry_template['attack_complexity'] = metric['cvssV3_1'].get('attackComplexity', '')
                            if 'integrityImpact' in metric['cvssV3_1']:
                                cve_entry_template['integrity_impact'] = metric['cvssV3_1'].get('integrityImpact', '')
                            if 'availabilityImpact' in metric['cvssV3_1']:
                                cve_entry_template['availability_impact'] = metric['cvssV3_1'].get('availabilityImpact', '')
                            if 'confidentialityImpact' in metric['cvssV3_1']:
                                cve_entry_template['confidentiality_impact'] = metric['cvssV3_1'].get('confidentialityImpact', '')
                            if 'privilegesRequired' in metric['cvssV3_1']:
                                cve_entry_template['privileges_required'] = metric['cvssV3_1'].get('privilegesRequired', '')
                            if 'userInteraction' in metric['cvssV3_1']:
                                cve_entry_template['user_interaction'] = metric['cvssV3_1'].get('userInteraction', '')
                            if 'scope' in metric['cvssV3_1']:
                                cve_entry_template['scope'] = metric['cvssV3_1'].get('scope', '')

                            #Finding any of the missing metrics
                            missing_metrics = []

                            for key in ['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 
                                                'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact']:
                                # Check if the metric is empty
                                if not cve_entry_template[key]:
                                    missing_metrics.append(key)

                            if missing_metrics:
                                cvss_v3_1_vector_string = metric['cvssV3_1'].get('vectorString', '')
                                logging.warning(f"⚠️ Missing CVSS v3.1 metrics for {cve_id}: {missing_metrics} in ADP container")

                                if cvss_v3_1_vector_string:
                                    self.vector_string_to_metrics(cve_entry_template ,cvss_v3_1_vector_string)

                            continue

                        if 'other' in metric and metric['other'].get('type') == 'kev':
                            # Extracting the CISA KEV information including date added
                            cve_entry_template['cisa_kev'] = 'TRUE'
                            cve_entry_template['cisa_kev_date'] = metric['other']['content']['dateAdded']
                            continue

                        if 'other' in metric and metric['other'].get('type') == 'ssvc':
                            # Extracting the SSVC metrics
                            ssvc_data_content = metric['other'].get('content', {})
                            ssvc_data_options = ssvc_data_content.get('options', [])

                            cve_entry_template['ssvc_timestamp'] = ssvc_data_content.get('timestamp', '')

                            for option in ssvc_data_options:
                                if 'Exploitation' in option:
                                    cve_entry_template['ssvc_exploitation'] = option['Exploitation']
                                if 'Automatable' in option:
                                    cve_entry_template['ssvc_automatable'] = option['Automatable']
                                if 'Technical Impact' in option:
                                    cve_entry_template['ssvc_technical_impact'] = option['Technical Impact']

                            # Calculate SSVC decision if all required fields are present
                            if cve_entry_template['ssvc_exploitation'] and cve_entry_template['ssvc_automatable'] and cve_entry_template['ssvc_technical_impact']:
                                cve_entry_template['ssvc_decision'] = self.calculate_ssvc_score(
                                    cve_entry_template['ssvc_exploitation'],
                                    cve_entry_template['ssvc_automatable'],
                                    cve_entry_template['ssvc_technical_impact']
                                )

                    #Finding the problem types in the CISA ADP container
                    cisa_adp_problem_container = cisa_adp_container.get('problemTypes', [])

                    for problem_type in cisa_adp_problem_container:
                        #Extract the descriptions list from the problemTypes list in the adp container
                        descriptions = problem_type.get('descriptions', [])

                        if descriptions:
                            for description in descriptions:
                                if description.get('type') == 'CWE':
                                    cve_entry_template['cwe_number'] = description.get('cweId', '')
                                    cve_entry_template['cwe_description'] = description.get('description', '')
                                    break

            #THIS IS FOR CNA CONTAINER
            if 'cna' in cve_data_json.get('containers', {}):
                #Finding the cna container in containers array
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

                # SOMETIMES extracting metrics from the cna container if adp container has no metrics
                if "metrics" in cna_container:
                    cna_metrics_container = cna_container.get('metrics', [])

                    for metric in cna_metrics_container:
                        if 'cvssV3_1' in metric:

                            # Extracting the CVSS v3.1 metrics
                            cve_entry_template['base_severity'] = metric['cvssV3_1'].get('baseSeverity', '')
                            cve_entry_template['base_score'] = metric['cvssV3_1'].get('baseScore', '')
                            
                            # Extract individual metrics if available
                            if 'attackVector' in metric['cvssV3_1']:
                                cve_entry_template['attack_vector'] = metric['cvssV3_1'].get('attackVector', '')
                            if 'attackComplexity' in metric['cvssV3_1']:
                                cve_entry_template['attack_complexity'] = metric['cvssV3_1'].get('attackComplexity', '')
                            if 'integrityImpact' in metric['cvssV3_1']:
                                cve_entry_template['integrity_impact'] = metric['cvssV3_1'].get('integrityImpact', '')
                            if 'availabilityImpact' in metric['cvssV3_1']:
                                cve_entry_template['availability_impact'] = metric['cvssV3_1'].get('availabilityImpact', '')
                            if 'confidentialityImpact' in metric['cvssV3_1']:
                                cve_entry_template['confidentiality_impact'] = metric['cvssV3_1'].get('confidentialityImpact', '')
                            if 'privilegesRequired' in metric['cvssV3_1']:
                                cve_entry_template['privileges_required'] = metric['cvssV3_1'].get('privilegesRequired', '')
                            if 'userInteraction' in metric['cvssV3_1']:
                                cve_entry_template['user_interaction'] = metric['cvssV3_1'].get('userInteraction', '')
                            if 'scope' in metric['cvssV3_1']:
                                cve_entry_template['scope'] = metric['cvssV3_1'].get('scope', '')

                            # Check for missing metrics
                            missing_metrics= []
                            for key in ['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 
                                                'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact']:
                                # Check if the metric is empty
                                if not cve_entry_template[key]:
                                    missing_metrics.append(key)

                            if missing_metrics:
                                # Handle missing metrics (e.g., log a warning)
                                print(f"⚠️ Missing CVSS v3.1 metrics for {cve_id}: {missing_metrics}")

                                cvss_v3_1_vector_string = metric['cvssV3_1'].get('vectorString', '')
                                if cvss_v3_1_vector_string:
                                    self.vector_string_to_metrics(cve_entry_template ,cvss_v3_1_vector_string)

                            continue

                if 'problemTypes' in cna_container:
                    # Finding the problem types in the CNA container
                    cna_problem_container = cna_container.get('problemTypes', [])

                    for problem_type in cna_problem_container:
                        descriptions = problem_type.get('descriptions', [])

                        for description in descriptions:
                            if description.get('type') == 'CWE':
                                cve_entry_template['cwe_number'] = description.get('cweId', '')
                                cve_entry_template['cwe_description'] = description.get('description', '')
                                break

                #print(f"✅ Successfully extracted data for {cve_id}")
                return cve_entry_template

        except Exception as e:
            logging.warning(f"❌ Error in extract_cve_data: {e}")
            import traceback
            traceback.print_exc()
            return None
        
    def write_to_year_csv(self, cve_template, year):
        """Write CVE data to CSV file in the same directory as the script"""
        try:
            # Get the directory where the script is located
            dataset_dir_path = os.path.join(os.getcwd(), 'dataset')
            os.makedirs(dataset_dir_path, exist_ok=True)

            csv_file_path = os.path.join(dataset_dir_path, f'cve_data_{year}.csv')
        
            # Convert lists to strings for CSV
            if isinstance(cve_template['impacted_products'], list):
                cve_template['impacted_products'] = '; '.join(cve_template['impacted_products'])
            if isinstance(cve_template['vulnerable_versions'], list):
                cve_template['vulnerable_versions'] = '; '.join(cve_template['vulnerable_versions'])
            
            file_exists = not os.path.exists(csv_file_path)
            with open(csv_file_path, mode= 'a', newline = '', encoding='utf-8') as csvfile:
                fieldnames = list(cve_template.keys())
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                if file_exists:
                    writer.writeheader()

                writer.writerow(cve_template)

                logging.info(f"   - ✅ Written {cve_template['cve_id']} to {csv_file_path}")

        except Exception as e:
            logging.error(f"❌ Error writing to CSV: {e}")

       

if __name__ == "__main__":
    
    extractor = cveExtractor()

    if len(sys.argv) > 1:
        #For automation using gh actions yaml script
        years = [sys.argv[1]]

    else:
        #For local machine 
        years = extractor.get_years()
    
    for year in years:
        #If we already have a file for this year, remove it as we will be rewriting it
        logging.info(f" Processing year: {year}")    
        extract_data = extractor.get_cve_files_for_year(year)
        extractor.get_cve_data_json(extract_data)