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

        # This is the main data structure to hold year data       
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
                logging.info(f" Found {len(year_response_data)} subdirectories in {year} year directory")
                
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
                    logging.info(f"Requesting: {subdir_url}")

                    subdir_response = self.session.get(subdir_url, params=params)
                    logging.info(f"Subdir response code: {subdir_response.status_code}")

                    if self._handle_rate_limit(subdir_response):
                        subdir_response = self.session.get(subdir_url, params=params)

                    if subdir_response.status_code == 200:
                        files = subdir_response.json()
                        logging.info(f"Found {len(files)} items in {subdir_name}")
                        
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
    
    #DEGUGGING METHOD to extract data for a specific CVE file by its name
    def extract_cve_record(self, file_name: str):
        logging.info(f' Extracting data for CVE record: {file_name}')

        file_year = file_name.split('-')[1]
        file_subdir = file_name.split('-')[2][0] + 'xxx'

        print(f' File year: {file_year}, subdir: {file_subdir}')


        file_url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/{file_year}/{file_subdir}/{file_name}"
        params = {'ref': self.branch}

        try:
            response = self.session.get(file_url, params=params)
            logging.info(f" Response status for year {year}: {response.status_code}")

            if self._handle_rate_limit(response):
                response = self.session.get(file_url, params=params)
            
            if response.status_code == 200:
                logging.info(f"✅ Successfully extracted values for {file_name}")
                cve_data = response.json()

                file_download_url =  cve_data.get('download_url', '')

            response = self.session.get(file_download_url)

            if self._handle_rate_limit(response):
                response = self.session.get(file_download_url)

            if response.status_code == 200:
                logging.info(f"✅ Successfully downloaded {file_name}")
                cve_data = response.json()

                extracted_data = self.extract_cve_data(cve_data)

                return extracted_data



        except requests.RequestException as e:
            logging.error(f"❌ Network error: {e}")
            return None

    
    #DEGUGGING METHOD to extract data for a specific CVE file in the year data
    def extract_data_for_cve_record(self, year_data: Dict, file_name: str):
        all_subdirs = year_data.get('subdirs', {})
        print(f'These are all subdirs: {all_subdirs.keys()}')

        download_url = ''
        for subdir in all_subdirs:
            for file in all_subdirs[subdir]:
                if file['name'] == file_name:
                    download_url = file['download_url']
        
        print(f"Downloading CVE record from: {download_url}")

        try:
            response = self.session.get(download_url)
        
            if self._handle_rate_limit(response):
                response = self.session.get(download_url)

            if response.status_code == 200:
                logging.info(f"✅ Successfully downloaded {file_name}")
                cve_data = response.json()

                extracted_data = self.extract_cve_data(cve_data)

                return extracted_data

        except json.JSONDecodeError as e:
                logging.error(f"❌ JSON parsing error for {file_name}: {e}")

    
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
            metrics_string_split = vector_string.split('/')[1:]

            metrics_new = []
            for metric in metrics_string_split:
                metrics_new.append(metric.split(':'))

            #Converting the list of lists into a dictionary for easier access
            dict_metrics = dict(metrics_new)


            # Parse each metric
            match dict_metrics.get('AV'):
                case 'N': cve_entry_template['attack_vector'] = 'NETWORK'
                case 'A': cve_entry_template['attack_vector'] = 'ADJACENT_NETWORK'
                case 'L': cve_entry_template['attack_vector'] = 'LOCAL'
                case 'P': cve_entry_template['attack_vector'] = 'PHYSICAL'
                case _: cve_entry_template['attack_vector'] = ''
            
            match dict_metrics.get('AC'):
                case 'L': cve_entry_template['attack_complexity'] = 'LOW'
                case 'H': cve_entry_template['attack_complexity'] = 'HIGH'
                case _: cve_entry_template['attack_complexity'] = ''
            
            match dict_metrics.get('PR'):
                case 'N': cve_entry_template['privileges_required'] = 'NONE'
                case 'L': cve_entry_template['privileges_required'] = 'LOW'
                case 'H': cve_entry_template['privileges_required'] = 'HIGH'
                case _: cve_entry_template['privileges_required'] = ''
            
            match dict_metrics.get('UI'):
                case 'N': cve_entry_template['user_interaction'] = 'NONE'
                case 'R': cve_entry_template['user_interaction'] = 'REQUIRED'
                case _: cve_entry_template['user_interaction'] = ''
            
            match dict_metrics.get('S'):
                case 'U': cve_entry_template['scope'] = 'UNCHANGED'
                case 'C': cve_entry_template['scope'] = 'CHANGED'
                case _: cve_entry_template['scope'] = ''
            
            match dict_metrics.get('C'):
                case 'N': cve_entry_template['confidentiality_impact'] = 'NONE'
                case 'L': cve_entry_template['confidentiality_impact'] = 'LOW'
                case 'H': cve_entry_template['confidentiality_impact'] = 'HIGH'
                case _: cve_entry_template['confidentiality_impact'] = ''
            
            match dict_metrics.get('I'):
                case 'N': cve_entry_template['integrity_impact'] = 'NONE'
                case 'L': cve_entry_template['integrity_impact'] = 'LOW'
                case 'H': cve_entry_template['integrity_impact'] = 'HIGH'
                case _: cve_entry_template['integrity_impact'] = ''
            
            match dict_metrics.get('A'):
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
            'cvss_version': '',
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
            # 1. FINDING TOP LEVEL METADATA CONTAINER
            cve_id = cve_data_json.get('cveMetadata', {}).get('cveId', '')
            #Extract CVE Id, date publsihed and date updated values
            cve_entry_template['cve_id'] = cve_id
            cve_entry_template['published_date'] = cve_data_json.get('cveMetadata', {}).get('datePublished', '')
            cve_entry_template['updated_date'] = cve_data_json.get('cveMetadata', {}).get('dateUpdated', '')

            # 2. FINDING THE ADP CONTAINER FROM TOP LEVEL 'CONTAINERS' CONTAINER
            if 'adp' in cve_data_json.get('containers', {}):
                # 2.1. Searching for the ADP container
                adp_containers = cve_data_json['containers'].get('adp', [])

                cisa_adp_vulnrcihment_container = None

                # 2.2. Iterating over all ADP containers to find the specific CISA ADP vulnerichment container
                for adp_container in adp_containers:

                    if adp_container.get('title') == "CISA ADP Vulnrichment":
                        cisa_adp_vulnrcihment_container = adp_container

                    # logging.info(f'These are all the adp containers: {all_adp_containers}')
                
                if cisa_adp_vulnrcihment_container:

                    all_adp_vulnrichment_containers = set()

                    for container in cisa_adp_vulnrcihment_container:
                        all_adp_vulnrichment_containers.update(container)
                    
                    logging.info(f'All containers in the ADP vulnrichment container: {all_adp_vulnrichment_containers}')

                    # 2.2.1. Getting the metrics list in the CISA ADP vulnerichment container
                    cisa_adp_vulnrichment_metrics_container = cisa_adp_vulnrcihment_container.get('metrics', [])
                    # 2.2.2. Getting the problemTypes list in the CISA ADP vulnerichment container
                    cisa_adp_vulnrichment_problem_container = cisa_adp_vulnrcihment_container.get('problemTypes', [])
                    # Getting the affected items list in CISA ADP vulnerichmenet container
                    cisa_adp_vulnrcihment_affected_container = cisa_adp_vulnrcihment_container.get('affected', [])

                    
                    #logging.info(f'This is the metrics container: {cisa_adp_vulnrichment_metrics_container }')
                    if cisa_adp_vulnrichment_metrics_container:
                        #2.2.1.1. Iterrating through the CISA ADP metrics list to find CVSS metrics
                        valid_versions = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']
                        all_versions_found = set()

                        for metric in cisa_adp_vulnrichment_metrics_container:
                            if isinstance(metric,  dict):
                                all_versions_found.update([version_key for version_key in valid_versions if version_key in metric]) 
                                logging.info(f" Available CVSS versions in ADP container for {cve_id}: {all_versions_found}")

                            version_key = next((str(version_key) for version_key in valid_versions if version_key in all_versions_found), None)
                            logging.info(f" The latest CVSS version_key key in ADP metrics container is  {version_key} for {cve_id}")

                            # Here we are looking for the CVSS version an the metrics
                            if version_key in metric:
                                cve_entry_template['cvss_version'] = metric[version_key].get('version', '')
                                cve_entry_template['base_severity'] = metric[version_key].get('baseSeverity', '')
                                cve_entry_template['base_score'] = metric[version_key].get('baseScore', '')

                                # Extract individual metrics if available
                                if 'attackVector' in metric[version_key]:
                                    cve_entry_template['attack_vector'] = metric[version_key].get('attackVector', '')
                                if 'attackComplexity' in metric[version_key]:
                                    cve_entry_template['attack_complexity'] = metric[version_key].get('attackComplexity', '')
                                if 'integrityImpact' in metric[version_key]:
                                    cve_entry_template['integrity_impact'] = metric[version_key].get('integrityImpact', '')
                                if 'availabilityImpact' in metric[version_key]:
                                    cve_entry_template['availability_impact'] = metric[version_key].get('availabilityImpact', '')
                                if 'confidentialityImpact' in metric[version_key]:
                                    cve_entry_template['confidentiality_impact'] = metric[version_key].get('confidentialityImpact', '')
                                if 'privilegesRequired' in metric[version_key]:
                                    cve_entry_template['privileges_required'] = metric[version_key].get('privilegesRequired', '')
                                if 'userInteraction' in metric[version_key]:
                                    cve_entry_template['user_interaction'] = metric[version_key].get('userInteraction', '')
                                if 'scope' in metric[version_key]:
                                    cve_entry_template['scope'] = metric[version_key].get('scope', '')

                                #Finding any of the missing metrics
                                missing_metrics = []
                                for key in ['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 
                                                'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact']:
                                    # Check if the metric is empty
                                    if not cve_entry_template[key]:
                                        missing_metrics.append(key)

                                if missing_metrics:
                                    cvss_vector_string = metric[version_key].get('vectorString', '')
                                    logging.warning(f"⚠️ Missing CVSS {version_key} metrics for {cve_id}: {missing_metrics} in ADP container")

                                    if cvss_vector_string:
                                        self.vector_string_to_metrics(cve_entry_template ,cvss_vector_string)

                                    continue
                        
                            # 2.2.1.2. Extracting CISA SSVC metrics from CISA ADP vulnerichment metrics 'other' containers
                            if 'other' in metric:
                                cisa_adp_vulnrichment_metrics_other_container = metric['other']
                                type_other = cisa_adp_vulnrichment_metrics_other_container.get('type', '')
                                content_other = cisa_adp_vulnrichment_metrics_other_container.get('content', [])

                                # For the other container with type ssvvc
                                if type_other =='ssvc':
                                    cve_entry_template['ssvc_timestamp'] = content_other.get('timestamp', '')

                                    options = content_other.get('options', [])

                                    for option in options:
                                        if 'Exploitation' in option:
                                            cve_entry_template['ssvc_exploitation'] = option.get('Exploitation', '')
                                        if 'Automatable' in option:
                                            cve_entry_template['ssvc_automatable'] = option.get('Automatable', '')
                                        if 'Technical Impact' in option:
                                            cve_entry_template['ssvc_technical_impact'] = option.get('Technical Impact', '')
                                    
                                    # Calculate SSVC decision if all required fields are present
                                    if cve_entry_template['ssvc_exploitation'] and cve_entry_template['ssvc_automatable'] and cve_entry_template['ssvc_technical_impact']:
                                        cve_entry_template['ssvc_decision'] = self.calculate_ssvc_score(
                                            cve_entry_template['ssvc_exploitation'],
                                            cve_entry_template['ssvc_automatable'],
                                            cve_entry_template['ssvc_technical_impact']
                                        )
                                # For the other container with type kev
                                elif type_other == 'kev':
                                    cve_entry_template['cisa_kev'] = 'TRUE'
                                    cve_entry_template['cisa_kev_date'] = content_other.get('dateAdded', '')

                    # 2.2.2. Finding the problem types container in the CISA ADP container
                    if cisa_adp_vulnrichment_problem_container:
                        for problem_type in cisa_adp_vulnrichment_problem_container:
                          #Extract the descriptions list from the problemTypes list in the adp container
                          descriptions = problem_type.get('descriptions', [])

                          if descriptions:
                              for description in descriptions:
                                  if description.get('type') == 'CWE':
                                      cve_entry_template['cwe_number'] = description.get('cweId', '')
                                      cve_entry_template['cwe_description'] = description.get('description', '')
                                      break

                    # 2.2.3. Finding the affected products if they exist
                    if cisa_adp_vulnrcihment_affected_container:
                        #logging.info(f'The affected container exists in adp')
                        for container in cisa_adp_vulnrcihment_affected_container:

                            cve_entry_template['impacted_vendor'] = container.get('vendor', '')
                            cve_entry_template['impacted_products'].append(container.get('product', ''))
                            
                            versions_list = container.get('versions', [])
                            for version in versions_list:
                                cve_entry_template['vulnerable_versions'].append(version.get('version', ''))
                    
                    #logging.info(f'This is the CVE entry template: {cve_entry_template}')
                                

            # 3. THIS IS FOR THE CNA CONTAINER
            if 'cna' in cve_data_json.get('containers', {}):
                #3.1. Finding the cna container in containers array
                cna_container = cve_data_json['containers']['cna']

                affected_list = cna_container.get('affected', [])
                for affected_item in affected_list:
                    # Extract vendor and product
                    vendor = affected_item.get('vendor', '')
                    product = affected_item.get('product', '')

                    cve_entry_template['impacted_vendor'] = vendor
                    cve_entry_template['impacted_products'].append(product)

                    versions_list = affected_item.get('versions', []) 
                    for version_item in versions_list:
                        cve_entry_template['vulnerable_versions'].append(version_item.get('version', ''))

                # SOMETIMES extracting metrics from the cna container if adp container has no metrics
                if "metrics" in cna_container:
                    #Fetch the mertics list from the cna container
                    cna_metrics_container = cna_container.get('metrics', [])
                    
                    #Iterrating through the metrics list
                    valid_versions1 = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']

                    all_versions_found1 = set()

                    for metric in cna_metrics_container:
                        if isinstance(metric, dict):
                            all_versions_found1.update([version for version in valid_versions1 if version in metric])
                            logging.info(f" Available CVSS versions in CNA container for {cve_id}: {all_versions_found}")
                    
                    version_key1 = next((version for version in valid_versions1 if version in all_versions_found1), None)
                    logging.info(f" The latest CVSS version key in CNA metrics container is  {version_key1} for {cve_id}")  
                    
                    #iterate over all the metrics in the metrics container
                    for metric in cna_metrics_container:
                        logging.info(f" Processing metric in CNA container for {cve_id}: {metric.keys()}")

                        #if not isinstance(metric, dict) or not isinstance(metric, list):
                            #continue


                        #Checking if the version key is in the metric
                        if version_key1 in metric:
                            logging.info(f" Extracting CVSS {version_key1} metrics from CNA container for {cve_id}")

                            if version_key1 in valid_versions:
                                # Extracting the CVSS  metrics
                                cve_entry_template['cvss_version'] = metric[version_key1].get('version', '')
                                cve_entry_template['base_severity'] = metric[version_key1].get('baseSeverity', '')
                                cve_entry_template['base_score'] = metric[version_key1].get('baseScore', '')
                                cvss_vector_string = metric[version_key1].get('vectorString', '')
                                
                                # Extract individual metrics if available
                                if 'attackVector' in metric[version_key1]:
                                    cve_entry_template['attack_vector'] = metric[version_key1].get('attackVector', '')
                                if 'attackComplexity' in metric[version_key1]:
                                    cve_entry_template['attack_complexity'] = metric[version_key1].get('attackComplexity', '')
                                if 'integrityImpact' in metric[version_key1]:
                                    cve_entry_template['integrity_impact'] = metric[version_key1].get('integrityImpact', '')
                                if 'availabilityImpact' in metric[version_key1]:
                                    cve_entry_template['availability_impact'] = metric[version_key1].get('availabilityImpact', '')
                                if 'confidentialityImpact' in metric[version_key1]:
                                    cve_entry_template['confidentiality_impact'] = metric[version_key1].get('confidentialityImpact', '')
                                if 'privilegesRequired' in metric[version_key1]:
                                    cve_entry_template['privileges_required'] = metric[version_key1].get('privilegesRequired', '')
                                if 'userInteraction' in metric[version_key1]:
                                    cve_entry_template['user_interaction'] = metric[version_key1].get('userInteraction', '')
                                if 'scope' in metric[version_key1]:
                                    cve_entry_template['scope'] = metric[version_key1].get('scope', '')

                                # Check for missing metrics
                                missing_metrics= []
                                for key in ['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 
                                                    'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact']:
                                    # Check if the metric is empty
                                    if not cve_entry_template[key]:
                                        missing_metrics.append(key)

                                if missing_metrics:
                                    # Handle missing metrics (e.g., log a warning)
                                    print(f"⚠️ Missing CVSS {version_key1} metrics for {cve_id}: {missing_metrics}")

                                    if cvss_vector_string:
                                        self.vector_string_to_metrics(cve_entry_template ,cvss_vector_string)

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

                print(f"✅ Successfully extracted data for {cve_id}")
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
    years = []

    if len(sys.argv) > 1:
        #For automation using gh actions yaml script
        args = list(sys.argv[2].split(','))
        #arg1 = [sys.argv[2]]

        for arg in args:
            logging.info(f" Processing year: {arg}")
            extract_data = extractor.get_cve_files_for_year(arg)
            extractor.get_cve_data_json(extract_data)


    else:
        #For local machine 
        years = extractor.get_years()
        years = ['2012']
    
        for year in years:
            #If we already have a file for this year, remove it as we will be rewriting it
            logging.info(f" Processing year: {year}")    
            extract_data = extractor.get_cve_files_for_year(year)
            extractor.get_cve_data_json(extract_data)

            #cve_record = extractor.extract_cve_record('CVE-2012-0003.json')
            #print(cve_record)
    