import requests
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import csv
import os
import time

from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.json_parser import extract_cvedata 
from config import GH_TOKEN
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from dotenv import load_dotenv
load_dotenv()

conn_details = {
    'base_url': "https://api.github.com",
    'repo_owner': 'cisagov',
    'repo_name': 'vulnrichment',
    'branch': 'develop'
}

def handle_rate_limit(response):
    if response.status_code == 403 and 'rate limit' in response.text.lower():
        reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
        current_time = int(time.time())
        wait_time = reset_time - current_time + 5 
        
        if wait_time > 0:
            logging.warning(f"Rate limit exceeded. Waiting {wait_time} seconds...")
            time.sleep(wait_time)
            return True
    return False
 
def write_to_csv(data: Dict = {},writer: Any = None):
    logging.info(f'Adding entry for {data}')
    #Normalizing lists for csv entry
    if isinstance(data.get('impacted_products'), list):
        data['impacted_products'] = ','.join(data['impacted_products'])
    
    if isinstance(data.get('vulnerable_versions'), list):
        data['vulnerable_versions'] = ','.join(data['vulnerable_versions'])
    
    if data.get('cvss_version') == 4.0:
        if isinstance(data.get('confidentiality_impact'), list):
            data['confidentiality_impact'] = str(data['confidentiality_impact'])
        if isinstance(data.get('integrity_impact'), list):
            data['integrity_impact'] = str(data['integrity_impact'])
        if isinstance(data.get('availability_impact'), list):
            data['availability_impact'] = str(data['availability_impact'])

    #Using the writer to write row data to csv
    writer.writerow(data)


def download_file_from_url(file: Dict ={}, file_year: str = '') -> Dict:
    file_name = file['name']
    file_download_url = file['download_url']

    year_session = requests.Session()

    if GH_TOKEN or os.environ.get('GH_TOKEN'):
        logging.info(f'Found Github token, initialzing connection with increased rate limit')

        year_session.headers.update({
            'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {GH_TOKEN}'
        })
    else:
        logging.warning(f'Github token not found consider using one for increased rate limits')

    try:
        response = year_session.get(url = file_download_url, timeout=60)

        if handle_rate_limit(response=response):
            response = year_session.get(url = file_download_url, timeout=60)
        
        #If successful with no rate limiting
        if response.status_code == 200:
            logging.info(f'Successfully download file: {file_name}')
            resp_json = response.json()

            if resp_json:
                cveId = resp_json.get('cveMetadata', {}).get('cveId', 'none')

                record_details = {
                    'cveId' : cveId,
                    'year': int(file_year),
                    'extracted_record': extract_cvedata(resp_json)
                }
            return record_details
        
    except requests.exceptions.RequestException as reqEx:
        logging.error(f'The following error occured in fetching the file from {file_download_url}: {reqEx}')
# Yields files from each subdir giving file:{file_name, download_url}
def subdir_files_generator(year_data: Dict ={}):
    all_subdirs_for_year = year_data['subdirs'].values()

    for subdir in all_subdirs_for_year:
        for subdir_file in subdir:
            yield subdir_file
        
# Method to process the cve entry data object by: 
# 1. Extracting CVE information from provided URL
# 2. Writing the extracted information to a CSV file
def extract_store_cve_data(year_data: Dict = {}):

    file_year = year_data['year']

    logging.info(f" Starting to process year data for {file_year}...")

    total_files_in_year = sum(len(f) for f in year_data['subdirs'].values())
    logging.info(f'Starting processing for {total_files_in_year} in {file_year}')

    files_written_to_csv = 0

    #Defining dependencies for threadpoolexecutor
    files_iter = subdir_files_generator(year_data=year_data)
    maxworkers = 50

    dataset_dir_path = os.path.join(os.getcwd(), 'dataset')
    os.makedirs(dataset_dir_path, exist_ok=True)
    year_file_path = os.path.join(dataset_dir_path, f'cve_{file_year}.csv')

    writer = None
    with open(file=year_file_path, mode='w', newline='', encoding='UTF-8') as csvfile:
        try:
            files_to_process = list(files_iter)

            with ThreadPoolExecutor(max_workers= maxworkers) as executor:
                futures_to_file = {
                    executor.submit(download_file_from_url, file, file_year): file for file in files_to_process
                }
            
                for future in as_completed(futures_to_file):
                    try:
                        result = future.result()

                        if result['extracted_record']:
                            #print(result['extracted_record'])
                            data_to_write = result['extracted_record']

                            # Checking if a writer doesnt exist so that we can create it and write headers from field names for the first time
                            if writer == None:
                                writer = csv.DictWriter(csvfile, fieldnames= data_to_write.keys())
                                writer.writeheader()
                            
                            write_to_csv(data = data_to_write, writer=writer)
                            files_written_to_csv = files_written_to_csv+1
                    except Exception as e:
                        error_cve_id = result['cveId']
                        logging.error(f'There was an error processing future for {error_cve_id}: {e}')

            logging.info(f'Successfully processed {files_written_to_csv} cve entry files for the year {file_year}')    

        except Exception as e:
            logging.error(f'There was error processing files for year {file_year}:{e}') 
    
# Method to get all information on CVE file entries for each year directory 
def get_cve_files_for_year(year: str) -> Dict:
    retry_startegy = Retry(
        total = 3,
        backoff_factor= 1,
        status_forcelist=[404,429, 500, 502, 503, 504]
    )

    adpater = HTTPAdapter(
        max_retries=retry_startegy
    )

    #Create a new session
    session = requests.Session()
    session.mount('https://', adapter=adpater)

    #Configure github token to avoid rate limits
    if not GH_TOKEN or os.environ.get('GH_TOKEN'):
        logging.info(f'Github token used to establish new session')
        session.headers.update({
            'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {GH_TOKEN}'
        })
    else:
        logging.warning(f'Github token NOT set! Rate limiting might occur')

    # This is the main data structure to hold year data       
    year_data = {'year': year, 'subdirs': {}}  
    
    url = f"{conn_details['base_url']}/repos/{conn_details['repo_owner']}/{conn_details['repo_name']}/contents/{year}"
    params = f'{conn_details["branch"]}'
    
    try:
        response = session.get(url, params=params)  
        logging.info(f" Response status for year {year}: {response.status_code}")
        
        if handle_rate_limit(response):
            response = session.get(url, params=params)

        if response.status_code == 200:
            year_response_data = response.json()
            logging.info(f" Found {len(year_response_data)} subdirectories in {year} year directory")
            
            for item in year_response_data:
                logging.info(f"- {item['name']}")

            # Process directories only
            subdirs = [item for item in year_response_data if item['type'] == 'dir']

            for i, item in enumerate(subdirs):
                subdir_name = item['name']
                logging.info(f"- [{i+1}/{len(subdirs)}] Processing {subdir_name}...")
                
                # Initialize subdirectory
                year_data['subdirs'][subdir_name] = []
                
                subdir_url = f"{conn_details['base_url']}/repos/{conn_details['repo_owner']}/{conn_details['repo_name']}/contents/{year}/{subdir_name}"
                logging.info(f"Requesting: {subdir_url}")

                subdir_response = session.get(subdir_url, params=params)
                logging.info(f"Subdir response code: {subdir_response.status_code}")

                if handle_rate_limit(subdir_response):
                    subdir_response = session.get(subdir_url, params=params)

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
                                'download_url': file_item['download_url'],
                            })
                            file_count += 1
                    
                    logging.info(f"Added {file_count} CVE files from {subdir_name}")
                else:
                    logging.error(f"Failed to get {subdir_name}: {subdir_response.status_code}")
                    if subdir_response.status_code != 200:
                        logging.error(f"Error details: {subdir_response.text[:200]}")
        else:
            logging.error(f"Failed to get year {year}: {response.status_code}")
            logging.error(f"Error details: {response.text[:200]}")

    except requests.RequestException as e:
        logging.error(f"Network error: {e}")

    total_files = sum(len(files) for files in year_data['subdirs'].values())
    logging.info(f"Summary: {total_files} total CVE files across {len(year_data['subdirs'])} subdirectories for {year} year added")

    return year_data


def run(year):

    year_data = get_cve_files_for_year(year= year)
    extract_store_cve_data(year_data=year_data)
