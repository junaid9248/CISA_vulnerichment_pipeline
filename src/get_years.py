import requests
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
#from config import GH_TOKEN

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from dotenv import load_dotenv
load_dotenv()

def get_years():
    base_url = "https://api.github.com"
    repo_owner_name = 'cisagov'
    repo_name = 'vulnrichment'
    GH_token = os.environ.get('GH_TOKEN')

    retry_startegy = Retry(
        total = 3,
        backoff_factor= 1,
        status_forcelist=[404, 429, 500, 502, 503, 504]
    )

    adpater = HTTPAdapter(
        max_retries=retry_startegy
    )

    #Create a new session
    session = requests.Session()
    session.mount('https://', adapter=adpater)

    #Configure github token to avoid rate limits
    if not GH_token:
        logging.warning(f'Github token NOT set! Rate limiting might occur')
    else:
        logging.info(f'Github token used to establish new session')
        session.headers.update({
            'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {GH_token}'
        })

    #Fetch from url
    target_url = f'{base_url}/repos/{repo_owner_name}/{repo_name}/contents'
    try:
        resp = session.get(url = target_url)

        #print(resp.json())

        if resp.status_code == 200:

            fetched_data = resp.json()

            if fetched_data!=None:
                years_list = [year_item['name'] for year_item in fetched_data 
                              if year_item['type']== 'dir' and year_item['name'] not in ['.github', 'assets']]
                
                if len(years_list) != 0:
                    logging.info(f'Successfully fetched all years. Number of years to be processed: {len(years_list)}')
                    return years_list   
                else:
                    logging.error('No years fetched') 
    except requests.RequestException as re:
        logging.error(f'An error occurred in fetching all years: {re}')
        return []

#For testing
if __name__ == '__main__':

    years = get_years()
    print(f'These are years: {years}')

