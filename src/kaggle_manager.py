
import os
import sys
import json
import subprocess
import re
from datetime import datetime
from pathlib import Path
from config import KAGGLE_USERNAME, KAGGLE_KEY

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from dotenv import load_dotenv
load_dotenv(override=True)

class KaggleManager:
    def __init__(self, dataset_folder_path: str = "dataset"):
        
        #Path to folder containing combined dataset and dataset metadata json 
        self.dataset_folder_path = Path(dataset_folder_path)
        #self.dataset_path = self.dataset_folder_path / "cve_combined.csv"

        self.metadata_file_path = self.dataset_folder_path / "dataset-metadata.json"
        self.dataset_metadata = self.get_metadata()

        self.kaggle_username = os.environ.get('KAGGLE_USERNAME') or KAGGLE_USERNAME
        self.kaggle_key = os.environ.get('KAGGLE_KEY') or KAGGLE_KEY

    def validate_environ(self):

            # Check if dataset folder exists
            if not self.dataset_folder_path.exists():
                logging.error(f"Dataset folder does not exist: {self.dataset_folder_path}")
                sys.exit(1)

            key_env_variables = [self.kaggle_username, self.kaggle_key]

            if not all(key_env_variables):
                logging.error(f"Missing environment variables: {key_env_variables}")
                sys.exit(1)


    def get_metadata(self):

        try:
            with open(self.metadata_file_path, 'r') as f:
                dataset_metadata = json.load(f)

                #Checking for important title and id fields
                imp_fields = ['id','title']
                missing_fields = [field for field in imp_fields if field not in dataset_metadata]

                if missing_fields:
                    logging.error(f"Missing fields in metadata: {missing_fields}")
                    return None

                return dataset_metadata
            
        except Exception as e:
            logging.error(f"Error occurred while getting metadata: {e}")
            return None
        
    
    #Creating a method that let's us run different kaggle commands through subprocess
    def run_kaggle_command(self, command):
        try:
            command_str = ' '.join(command)
            logging.info(f'Running "{command_str}" kaggle command')

            result = subprocess.run(command, 
                                    capture_output= True,
                                    text=True,
                                    check=True)
            
            return result
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {e}")
            logging.error(f"Error output: {e.stderr}")
            return None
        

    #Method to check if a dataset exists on Kaggle using metadata id
    def check_dataset_exists(self, dataset_name: str = ''):
        try:
            logging.info(f"Checking for existence of dataset: {dataset_name}")
            #Command to list your own datsets
            command=['kaggle', 
                     'datasets', 
                     'list', 
                     '-s', 
                     f'{dataset_name}']
            #NOTE: --csv flag prints results in a csv format

            result = self.run_kaggle_command(command)
            result2 = ','.join(result.stdout.strip().split('\n'))
            #logging.info(f'Here is the result: {result.stdout}')

            if result2:
                logging.info(f'Here is the result2: {result2}')
        
                if re.search(dataset_name, result2):
                    return True
                else:
                    return False

        except Exception as e:
            raise e(f"Error occurred while checking dataset existence: {e}")
        
    #Method to create a new dataset for kaggle upload
    def create_kaggle_dataset(self, dataset: str = ''):
        try:
            logging.info("Creating new dataset on Kaggle...")

            # -p flag takes path to the folder containing combined dataset and metadata file
            create_dataset_command = ['kaggle', 
                                      'datasets', 
                                      'create',
                                      '-p', str(self.dataset_folder_path), 
                                      '-u']
            result = self.run_kaggle_command(command=create_dataset_command)

            if result:
                logging.info(f"Dataset {dataset} created successfully on Kaggle profile!")
            else:
                logging.error(f"Failed to create dataset {dataset}")

        except Exception as e:
            logging.error(f"Error occurred while creating dataset {dataset}: {e}")
            return None
        
    #Method to update an existing dataset on kaggle to it's newer version 
    def update_dataset(self, dataset: str = ''):
        try:
                logging.info(f"Updating existing dataset {dataset} on Kaggle...")

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                update_command = ['kaggle', 
                                  'datasets', 
                                  'version', 
                                  '-p', str(self.dataset_folder_path), 
                                  '-m', f"New version has been uploaded at: {timestamp}",
                                  '--delete-old-versions']

                result = self.run_kaggle_command(update_command)

                if result:
                    logging.info(f"Dataset {dataset} updated successfully!")
                    return True
                else:
                    return False
            
        except Exception as e:
            logging.error(f"Error occurred while updating dataset: {e}")
            return False

