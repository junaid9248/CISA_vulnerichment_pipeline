
import os
import sys
import json
import subprocess
import logging
from datetime import datetime
from pathlib import Path

#Created a logger for logging event details
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from dotenv import load_dotenv

load_dotenv(override=True)
class KaggleManager:
    def __init__(self, dataset_folder_path="dataset"):
        self.dataset_folder_path = Path(dataset_folder_path)
        self.dataset_path = self.dataset_folder_path / "cve_data.csv"
        #self.metadata_file = self.dataset_folder_path / "dataset_metadata.json"

        #Validating the key kaggle enivronment variables
        self.username_token = os.getenv('KAGGLE_USERNAME')
        self.key_token = os.getenv('KAGGLE_KEY')

        self._validate_environ()

        #Get metadata
        self.dataset_metadata = self._get_metadata()

    def _validate_environ(self):

            # Check if dataset folder exists
            if not self.dataset_folder_path.exists():
                logger.error(f"Dataset folder does not exist: {self.dataset_folder_path}")
                sys.exit(1)

            #Check if environment variables for kaggle exist
            
            key_env_variables = [self.username_token, self.key_token]

            if not all(key_env_variables):
                logger.error(f"Missing environment variables: {key_env_variables}")
                sys.exit(1)


    def _get_metadata(self):

        try:
            with open(self.metadata_file, 'r') as f:
                dataset_metadata = json.load(f)

                #Checking for important title and id fields
                imp_fields = ['id','title']
                missing_fields = [field for field in imp_fields if field not in dataset_metadata]

                if missing_fields:
                    logger.error(f"Missing fields in metadata: {missing_fields}")
                    return None

                return dataset_metadata
            
        except Exception as e:
            logger.error(f"Error occurred while getting metadata: {e}")
            return None
        
    
    #Creating a method that let's us run different kaggle commands through subprocess
    def _run_kaggle_command(self, command):
        try:
            command_str = ''.join(command)
            logger.info(f'Running "{command_str}" kaggle command')

            result = subprocess.run(command, 
                                    capture_output= True,
                                    text=True,
                                    check=True
                                    )
            
            if result.stdout:
                logger.info(f'Command output for "{command_str}": {result.stdout}')
                return result
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e}")
            logger.error(f"Error output: {e.stderr}")
            return None
        
    # Creating four kaggle commands 1. Create a new dataset, 2. Upload new dataset, 3. Update  dataset

    #Method to check if a dataset exists on Kaggle using metadata id
    def _check_dataset_exists(self):
        try:
            logger.info("Checking for existing dataset")
            command=['kaggle', 'datasets', 'list', '-s', self.dataset_metadata['id'], '--csv']

            exists = self._run_kaggle_command(command)

            if exists.stdout:
                outputs = exists.stdout.strip().split('\n')

                if len(outputs) > 1 and self.dataset_metadata['id'] in outputs:
                    logger.info(f"Dataset {self.dataset_metadata['id']} already exists on Kaggle")
                    return True
                
            return False

        except Exception as e:
            logger.error(f"Error occurred while checking dataset existence: {e}")
            return False
        
    #Method to create a new dataset for kaggle upload
    def _create_dataset(self):
        try:
            logger.info("Creating new dataset on Kaggle...")
            logger.info(f"Dataset path: {self.dataset_path}")
            
            dataset_metadata_path = self.dataset_folder_path / "dataset-metadata.json"
            
            logger.info("Checking if metadata file exists...")
            if not os.path.exists(dataset_metadata_path):
                logger.info("Metadata file does NOT exist, creating metadata file...")
                create_metadata_command = ['kaggle', 'datasets', 'init', '-p', str(self.dataset_folder_path)]
                self._run_kaggle_command(create_metadata_command)

                logger.info("Creating dataset file...")
                create_dataset_command = ['kaggle', 'datasets', 'create', '-p', str(self.dataset_folder_path)]
                result = self._run_kaggle_command(create_dataset_command)
            else:
                logger.info("Metadata file exists, creating dataset...")
                create_dataset_command = ['kaggle', 'datasets', 'create', '-p', str(self.dataset_folder_path)]
                result = self._run_kaggle_command(create_dataset_command)

            if result:
                logger.info("✅ Dataset created successfully")
            else:
                logger.error("❌ Failed to create dataset")

        except Exception as e:
            logger.error(f"Error occurred while creating dataset: {e}")
            return None
        
    #Method to update an existing dataset on kaggle to it's newer version 
    def _update_dataset(self):
        try:
            exists = self._check_dataset_exists()

            if exists:
                logger.info("Updating existing dataset on Kaggle...")

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                update_command = ['kaggle', 
                                  'datasets', 
                                  'versions', 
                                  '-p', 
                                  str(self.dataset_folder_path), 
                                  '-m', f'New version has been uploaded at: {timestamp}']

                result = self._run_kaggle_command(update_command)

                if result:
                    logger.info("✅ Dataset updated successfully")
                    return True
                else:
                    logger.error("❌ Failed to update dataset")
                return False
            
        except Exception as e:
            logger.error(f"Error occurred while updating dataset: {e}")
            return False
        
    #Method to upload the dataset to kaggle
    def _upload_dataset(self):
        try:
            if self._check_dataset_exists():
                logger.info('Dataset exists. Starting upload...')
                dataset = self._update_dataset()
            else:
                logger.info('Dataset does NOT exist. Creating new dataset...')
                dataset = self._create_dataset()

            if  dataset:
                upload_url = f'https://www.kaggle.com/datasets/junaidmohammed9248/{self.dataset_metadata["id"]}'

        except Exception as e:
            logger.error(f"Error occurred while uploading dataset: {e}")
            return False



def main():
    try:
        manager = KaggleManager()
        success = manager._upload_dataset()

        if success:
            logger.info("Kaggle dataset upload process completed successfully.")
        else:
            logger.error("Kaggle dataset upload process failed.")

    except Exception as e:
        sys.exit(1)



if __name__ == "__main__":
    main()

