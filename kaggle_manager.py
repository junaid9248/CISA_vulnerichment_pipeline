
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

class KaggleManager:
    def __init__(self, dataset_folder_path="dataset"):
        self.dataset_folder_path = Path(dataset_folder_path)
        self.dataset_path = self.dataset_folder_path / "cve_data.csv"
        self.metadata_file = self.dataset_folder_path / "dataset_metadata.json"

        #Validating the key kaggle enivronment variables
        self._validate_environ()

        #Get metadata
        self.dataset_metadata = self._get_metadata()

    def _validate_environ(self):

            # Check if dataset folder exists
            if not self.dataset_folder_path.exists():
                logger.error(f"Dataset folder does not exist: {self.dataset_folder_path}")
                sys.exit(1)

            #Check if environment variables for kaggle exist

            key_env_variables = ['KAGGLE_USERNAME', 'KAGGLE_KEY']
            missing_env_vars = [var for var in key_env_variables if var not in os.getenv(var)]

            if missing_env_vars:
                logger.error(f"Missing environment variables: {missing_env_vars}")
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
            logger.logging("Checking for existing dataset")
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

        
        






def main():
    try:
        manager = KaggleManager()

    except Exception as e:
        sys.exit(1)




if __name__ == "__main__":
    main()

