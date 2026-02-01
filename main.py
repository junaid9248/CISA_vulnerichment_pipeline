import argparse
import os
from config import KAGGLE_USERNAME
from src.extractor import run
from src.get_years import get_years
from src.kaggle_manager import KaggleManager
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from dotenv import load_dotenv
load_dotenv()

def main(arguments):

    if arguments:
        if arguments.year:
            years_string = arguments.years_list
            years = years_string.split(',')

            if years:
                logging.info(f'Starting extraction process in test mode for years: {years}')

                for year in years:
                    run(year= year)
        elif arguments.run:
            years = get_years()

            if years:
                logging.info(f'Starting extraction process in auto mode for years: {years}')

                for year in years:
                    run(year= year)

        if arguments.upload:
            kmanager = KaggleManager()
            dataset= None
            if KAGGLE_USERNAME or os.environ.get('KAGGLE_USERNAME', None):
                dataset = f"{KAGGLE_USERNAME}/cisa-cve-vulnrichment"
                #"junaidmohammad9248/cisa-cve-vulnrichment

            exists= kmanager.check_dataset_exists(dataset)

            if exists:
                logging.info(f"Dataset {dataset} ALREADY exists on Kaggle")

                kmanager.update_dataset(dataset = dataset)
            else:
                logging.info(f"Dataset {dataset} does NOT exist on Kaggle")
                kmanager.create_kaggle_dataset(dataset=dataset)

if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Arguments for the Kaggle CI/CD pipeline')

    # Adding arguments for the defined parser
    argparser.add_argument(
        '--run',
        action='store_true',
        help='Flag for running with all available years'
    )
    argparser.add_argument(
        '--year',
        action='store_true',
        help='Flag set for running with test years'
    )
    argparser.add_argument(
        'years_list',
        nargs='?',
        type=str,
        help='Comma-separated list of years for testing purposes'
    )

    argparser.add_argument(
        '--upload',
        action='store_true',
        help='Flag to run kaggle upload'
    )

    arguments = argparser.parse_args()

    main(arguments=arguments)