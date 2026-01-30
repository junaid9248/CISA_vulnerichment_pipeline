import argparse
from src.extractor import run
from src.get_years import get_years

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main(arguments):

    if arguments:
        if arguments.year:
            years_string = arguments.years_list
            years = years_string.split(',')
        elif arguments.run:
            years = get_years()
            
    if years:
        logging.info(f'Starting extraction process for years {years}')

        for year in years:
            run(year= year)

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
    arguments = argparser.parse_args()

    main(arguments=arguments)