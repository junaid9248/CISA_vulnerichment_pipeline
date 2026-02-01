import os 

from dotenv import load_dotenv
load_dotenv()
GH_TOKEN = os.environ.get('GH_TOKEN', None)
KAGGLE_USERNAME = os.environ.get('KAGGLE_USERNAME', None)
KAGGLE_KEY = os.environ.get('KAGGLE_KEY', None)
KAGGLE_API_TOKEN = os.environ.get('KAGGLE_API_TOKEN', None)

