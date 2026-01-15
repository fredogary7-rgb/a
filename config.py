import os
from dotenv import load_dotenv

load_dotenv()

BKAPAY_PUBLIC_KEY = os.getenv("BKAPAY_PUBLIC_KEY")
BKAPAY_CALLBACK_URL = os.getenv("BKAPAY_CALLBACK_URL")
