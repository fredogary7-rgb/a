# config.py
import os
from dotenv import load_dotenv

load_dotenv()  # Charge les variables d'environnement depuis .env

BKAPAY_PUBLIC_KEY = os.getenv("BKAPAY_PUBLIC_KEY")
BKAPAY_CALLBACK_URL = os.getenv("BKAPAY_CALLBACK_URL")  # <-- Bien présent
BKAPAY_WEBHOOK_SECRET = os.getenv("BKAPAY_WEBHOOK_SECRET")
