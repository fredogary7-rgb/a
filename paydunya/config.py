import os
from dotenv import load_dotenv

load_dotenv()

MODE = os.getenv("PAYDUNYA_MODE", "test")

PAYDUNYA = {
    "master_key": os.getenv("PAYDUNYA_MASTER_KEY"),

    "public_key": os.getenv("PAYDUNYA_TEST_PUBLIC") if MODE == "test"
                    else os.getenv("PAYDUNYA_LIVE_PUBLIC"),

    "private_key": os.getenv("PAYDUNYA_TEST_PRIVATE") if MODE == "test"
                    else os.getenv("PAYDUNYA_LIVE_PRIVATE"),

    "token": os.getenv("PAYDUNYA_TEST_TOKEN") if MODE == "test"
                    else os.getenv("PAYDUNYA_LIVE_TOKEN"),

    "store": {
        "name": "MonSite",
        "tagline": "Paiement sécurisé",
        "website_url": "https://monsite.com"
    }
}
