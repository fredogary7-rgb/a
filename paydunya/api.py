import requests
from paydunya.config import PAYDUNYA
BASE_URL = "https://app.paydunya.com/api/v1/checkout-invoice"

HEADERS = {
    "PAYDUNYA-MASTER-KEY": PAYDUNYA["master_key"],
    "PAYDUNYA-PUBLIC-KEY": PAYDUNYA["public_key"],
    "PAYDUNYA-PRIVATE-KEY": PAYDUNYA["private_key"],
    "PAYDUNYA-TOKEN": PAYDUNYA["token"],
    "Content-Type": "application/json"
}


def create_invoice(amount, description):
    payload = {
        "invoice": {
            "total_amount": amount,
            "description": description
        },
        "store": PAYDUNYA["store"]
    }

    response = requests.post(f"{BASE_URL}/create", json=payload, headers=HEADERS)
    return response.json()


def verify_invoice(token):
    response = requests.get(f"{BASE_URL}/confirm/{token}", headers=HEADERS)
    return response.json()
