import requests

url = "https://soleaspay.com/api/action/auth"

payload = {
    "public_apikey": "",
    "private_secretkey": "YOUR_PRIVATE_SECRET_KEY"
}

headers = {
    "Content-Type": "application/json"
}

res = requests.post(url, json=payload, headers=headers)
data = res.json()

print(data)
token = data["token"]
