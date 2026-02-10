import requests

url = "https://soleaspay.com/api/agent/bills/v3"

headers = {
    "x-api-key": "YOUR_API_KEY",
    "operation": "2",
    "service": "2",  # ex: OM
    "Content-Type": "application/json"
}

payload = {
    "wallet": "690000001",
    "amount": 1000,
    "currency": "XAF",
    "orderId": "ORDER_123456",
    "description": "Paiement test",
    "payer": "John Doe",
    "payerEmail": "john@mail.com",
    "successUrl": "https://tonsite.com/success",
    "failureUrl": "https://tonsite.com/failure"
}

res = requests.post(url, json=payload, headers=headers)
print(res.json())
