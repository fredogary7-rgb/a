def is_success(response):
    return response.get("response_code") == "00"


def is_payment_completed(result):
    return result.get("status") == "completed"
