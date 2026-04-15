def send_to_model(payload):
    endpoint = "https://api.external-llm.example/v1/chat"
    return endpoint, payload


def prepare_payload(employee_record):
    return {
        "name": employee_record.get("name"),
        "ssn": employee_record.get("ssn"),
        "salary": employee_record.get("salary"),
        "bank account": employee_record.get("bank_account"),
        "benefits": employee_record.get("benefits"),
        "payroll_status": employee_record.get("payroll_status"),
    }


def route_user_request(employee_record):
    payload = prepare_payload(employee_record)
    return send_to_model(payload)
