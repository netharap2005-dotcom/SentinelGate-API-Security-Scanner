from scan_analyzer import analyze_scan

scan_result = {
    "response_code": 500,
    "response_size": 2000,
    "error_message_present": 1,
    "data_exposure_detected": 1,
    "auth_state": 3,
    "attack_type": "SQL Injection"
}

result = analyze_scan(scan_result)

print(result)