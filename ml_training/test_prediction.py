from ml_predictor import predict_severity
from cvss_calculator import calculate_cvss_score, score_to_severity

scan_result = {
    "response_code": 500,
    "response_size": 2000,
    "error_message_present": 1,
    "data_exposure_detected": 1,
    "auth_state": 3,
    "attack_type": "SQL Injection"
}

ml_result = predict_severity(scan_result)

cvss_score = calculate_cvss_score(
    response_code=scan_result["response_code"],
    error_message_present=scan_result["error_message_present"],
    data_exposure_detected=scan_result["data_exposure_detected"],
    auth_state=scan_result["auth_state"],
    attack_type=scan_result["attack_type"]
)

cvss_severity = score_to_severity(cvss_score)

severity_order = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}

final_severity = ml_result
if severity_order[cvss_severity] > severity_order[ml_result]:
    final_severity = cvss_severity

print("ML Predicted Severity:", ml_result)
print("CVSS Score:", cvss_score)
print("CVSS Severity:", cvss_severity)
print("Final Severity:", final_severity)