from ml_predictor import predict_severity
from cvss_calculator import calculate_cvss_score, score_to_severity


def analyze_scan(scan_result):
    ml_result = predict_severity(scan_result)

    cvss_score = calculate_cvss_score(
        response_code=scan_result["response_code"],
        error_message_present=scan_result["error_message_present"],
        data_exposure_detected=scan_result["data_exposure_detected"],
        auth_state=scan_result["auth_state"],
        attack_type=scan_result["attack_type"]
    )

    cvss_severity = score_to_severity(cvss_score)

    severity_rank = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }

    final = ml_result
    if severity_rank[cvss_severity] > severity_rank[ml_result]:
        final = cvss_severity

    return {
        "attack_type": scan_result["attack_type"],
        "response_code": scan_result["response_code"],
        "response_size": scan_result["response_size"],
        "error_message_present": scan_result["error_message_present"],
        "data_exposure_detected": scan_result["data_exposure_detected"],
        "auth_state": scan_result["auth_state"],
        "ml_predicted_severity": ml_result,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "final_severity": final
    }